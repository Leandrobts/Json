// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a função de teste atualizada
import { executeInvestigatePropertyAccessInRangeError } from './testInvestigatePropertyAccessInRangeError.mjs'; // Nome do arquivo .mjs

async function runDebugOOBWriteAt0x70Strategy() {
    const FNAME_RUNNER = "runDebugOOBWriteAt0x70Strategy_v23";
    logS3(`==== INICIANDO ${FNAME_RUNNER}: Depurando Escrita OOB em 0x70 ====`, 'test', FNAME_RUNNER);

    // A função executeInvestigatePropertyAccessInRangeError agora contém a lógica de depuração
    const result = await executeInvestigatePropertyAccessInRangeError();

    if (result && result.error) {
        logS3(`   RESULTADO DO TESTE: Erro ${result.error.name} - ${result.error.message}`, "error", FNAME_RUNNER);
    } else {
        logS3(`   RESULTADO DO TESTE: Completou sem erro explícito.`, "good", FNAME_RUNNER);
    }
    logS3(`==== ${FNAME_RUNNER} CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_DebugOOBWriteAt0x70_v23';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME);
    logS3(`==== INICIANDO Script 3: ${FNAME} ====`, 'test', FNAME);
    document.title = `S3 - ${FNAME}`;

    await runDebugOOBWriteAt0x70Strategy();

    logS3(`\n==== Script 3 CONCLUÍDO (${FNAME}) ====`, 'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (document.title.includes("ERRO") || document.title.includes("FAIL") || document.title.includes("RangeError")) {
         // Manter título se indicar problema
    } else if (!document.title.startsWith("S3 -")) {
        document.title = "S3 Concluído";
    }
}
