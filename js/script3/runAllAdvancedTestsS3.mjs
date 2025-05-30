// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { executeRevisitComplexObjectRangeError } from './testRevisitComplexObjectRangeError.mjs';

async function runRevisitRangeErrorStrategy() {
    const FNAME_WRAPPER = "runRevisitRangeErrorStrategy";
    logS3(`==== INICIANDO Estratégia Wrapper: ${FNAME_WRAPPER} ====`, 'test', FNAME_WRAPPER);
    await executeRevisitComplexObjectRangeError();
    logS3(`==== Estratégia Wrapper ${FNAME_WRAPPER} CONCLUÍDA ====`, 'test', FNAME_WRAPPER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_RevisitRangeError_v21';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: ${FNAME} ====`, 'test', FNAME);
    document.title = `S3 - ${FNAME}`;

    await runRevisitRangeErrorStrategy();

    logS3(`\n==== Script 3 CONCLUÍDO (${FNAME}) ====`, 'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (document.title.includes("ERRO") || document.title.includes("FAIL") || document.title.includes("RangeError")) {
         // Manter título se indicar problema
    } else if (!document.title.startsWith("S3 -")) { // Evitar sobrescrever títulos de sucesso/problema específicos
        document.title = "S3 Concluído";
    }
}
