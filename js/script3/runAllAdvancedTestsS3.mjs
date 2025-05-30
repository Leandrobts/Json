// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { executeAddrofCandidateReadValidation } from './testAddrofCandidateRead.mjs';

async function runAddrofCandidateValidationWrapper() {
    const FNAME_WRAPPER = "runAddrofCandidateValidationWrapper";
    logS3(`==== INICIANDO Estratégia Wrapper: ${FNAME_WRAPPER} ====`, 'test', FNAME_WRAPPER);
    await executeAddrofCandidateReadValidation();
    logS3(`==== Estratégia Wrapper ${FNAME_WRAPPER} CONCLUÍDA ====`, 'test', FNAME_WRAPPER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_ValidateAddrofRead_v20';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: ${FNAME} ====`, 'test', FNAME);
    document.title = `S3 - ${FNAME}`;

    await runAddrofCandidateValidationWrapper();

    logS3(`\n==== Script 3 CONCLUÍDO (${FNAME}) ====`, 'test', FNAME);
    if (runBtn) runBtn.disabled = false;
    if (!document.title.includes("ERRO") && !document.title.includes("FAIL")) {
        document.title = "S3 Concluído";
    }
}
