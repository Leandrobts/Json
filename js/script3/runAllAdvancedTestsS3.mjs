// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { sprayAndInvestigateObjectExposure } from './testRetypeOOB_AB_ViaShadowCraft.mjs';

async function runButterflyCorruption_v21a_wrapper() {
    const FNAME_RUNNER = "runButterflyCorruption_v21a_wrapper";
    logS3(`==== INICIANDO Estratégia Wrapper: ${FNAME_RUNNER} ====`, 'test', FNAME_RUNNER);
    await sprayAndInvestigateObjectExposure(); 
    logS3(`==== Estratégia Wrapper ${FNAME_RUNNER} CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_ButterflyCorruption_v21a';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME);
    logS3(`==== INICIANDO Script 3: Tentativa de Corrupção de Butterfly (lógica v21a) ====`,'test', FNAME);
    document.title = `Iniciando Script 3 - Butterfly Corruption v21a`;

    await runButterflyCorruption_v21a_wrapper(); 
    
    logS3(`\n==== Script 3 CONCLUÍDO (lógica v21a) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;
}
