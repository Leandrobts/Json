// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a função do script modificado
import { sprayAndInvestigateObjectExposure } from './testRetypeOOB_AB_ViaShadowCraft.mjs';

async function runShadowCraftWithLeakedVectorStrategy() {
    const FNAME_RUNNER = "runShadowCraftWithLeakedVectorStrategy";
    logS3(`==== INICIANDO Estratégia ShadowCraft com "Vazamento" como m_vector ====`, 'test', FNAME_RUNNER);
    await sprayAndInvestigateObjectExposure();
    logS3(`==== Estratégia ShadowCraft com "Vazamento" como m_vector CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_ShadowCraftLeakedVec_v20b';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME);
    logS3(`==== INICIANDO Script 3: ${FNAME} ====`,'test', FNAME);
    document.title = `Iniciando S3 - ${FNAME}`;

    await runShadowCraftWithLeakedVectorStrategy();

    logS3(`\n==== Script 3 CONCLUÍDO (${FNAME}) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (document.title.includes("FALHOU") || document.title.includes("ERRO")) {
        // Manter título de erro
    } else if (!document.title.startsWith("ShadowCraft:")) {
         document.title = `S3 Concluído - ${FNAME}`;
    }
}
