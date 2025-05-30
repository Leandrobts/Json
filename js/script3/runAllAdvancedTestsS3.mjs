// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { sprayAndInvestigateObjectExposure } from './testRetypeOOB_AB_ViaShadowCraft.mjs';

async function runDetectSprayCorruption_v12a_wrapper() {
    const FNAME_RUNNER = "runDetectSprayCorruption_v12a_wrapper";
    logS3(`==== INICIANDO Estratégia Wrapper: ${FNAME_RUNNER} ====`, 'test', FNAME_RUNNER);
    await sprayAndInvestigateObjectExposure(); // Chama a função exportada que agora tem a lógica _v12a
    logS3(`==== Estratégia Wrapper ${FNAME_RUNNER} CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_DetectSprayCorruption_v12a';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME);
    logS3(`==== INICIANDO Script 3: Detectar Qualquer Corrupção em Arrays Pulverizados (lógica v12a) ====`,'test', FNAME);
    document.title = `Iniciando Script 3 - Detect Spray Corruption v12a`;

    await runDetectSprayCorruption_v12a_wrapper(); 
    
    logS3(`\n==== Script 3 CONCLUÍDO (lógica v12a) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (!document.title.includes("CORRUPÇÃO DETECTADA") && !document.title.includes("FALHOU") && !document.title.includes("Nenhuma Corrupção")) {
        document.title = "Script 3 v12a Concluído";
    }
}
