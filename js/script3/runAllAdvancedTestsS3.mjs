// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { sprayAndInvestigateObjectExposure } from './testRetypeOOB_AB_ViaShadowCraft.mjs';

async function runGetterLeakAttempt_v17a_wrapper() {
    const FNAME_RUNNER = "runGetterLeakAttempt_v17a_wrapper";
    logS3(`==== INICIANDO Estratégia Wrapper: ${FNAME_RUNNER} ====`, 'test', FNAME_RUNNER);
    const results = await sprayAndInvestigateObjectExposure(); // Chama a função exportada que agora tem a lógica _v17a
    logS3(`==== Estratégia Wrapper ${FNAME_RUNNER} CONCLUÍDA ====`, 'test', FNAME_RUNNER);
    // Poderia logar results aqui se desejado
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_GetterLeak_v17a';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME);
    logS3(`==== INICIANDO Script 3: Tentativa de Vazamento de Ponteiro via Getter (lógica v17a) ====`,'test', FNAME);
    document.title = `Iniciando Script 3 - Getter Leak v17a`;

    await runGetterLeakAttempt_v17a_wrapper(); 
    
    logS3(`\n==== Script 3 CONCLUÍDO (lógica v17a) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    // Título é atualizado dentro do teste principal
}
