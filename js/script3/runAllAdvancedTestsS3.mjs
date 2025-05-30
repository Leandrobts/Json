// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { sprayAndInvestigateObjectExposure } from './testRetypeOOB_AB_ViaShadowCraft.mjs';

async function runSprayABAndCheckSize_v15a_wrapper() {
    const FNAME_RUNNER = "runSprayABAndCheckSize_v15a_wrapper";
    logS3(`==== INICIANDO Estratégia Wrapper: ${FNAME_RUNNER} ====`, 'test', FNAME_RUNNER);
    await sprayAndInvestigateObjectExposure(); // Chama a função exportada que agora tem a lógica _v15a
    logS3(`==== Estratégia Wrapper ${FNAME_RUNNER} CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_SprayABCheckSize_v15a';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME);
    logS3(`==== INICIANDO Script 3: Spray ArrayBuffers, Trigger 0x70, Checar Corrupção de Tamanho (lógica v15a) ====`,'test', FNAME);
    document.title = `Iniciando Script 3 - Spray AB & Check Size v15a`;

    await runSprayABAndCheckSize_v15a_wrapper(); 
    
    logS3(`\n==== Script 3 CONCLUÍDO (lógica v15a) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    // Título é atualizado dentro do teste principal
}
