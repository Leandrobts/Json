// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { sprayAndInvestigateObjectExposure } from './testRetypeOOB_AB_ViaShadowCraft.mjs'; // A função exportada é a mesma

async function runInvestigate0x6CEffect_v11a_wrapper() {
    const FNAME_RUNNER = "runInvestigate0x6CEffect_v11a_wrapper";
    logS3(`==== INICIANDO Estratégia Wrapper: ${FNAME_RUNNER} ====`, 'test', FNAME_RUNNER);
    await sprayAndInvestigateObjectExposure(); // Chama a função exportada que agora tem a lógica _v11a
    logS3(`==== Estratégia Wrapper ${FNAME_RUNNER} CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_Investigate0x6C_v11a';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME);
    logS3(`==== INICIANDO Script 3: Investigar Efeito de 0x70 em 0x6C (lógica v11a) ====`,'test', FNAME);
    document.title = `Iniciando Script 3 - Investigate 0x6C v11a`;

    await runInvestigate0x6CEffect_v11a_wrapper(); 
    
    logS3(`\n==== Script 3 CONCLUÍDO (lógica v11a) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    // A lógica de título é atualizada dentro do teste agora
    if (!document.title.includes("0x6C") && !document.title.includes("FALHOU")) {
        document.title = "Script 3 v11a Concluído";
    }
}
