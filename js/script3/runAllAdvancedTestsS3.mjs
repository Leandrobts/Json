// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// A importação já pega a versão mais recente de sprayAndInvestigateObjectExposure
import { sprayAndInvestigateObjectExposure } from './testRetypeOOB_AB_ViaShadowCraft.mjs'; 

async function runSprayAndInvestigateStrategy() {
    const FNAME_RUNNER = "runSprayAndInvestigateStrategy";
    logS3(`==== INICIANDO Estratégia de Investigação com Spray e Corrupção ====`, 'test', FNAME_RUNNER);
    await sprayAndInvestigateObjectExposure(); // Chamando a função atualizada
    logS3(`==== Estratégia de Investigação com Spray e Corrupção CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_SprayInvestigate_v7'; // Atualizado para v7
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME);

    logS3(`==== INICIANDO Script 3: Investigação Focada com Spray e Corrupção (v7) ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - Spray & Investigate v7";

    await runSprayAndInvestigateStrategy();
    
    logS3(`\n==== Script 3 CONCLUÍDO (Investigação com Spray v7) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (document.title.includes("ACHADO") || document.title.includes("PROVÁVEL") || document.title.includes("SUPER ARRAY")) {
        // Mantém o título específico do achado
    } else if (!document.title.includes("FAIL") && !document.title.includes("ERRO")) {
         document.title = "Script 3 Concluído - Spray & Investigate v7";
    }
}
