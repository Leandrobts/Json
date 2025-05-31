// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a função de teste principal do arquivo que contém a lógica do ExploitLogic_v23_RevisitOriginalCrash
import { sprayAndInvestigateObjectExposure } from './testRetypeOOB_AB_ViaShadowCraft.mjs'; 

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = 'runAllAdvancedTestsS3_Orchestrator_v23'; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    // Log do User Agent para referência
    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 via ${FNAME_ORCHESTRATOR} ====`, 'test', FNAME_ORCHESTRATOR);
    // O título inicial será definido pela função chamada (sprayAndInvestigateObjectExposure)

    try {
        // sprayAndInvestigateObjectExposure agora contém a lógica de ExploitLogic_v23_RevisitOriginalCrash
        await sprayAndInvestigateObjectExposure(); 
    } catch (e) {
        logS3(`ERRO CRÍTICO não capturado pela função de teste principal: ${e.message}`, "critical", FNAME_ORCHESTRATOR);
        if (e.stack) {
            logS3(`Stack: ${e.stack}`, "critical", FNAME_ORCHESTRATOR);
        }
        document.title = "ERRO GERAL S3 ORCHESTRATOR";
    }
    
    logS3(`\n==== Script 3 (orquestrado por ${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;
    
    // A lógica de atualização do título no finally da função sprayAndInvestigateObjectExposure
    // já deve ter definido um título apropriado. Se não, um fallback.
    if (document.title.startsWith("Iniciando")) {
        if (!document.title.includes("CRASH") && 
            !document.title.includes("PROBLEM") && 
            !document.title.includes("SUCCESS") && 
            !document.title.includes("POTENTIAL") &&
            !document.title.includes("FALHOU") &&
            !document.title.includes("ERR")) {
           document.title = "Script 3 (v23) Concluído";
        }
    }
}
