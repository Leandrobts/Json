// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { sprayAndInvestigateObjectExposure } from './testRetypeOOB_AB_ViaShadowCraft.mjs'; 

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = 'runAllAdvancedTestsS3_Orchestrator_v25'; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 via ${FNAME_ORCHESTRATOR} (Teste v25: MinimalVictimProbe) ====`, 'test', FNAME_ORCHESTRATOR);
    
    let testResult = null;
    try {
        testResult = await sprayAndInvestigateObjectExposure(); 
    } catch (e) {
        logS3(`ERRO CRÍTICO não capturado por sprayAndInvestigateObjectExposure: ${e.message}`, "critical", FNAME_ORCHESTRATOR);
        if (e.stack) {
            logS3(`Stack: ${e.stack}`, "critical", FNAME_ORCHESTRATOR);
        }
        document.title = "ERRO GERAL S3 ORCHESTRATOR";
    }
    
    logS3(`\n==== Script 3 (orquestrado por ${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;
    
    if (testResult) {
        if (testResult.potentiallyCrashed && !testResult.errorOccurred) {
             if(!document.title.includes("CRASH") && !document.title.includes("PROBLEM") && !document.title.includes("SUCCESS")) {
                document.title = `v25 CONGELOU?`;
             }
        } else if (testResult.errorOccurred) {
            if(!document.title.includes("CRASH") && !document.title.includes("PROBLEM") && !document.title.includes("SUCCESS") && !document.title.includes("FALHOU")) {
                 document.title = `v25 ERRO: ${testResult.errorOccurred.name}`;
            }
        } else if (testResult.getter_probe_details?.error) {
             document.title = `v25 toJSON Probe Err`;
        } else if (testResult.getter_probe_details?.probe_called) {
            document.title = "v25 MinimalProbe Executed";
        }
         else if (!document.title.includes("SUCCESS") && !document.title.includes("POTENTIAL") && !document.title.includes("FALHOU") && !document.title.includes("CRASH")) {
            document.title = "v25 Concluído";
        }
    } else if (!document.title.includes("FALHOU") && !document.title.includes("CRASH") && !document.title.includes("ERRO")) {
         document.title = "Script 3 (v25) Concluído";
    }
}
