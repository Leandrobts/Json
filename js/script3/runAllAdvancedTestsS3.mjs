// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a função de teste principal e as toJSONs relevantes
import {
    executeRevisitForInRangeErrorTest,
    toJSON_ForIn_V4_Instrumented,
    toJSON_ProbeGenericObject_Revisit // A versão que visamos testar para o RangeError
} from './testInvestigateForInRCE.mjs'; // Nome do arquivo atualizado

async function runRevisitRangeErrorStrategyInvestigative() {
    const FNAME_RUNNER = "runRevisitRangeErrorStrategyInvestigative";
    logS3(`==== INICIANDO Estratégia de Reinvestigação do RangeError com for...in (Duas Variantes) ====`, 'test', FNAME_RUNNER);

    let result;
    let criticalErrorOccurred = false;

    // Teste 1: Com toJSON_ForIn_V4_Instrumented (esperamos que passe, como no último log)
    logS3(`\nExecutando sub-teste com toJSON: toJSON_ForIn_V4_Instrumented`, "info", FNAME_RUNNER);
    result = await executeRevisitForInRangeErrorTest(toJSON_ForIn_V4_Instrumented, "toJSON_ForIn_V4_Instrumented");
    if (result && result.stringifyError && result.stringifyError.name === 'RangeError') {
        logS3(`   !!!!!! RangeError INESPERADO com toJSON_ForIn_V4_Instrumented no objeto ${result.targetObjectId} !!!!!!`, "critical", FNAME_RUNNER);
        criticalErrorOccurred = true;
    } else if (result && result.stringifyError) {
        logS3(`   Erro com toJSON_ForIn_V4_Instrumented no objeto ${result.targetObjectId}: ${result.stringifyError.name}`, "error", FNAME_RUNNER);
    } else {
        logS3(`   Sub-teste com toJSON_ForIn_V4_Instrumented completou como esperado (sem RangeError) no objeto ${result.targetObjectId}.`, "good", FNAME_RUNNER);
    }
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    // Teste 2: Com toJSON_ProbeGenericObject_Revisit (esperamos que esta possa causar o RangeError)
    if (!criticalErrorOccurred || !document.title.includes("RangeError")) { // Só prossegue se o primeiro não deu RangeError
        logS3(`\nExecutando sub-teste com toJSON: toJSON_ProbeGenericObject_Revisit`, "info", FNAME_RUNNER);
        result = await executeRevisitForInRangeErrorTest(toJSON_ProbeGenericObject_Revisit, "toJSON_ProbeGenericObject_Revisit");
        if (result && result.stringifyError && result.stringifyError.name === 'RangeError') {
            logS3(`   !!!!!! RangeError ESPERADO/REPRODUZIDO com toJSON_ProbeGenericObject_Revisit no objeto ${result.targetObjectId} !!!!!!`, "vuln", FNAME_RUNNER);
            document.title = `RangeError with ProbeGenericRevisit!`;
        } else if (result && result.stringifyError) {
            logS3(`   Outro erro com toJSON_ProbeGenericObject_Revisit no objeto ${result.targetObjectId}: ${result.stringifyError.name}`, "error", FNAME_RUNNER);
        } else {
            logS3(`   Sub-teste com toJSON_ProbeGenericObject_Revisit completou SEM RangeError no objeto ${result.targetObjectId}. O Heisenbug continua...`, "warn", FNAME_RUNNER);
        }
    } else {
        logS3("Pulando teste com toJSON_ProbeGenericObject_Revisit devido a RangeError no teste anterior.", "warn", FNAME_RUNNER);
    }

    logS3(`==== Estratégia de Reinvestigação do RangeError (Duas Variantes) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_RevisitForInRangeErrorInvestigative';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Reinvestigação do RangeError com for...in (Duas Variantes) ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - Revisit ForIn RangeError (Investigative)";

    await runRevisitRangeErrorStrategyInvestigative();

    logS3(`\n==== Script 3 CONCLUÍDO (Revisit ForIn RangeError Investigative) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes("CONGELOU?")) {
        // Manter
    } else if (document.title.includes("RangeError") || document.title.includes("ERRO") || document.title.includes("CRASH") || document.title.includes("vuln")) {
        // Manter títulos que indicam resultados específicos
    }
    else {
        document.title = "Script 3 Concluído - Revisit ForIn RangeError (Investigative)";
    }
}
