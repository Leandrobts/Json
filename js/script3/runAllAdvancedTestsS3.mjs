// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a nova função de teste
import { executeRevisitOriginalRangeErrorTest } from './testRevisitOriginalRangeError.mjs'; // Nome do arquivo atualizado

async function runRevisitOriginalRangeErrorStrategy() {
    const FNAME_RUNNER = "runRevisitOriginalRangeErrorStrategy";
    logS3(`==== INICIANDO Estratégia de Reinvestigação do RangeError Original (MyComplexObject) ====`, 'test', FNAME_RUNNER);

    const result = await executeRevisitOriginalRangeErrorTest();

    if (result && result.setupError) {
        logS3(`   Falha na configuração do teste: ${result.setupError.message}.`, "error", FNAME_RUNNER);
    } else if (result && result.stringifyError && result.stringifyError.name === 'RangeError') {
        logS3(`   !!!!!! RangeError FOI REPRODUZIDO no objeto ${result.targetObjectId} usando toJSON_ProbeGenericObject_Revisit !!!!!!`, "vuln", FNAME_RUNNER);
    } else if (result && result.stringifyError) {
        logS3(`   Outro erro (${result.stringifyError.name}) ocorreu no objeto ${result.targetObjectId}.`, "error", FNAME_RUNNER);
    } else {
        logS3(`   Teste com toJSON_ProbeGenericObject_Revisit completou SEM RangeError no objeto ${result.targetObjectId}. O Heisenbug persiste em sua ausência.`, "warn", FNAME_RUNNER);
    }

    logS3(`==== Estratégia de Reinvestigação do RangeError Original CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_RevisitOriginalRangeError';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Reinvestigação do RangeError Original com MyComplexObject ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - Revisit Original RangeError";

    await runRevisitOriginalRangeErrorStrategy();

    logS3(`\n==== Script 3 CONCLUÍDO (Revisit Original RangeError) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes("CONGELOU?")) {
        // Manter
    } else if (document.title.includes("RangeError REPRODUCED") || document.title.includes("ERRO") || document.title.includes("CRASH") || document.title.includes("vuln")) {
        // Manter títulos que indicam resultados específicos
    }
    else {
        document.title = "Script 3 Concluído - Revisit Original RangeError";
    }
}
