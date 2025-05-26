// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a nova função de teste
import { executeAttemptToReproduceRangeError } from './testRevisitOriginalRangeError.mjs'; // Nome do arquivo atualizado

async function runAttemptReproduceRangeErrorStrategy() {
    const FNAME_RUNNER = "runAttemptReproduceRangeErrorStrategy";
    logS3(`==== INICIANDO Estratégia de Tentativa de Reprodução do RangeError Original (MyComplexObject) ====`, 'test', FNAME_RUNNER);

    await executeAttemptToReproduceRangeError();

    logS3(`==== Estratégia de Tentativa de Reprodução do RangeError Original CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_AttemptRevisitOriginalRangeError';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Tentativa de Reprodução do RangeError Original com MyComplexObject ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - Attempt Original RangeError";

    await runAttemptReproduceRangeErrorStrategy();

    logS3(`\n==== Script 3 CONCLUÍDO (Attempt Original RangeError) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes("CONGELOU?")) {
        // Manter
    } else if (document.title.includes("RangeError") || document.title.includes("ERRO") || document.title.includes("CRASH") || document.title.includes("vuln")) {
        // Manter títulos que indicam resultados específicos
    }
    else {
        document.title = "Script 3 Concluído - Attempt Original RangeError";
    }
}
