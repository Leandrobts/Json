// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { executeRangeErrorToArbitraryReadTest } from './testRangeErrorToArbitraryRead.mjs'; // Arquivo novo

async function runRangeErrorToArbitraryReadStrategy() {
    const FNAME_RUNNER = "runRangeErrorToArbitraryReadStrategy";
    logS3(`==== INICIANDO Estratégia: RangeError para Leitura Arbitrária ====`, 'test', FNAME_RUNNER);
    await executeRangeErrorToArbitraryReadTest();
    logS3(`==== Estratégia: RangeError para Leitura Arbitrária CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_RangeErrorToArbRead';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Teste RangeError para Leitura Arbitrária ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - RE to ArbRead";

    await runRangeErrorToArbitraryReadStrategy();

    logS3(`\n==== Script 3 CONCLUÍDO (RE to ArbRead) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes("CONGELOU?")) { /* Manter */ }
    else if (document.title.includes("SUCCESS") || document.title.includes("ERRO") || document.title.includes("RangeError")) { /* Manter */ }
    else { document.title = "Script 3 Concluído - RE to ArbRead"; }
}
