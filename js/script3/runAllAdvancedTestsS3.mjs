// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a nova função de teste
import { executeCorruptedIteratorLeakFocusConsoleTest } from './testCorruptedIteratorLeakFocusConsole.mjs';

async function runCorruptedIteratorLeakFocusConsoleStrategy() {
    const FNAME_RUNNER = "runCorruptedIteratorLeakFocusConsoleStrategy";
    logS3(`==== INICIANDO Estratégia de Vazamento por Iterador Corrompido (Foco Console PS4) ====`, 'test', FNAME_RUNNER);

    await executeCorruptedIteratorLeakFocusConsoleTest();

    logS3(`==== Estratégia de Vazamento por Iterador Corrompido (Foco Console PS4) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_CorruptedIteratorLeakFocusConsole';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Teste de Vazamento por Iterador Corrompido (Foco Console PS4) ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - Corrupted Iterator Leak (Console)";

    await runCorruptedIteratorLeakFocusConsoleStrategy();

    logS3(`\n==== Script 3 CONCLUÍDO (Corrupted Iterator Leak Console) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes("CONGELOU?")) {
        // Manter
    } else if (document.title.includes("LEAK") || document.title.includes("RangeError") || document.title.includes("REPRODUCED") || document.title.includes("ERRO")) {
        // Manter títulos que indicam resultados específicos
    }
    else {
        document.title = "Script 3 Concluído - Corrupted Iterator Leak (Console)";
    }
}
