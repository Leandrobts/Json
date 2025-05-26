// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a nova função de teste
import { executeForInGadgetTest } from './testForInGadget.mjs';

async function runForInGadgetStrategy() {
    const FNAME_RUNNER = "runForInGadgetStrategy";
    logS3(`==== INICIANDO Estratégia de Gadget via for...in Corrompido ====`, 'test', FNAME_RUNNER);

    await executeForInGadgetTest();

    logS3(`==== Estratégia de Gadget via for...in Corrompido CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_ForInGadget';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Teste de Gadget via for...in Corrompido ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - Test ForIn Gadget";

    await runForInGadgetStrategy();

    logS3(`\n==== Script 3 CONCLUÍDO (Teste de Gadget via for...in) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    // Ajuste final do título
    if (document.title.startsWith("Iniciando") || document.title.includes("CONGELOU?")) {
        // Manter
    } else if (document.title.includes("SUCCESS") || document.title.includes("ERRO") || document.title.includes("RangeError") || document.title.includes("PROBLEM")) {
        // Manter títulos que indicam resultados específicos
    }
    else {
        document.title = "Script 3 Concluído - Test ForIn Gadget";
    }
}
