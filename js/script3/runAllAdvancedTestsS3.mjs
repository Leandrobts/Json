// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a nova função de teste
import { executeForInGadgetExplorationTest_V2 } from './testForInGadgetExploration.mjs'; // Nome do arquivo atualizado

async function runForInGadgetExplorationStrategyV2() {
    const FNAME_RUNNER = "runForInGadgetExplorationStrategyV2";
    logS3(`==== INICIANDO Estratégia de Exploração Detalhada de Gadget via for...in (V2) ====`, 'test', FNAME_RUNNER);

    await executeForInGadgetExplorationTest_V2();

    logS3(`==== Estratégia de Exploração Detalhada de Gadget via for...in (V2) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_ForInGadgetExplorationV2';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Teste de Exploração Detalhada de Gadget via for...in (V2) ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - Explore ForIn Gadget V2";

    await runForInGadgetExplorationStrategyV2();

    logS3(`\n==== Script 3 CONCLUÍDO (Teste de Exploração Detalhada de Gadget via for...in V2) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes("CONGELOU?")) {
        // Manter
    } else if (document.title.includes("SUCCESS") || document.title.includes("ERRO") || document.title.includes("RangeError") || document.title.includes("PROBLEM") || document.title.includes("Called") || document.title.includes("Modified")) {
        // Manter títulos que indicam resultados específicos
    }
    else {
        document.title = "Script 3 Concluído - Explore ForIn Gadget V2";
    }
}
