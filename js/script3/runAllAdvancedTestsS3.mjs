// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a nova função de teste
import { executeForInExplorationOnComplexObject } from './testMyComplexObjectForInExploration.mjs';

async function runForInExplorationStrategy() {
    const FNAME_RUNNER = "runForInExplorationStrategy";
    logS3(`==== INICIANDO Estratégia de Exploração de 'for...in' em MyComplexObject Pós-Corrupção ====`, 'test', FNAME_RUNNER);

    await executeForInExplorationOnComplexObject();

    logS3(`==== Estratégia de Exploração de 'for...in' em MyComplexObject CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_ForInExplorationComplexObj';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Exploração de 'for...in' em MyComplexObject Pós-Corrupção ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - ForIn Expl. ComplexObj";

    await runForInExplorationStrategy();

    logS3(`\n==== Script 3 CONCLUÍDO (Exploração ForIn ComplexObj) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    // Ajuste final do título
    if (document.title.startsWith("Iniciando") || document.title.includes("CONGELOU?")) {
        // Manter
    } else if (document.title.includes("PROBLEM") || document.title.includes("ERRO") || document.title.includes("RangeError")) {
        // Manter títulos que indicam resultados específicos
    }
    else {
        document.title = "Script 3 Concluído - ForIn Expl. ComplexObj";
    }
}
