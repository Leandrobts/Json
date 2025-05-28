// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a nova função de teste
import { executeMinimalForInOnComplexObjectTest } from './testMinimalForInOnComplexObject.mjs';

async function runMinimalForInStrategy() {
    const FNAME_RUNNER = "runMinimalForInStrategy";
    logS3(`==== INICIANDO Estratégia de 'for...in' Minimalista em MyComplexObject (RangeError Check) ====`, 'test', FNAME_RUNNER);

    await executeMinimalForInOnComplexObjectTest();

    logS3(`==== Estratégia de 'for...in' Minimalista em MyComplexObject (RangeError Check) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_MinimalForInComplexObj';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: 'for...in' Minimalista em MyComplexObject Pós-Corrupção (RangeError Check) ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - Minimal ForIn ComplexObj (RE Check)";

    await runMinimalForInStrategy();

    logS3(`\n==== Script 3 CONCLUÍDO (Minimal ForIn ComplexObj RE Check) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes("CONGELOU?")) {
        // Manter
    } else if (document.title.includes("RangeError") || document.title.includes("REPRODUCED") || document.title.includes("ERRO")) {
        // Manter títulos que indicam resultados específicos
    }
    else {
        document.title = "Script 3 Concluído - Minimal ForIn ComplexObj (RE Check)";
    }
}
