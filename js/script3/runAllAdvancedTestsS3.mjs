// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a nova função de teste
import { executeDiagnoseRangeErrorOnComplexTest } from './testDiagnoseRangeErrorOnComplex.mjs';

async function runDiagnoseRangeErrorStrategy() {
    const FNAME_RUNNER = "runDiagnoseRangeErrorStrategy";
    logS3(`==== INICIANDO Estratégia de Diagnóstico do RangeError em Objetos Complexos ====`, 'test', FNAME_RUNNER);

    await executeDiagnoseRangeErrorOnComplexTest();

    logS3(`==== Estratégia de Diagnóstico do RangeError em Objetos Complexos CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_DiagnoseRangeErrorComplex';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Diagnóstico do RangeError em Objetos Complexos Pós-Corrupção ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - Diagnose RE ComplexObj";

    await runDiagnoseRangeErrorStrategy();

    logS3(`\n==== Script 3 CONCLUÍDO (Diagnose RE ComplexObj) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    // Ajuste final do título
    if (document.title.startsWith("Iniciando") || document.title.includes("CONGELOU?")) {
        // Manter
    } else if (document.title.includes("RangeError") || document.title.includes("REPRODUCED") || document.title.includes("ERRO")) {
        // Manter títulos que indicam resultados específicos
    }
    else {
        document.title = "Script 3 Concluído - Diagnose RE ComplexObj";
    }
}
