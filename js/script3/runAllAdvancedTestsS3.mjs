// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a nova função de teste
import { executeSequentialStringifyTest } from './testSequentialStringify.mjs'; // Nome do arquivo atualizado

async function runSequentialStringifyInvestigation() {
    const FNAME_RUNNER = "runSequentialStringifyInvestigation";
    logS3(`==== INICIANDO Investigação de Stringify Sequencial em victim_ab ====`, 'test', FNAME_RUNNER);

    await executeSequentialStringifyTest();

    logS3(`==== Investigação de Stringify Sequencial em victim_ab CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_SequentialStringify';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Investigação de Stringify Sequencial em victim_ab Pós-Corrupção ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - Seq. Stringify victim_ab";

    await runSequentialStringifyInvestigation();

    logS3(`\n==== Script 3 CONCLUÍDO (Investigação Seq. Stringify victim_ab) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes("CONGELOU?")) {
        // Manter
    } else if (document.title.includes("SUCCESS") || document.title.includes("Type Confusion") || document.title.includes("ERRO") || document.title.includes("CRASH")) {
        // Manter títulos que indicam resultados específicos
    }
    else {
        document.title = "Script 3 Concluído - Seq. Stringify victim_ab";
    }
}
