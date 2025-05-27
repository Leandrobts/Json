// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a nova função de teste
import { executeGetterTriggerReproTest } from './testMyComplexObjectGetterRepro.mjs'; // Atualizado o nome do arquivo

async function runReproduceGetterTriggerStrategy() {
    const FNAME_RUNNER = "runReproduceGetterTriggerStrategy";
    logS3(`==== INICIANDO Estratégia de Reprodução do Acionamento do Getter em MyComplexObject ====`, 'test', FNAME_RUNNER);

    await executeGetterTriggerReproTest();

    logS3(`==== Estratégia de Reprodução do Acionamento do Getter em MyComplexObject CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_ReproduceMyComplexGetter'; // Nome do teste principal atualizado
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Tentativa de Reproduzir Acionamento do Getter em MyComplexObject ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - Reproduce MyComplex Getter";

    await runReproduceGetterTriggerStrategy();

    logS3(`\n==== Script 3 CONCLUÍDO (Reproduce MyComplex Getter) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes("CONGELOU?")) {
        // Manter
    } else if (document.title.includes("SUCCESS") || document.title.includes("ERRO") || document.title.includes("RangeError") || document.title.includes("PROBLEM") || document.title.includes("Called") || document.title.includes("Modified")) {
        // Manter títulos que indicam resultados específicos
    }
    else {
        document.title = "Script 3 Concluído - Reproduce MyComplex Getter";
    }
}
