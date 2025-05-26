// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a nova função de teste
import { executeMyComplexObjectGetterExploitTest } from './testMyComplexObjectGetterExploit.mjs'; // Nome do arquivo atualizado

async function runMyComplexObjectGetterStrategy() {
    const FNAME_RUNNER = "runMyComplexObjectGetterStrategy";
    logS3(`==== INICIANDO Estratégia de Exploração do Getter em MyComplexObject ====`, 'test', FNAME_RUNNER);

    await executeMyComplexObjectGetterExploitTest();

    logS3(`==== Estratégia de Exploração do Getter em MyComplexObject CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_MyComplexObjectGetterExploit';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Teste de Exploração do Getter em MyComplexObject ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - MyComplexObject Getter Exploit";

    await runMyComplexObjectGetterStrategy();

    logS3(`\n==== Script 3 CONCLUÍDO (MyComplexObject Getter Exploit) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes("CONGELOU?")) {
        // Manter
    } else if (document.title.includes("SUCCESS") || document.title.includes("ERRO") || document.title.includes("CRASH") || document.title.includes("Called") || document.title.includes("Modified")) {
        // Manter títulos que indicam resultados específicos
    }
    else {
        document.title = "Script 3 Concluído - MyComplexObject Getter Exploit";
    }
}
