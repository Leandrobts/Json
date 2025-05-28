// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a nova função de teste
import { executeFakeArrayBufferSimpleTest } from './testFakeArrayBufferSimple.mjs'; // Atualizado

async function runFakeABSimpleStrategy() { // Nome da estratégia atualizado
    const FNAME_RUNNER = "runFakeABSimpleStrategy";
    logS3(`==== INICIANDO Estratégia de ArrayBuffer Falso Simplificado ====`, 'test', FNAME_RUNNER);

    await executeFakeArrayBufferSimpleTest();

    logS3(`==== Estratégia de ArrayBuffer Falso Simplificado CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_FakeABSimple'; // Nome do teste principal atualizado
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: ArrayBuffer Falso Simplificado (StructureID=2) ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - Fake AB Simple";

    await runFakeABSimpleStrategy(); // Chama a nova estratégia

    logS3(`\n==== Script 3 CONCLUÍDO (Fake AB Simple) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (!document.title.includes("SUCCESS")) {
         document.title = "Script 3 Concluído - Fake AB Simple";
    }
}
