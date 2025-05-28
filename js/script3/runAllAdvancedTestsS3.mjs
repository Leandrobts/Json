// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a nova função de teste
import { executeFakeArrayBufferActivateTest } from './testFakeArrayBufferActivate.mjs'; // Atualizado

async function runFakeABActivateStrategy() { // Nome da estratégia atualizado
    const FNAME_RUNNER = "runFakeABActivateStrategy";
    logS3(`==== INICIANDO Estratégia de Ativação de ArrayBuffer Falso ====`, 'test', FNAME_RUNNER);

    await executeFakeArrayBufferActivateTest();

    logS3(`==== Estratégia de Ativação de ArrayBuffer Falso CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_FakeABActivate'; // Nome do teste principal atualizado
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Ativação Especulativa de Fake ArrayBuffer (StructureID=2) ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - Fake AB Activate";

    await runFakeABActivateStrategy(); // Chama a nova estratégia

    logS3(`\n==== Script 3 CONCLUÍDO (Fake AB Activate) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (!document.title.includes("SUCCESS")) {
         document.title = "Script 3 Concluído - Fake AB Activate";
    }
}
