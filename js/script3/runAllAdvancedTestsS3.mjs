// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a nova função de teste
import { executeGetterTriggerAndFakeABReadTest } from './testGetterTriggerAndFakeABRead.mjs';

async function runGetterAndFakeABStrategy() {
    const FNAME_RUNNER = "runGetterAndFakeABStrategy";
    logS3(`==== INICIANDO Estratégia de Acionamento de Getter e Leitura via Fake AB "Re-tipado" ====`, 'test', FNAME_RUNNER);

    await executeGetterTriggerAndFakeABReadTest();

    logS3(`==== Estratégia de Acionamento de Getter e Leitura via Fake AB "Re-tipado" CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_GetterAndFakeABRead';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Acionamento de Getter e Leitura via Fake AB "Re-tipado" ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - Getter & FakeAB Read";

    await runGetterAndFakeABStrategy();

    logS3(`\n==== Script 3 CONCLUÍDO (Getter & FakeAB Read) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes("CONGELOU?")) {
        // Manter
    } else if (document.title.includes("SUCCESS") || document.title.includes("ERRO") || document.title.includes("PROBLEM")) {
        // Manter títulos que indicam resultados específicos
    }
    else {
        document.title = "Script 3 Concluído - Getter & FakeAB Read";
    }
}
