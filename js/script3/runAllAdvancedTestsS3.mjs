// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a nova função de teste
import { executeFakeABViaCorruptOffsetTest } from './testFakeABViaCorruptOffset.mjs';

async function runFakeABViaCorruptOffsetStrategy() {
    const FNAME_RUNNER = "runFakeABViaCorruptOffsetStrategy";
    logS3(`==== INICIANDO Estratégia: Fake AB via Corrupção de Offset em Propriedade ====`, 'test', FNAME_RUNNER);

    await executeFakeABViaCorruptOffsetTest();

    logS3(`==== Estratégia: Fake AB via Corrupção de Offset em Propriedade CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_FakeABViaCorruptOffset';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Fake AB via Corrupção de Offset em Propriedade ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - FakeAB via Corrupt Prop Offset";

    await runFakeABViaCorruptOffsetStrategy();

    logS3(`\n==== Script 3 CONCLUÍDO (FakeAB via Corrupt Prop Offset) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes("CONGELOU?")) {
        // Manter
    } else if (document.title.includes("SUCCESS") || document.title.includes("ERRO") || document.title.includes("PROBLEM")) {
        // Manter títulos que indicam resultados específicos
    }
    else {
        document.title = "Script 3 Concluído - FakeAB via Corrupt Prop Offset";
    }
}
