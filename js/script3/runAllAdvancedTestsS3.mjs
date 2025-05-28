// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a nova função de teste
import { executeGetterAndCorruptedPropForFakeABTest } from './testGetterAndCorruptedPropForFakeAB.mjs';

async function runGetterAndCorruptedPropStrategy() {
    const FNAME_RUNNER = "runGetterAndCorruptedPropStrategy";
    logS3(`==== INICIANDO Estratégia: Getter + Propriedade Corrompida para Ativar Fake AB ====`, 'test', FNAME_RUNNER);

    await executeGetterAndCorruptedPropForFakeABTest();

    logS3(`==== Estratégia: Getter + Propriedade Corrompida para Ativar Fake AB CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_GetterCorruptPropFakeAB';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Getter + Propriedade Corrompida para Ativar Fake AB ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - Getter+CorruptProp FakeAB";

    await runGetterAndCorruptedPropStrategy();

    logS3(`\n==== Script 3 CONCLUÍDO (Getter+CorruptProp FakeAB) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    // Ajuste final do título
    if (document.title.startsWith("Iniciando") || document.title.includes("CONGELOU?")) {
        // Manter
    } else if (document.title.includes("SUCCESS") || document.title.includes("ERRO") || document.title.includes("PROBLEM")) {
        // Manter títulos que indicam resultados específicos
    }
    else {
        document.title = "Script 3 Concluído - Getter+CorruptProp FakeAB";
    }
}
