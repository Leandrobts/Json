// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a nova função de teste
import { executeGetterInspectsCorruptedPropsTest } from './testGetterInspectsCorruptedProps.mjs';

async function runGetterInspectsCorruptedPropsStrategy() {
    const FNAME_RUNNER = "runGetterInspectsCorruptedPropsStrategy";
    logS3(`==== INICIANDO Estratégia: Getter Inspeciona Props Corrompidas para Leaks de Ponteiro ====`, 'test', FNAME_RUNNER);

    await executeGetterInspectsCorruptedPropsTest();

    logS3(`==== Estratégia: Getter Inspeciona Props Corrompidas para Leaks de Ponteiro CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_GetterInspectsCorruptedProps';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Getter Inspeciona Props Corrompidas para Leaks de Ponteiro ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - Getter Inspects Props";

    await runGetterInspectsCorruptedPropsStrategy();

    logS3(`\n==== Script 3 CONCLUÍDO (Getter Inspects Props) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    // Ajuste final do título
    if (document.title.startsWith("Iniciando") || document.title.includes("CONGELOU?")) {
        // Manter
    } else if (document.title.includes("SUCCESS") || document.title.includes("ERRO") || document.title.includes("PROBLEM") || document.title.includes("Leaked")) {
        // Manter títulos que indicam resultados específicos
    }
    else {
        document.title = "Script 3 Concluído - Getter Inspects Props";
    }
}
