// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a nova função de teste
import { executeGetterChecksRetypedOOBABTest } from './testGetterChecksRetypedOOBAB.mjs';

async function runGetterChecksRetypedOOBABStrategy() {
    const FNAME_RUNNER = "runGetterChecksRetypedOOBABStrategy";
    logS3(`==== INICIANDO Estratégia: Getter Verifica oob_array_buffer_real "Re-tipado" ====`, 'test', FNAME_RUNNER);

    await executeGetterChecksRetypedOOBABTest();

    logS3(`==== Estratégia: Getter Verifica oob_array_buffer_real "Re-tipado" CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_GetterChecksRetypedOOBAB';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Getter Verifica oob_array_buffer_real "Re-tipado" ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - Getter Checks Retyped OOB_AB";

    await runGetterChecksRetypedOOBABStrategy();

    logS3(`\n==== Script 3 CONCLUÍDO (Getter Checks Retyped OOB_AB) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes("CONGELOU?")) {
        // Manter
    } else if (document.title.includes("SUCCESS") || document.title.includes("ERRO") || document.title.includes("PROBLEM")) {
        // Manter títulos que indicam resultados específicos
    }
    else {
        document.title = "Script 3 Concluído - Getter Checks Retyped OOB_AB";
    }
}
