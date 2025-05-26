// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { executeAggressiveHeapSprayAndCorruptTest } from './testAggressiveHeapSpray.mjs';

async function runAggressiveSprayStrategy() {
    const FNAME_RUNNER = "runAggressiveSprayStrategy";
    logS3(`==== INICIANDO Estratégia de Spray Agressivo e Corrupção Múltipla ====`, 'test', FNAME_RUNNER);

    await executeAggressiveHeapSprayAndCorruptTest();

    logS3(`==== Estratégia de Spray Agressivo e Corrupção Múltipla CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_AggressiveSpray';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Spray Agressivo, Corrupção OOB Múltipla e Sondagem de Vítimas ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - AggroSpray & Corrupt";

    await runAggressiveSprayStrategy();

    logS3(`\n==== Script 3 CONCLUÍDO (AggroSpray & Corrupt) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes("CONGELOU?")) {
        // Manter
    } else if (document.title.includes("SUCCESS") || document.title.includes("ERRO") || document.title.includes("CRASH")) {
        // Manter títulos que indicam resultados específicos
    }
    else {
        document.title = "Script 3 Concluído - AggroSpray & Corrupt";
    }
}
