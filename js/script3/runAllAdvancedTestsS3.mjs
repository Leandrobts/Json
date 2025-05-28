// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a nova função de teste
import { executeImmediateEffectOfOOBWriteTest } from './testImmediateEffectOfOOBWrite.mjs';

async function runImmediateEffectStrategy() {
    const FNAME_RUNNER = "runImmediateEffectStrategy";
    logS3(`==== INICIANDO Estratégia de Verificação do Efeito Imediato da Escrita OOB em 0x70 ====`, 'test', FNAME_RUNNER);

    await executeImmediateEffectOfOOBWriteTest();

    logS3(`==== Estratégia de Verificação do Efeito Imediato da Escrita OOB em 0x70 CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_ImmediateEffectOOB0x70';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Verificação do Efeito Imediato da Escrita OOB em 0x70 ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - Immediate 0x70 Effect";

    await runImmediateEffectStrategy();

    logS3(`\n==== Script 3 CONCLUÍDO (Immediate 0x70 Effect) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    // Ajuste final do título
    if (document.title.startsWith("Iniciando")) { // Se ainda está com o título inicial, pode ter congelado cedo
        document.title = "FREEZE? Initial 0x70 Effect";
    } else if (document.title.includes("CRASH") || document.title.includes("ERROR") || document.title.includes("FREEZE?")) {
        // Manter títulos que indicam problemas
    } else if (document.title.includes("Survived")) {
        // Manter título de sucesso
    }
    else {
        document.title = "Script 3 Concluído - Immediate 0x70 Effect";
    }
}
