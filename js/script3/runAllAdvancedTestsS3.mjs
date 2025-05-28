// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a nova função de teste
import { executeOOBWriteSurvivalTest } from './testOOBWriteSurvival.mjs';

async function runOOBWriteSurvivalStrategy() {
    const FNAME_RUNNER = "runOOBWriteSurvivalStrategy";
    logS3(`==== INICIANDO Estratégia de Teste de Sobrevivência a Escritas OOB Críticas ====`, 'test', FNAME_RUNNER);

    await executeOOBWriteSurvivalTest();

    logS3(`==== Estratégia de Teste de Sobrevivência a Escritas OOB Críticas CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_OOBWriteSurvival';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Teste de Sobrevivência a Escritas OOB Críticas ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - OOB Write Survival";

    await runOOBWriteSurvivalStrategy();

    logS3(`\n==== Script 3 CONCLUÍDO (OOB Write Survival) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    // Ajuste final do título
    if (document.title.startsWith("Iniciando")) {
        document.title = "Script 3 Concluído - OOB Write Survival (Verificar Logs)";
    } else if (document.title.includes("CRASH") || document.title.includes("ERROR") || document.title.includes("FREEZE?")) {
        // Manter títulos que indicam problemas
    } else if (document.title.includes("Survived")) {
        // Manter título de sucesso para o último caso testado que sobreviveu
    }
    else {
        document.title = "Script 3 Concluído - OOB Write Survival";
    }
}
