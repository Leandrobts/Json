// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Atualizar a importação para incluir a nova função de spray e investigação
import { executeRetypeOOB_AB_Test, sprayAndInvestigateObjectExposure, attemptWebKitBaseLeakStrategy_OLD } from './testRetypeOOB_AB_ViaShadowCraft.mjs';

async function runRetypeOOB_AB_Strategy() {
    const FNAME_RUNNER = "runRetypeOOB_AB_Strategy";
    logS3(`==== INICIANDO Estratégia de "Re-Tipagem" do oob_array_buffer_real ====`, 'test', FNAME_RUNNER);
    await executeRetypeOOB_AB_Test();
    logS3(`==== Estratégia de "Re-Tipagem" do oob_array_buffer_real CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

async function runSprayAndInvestigateStrategy() {
    const FNAME_RUNNER = "runSprayAndInvestigateStrategy";
    logS3(`==== INICIANDO Estratégia de Investigação com Spray e Corrupção ====`, 'test', FNAME_RUNNER);
    await sprayAndInvestigateObjectExposure(); // Nova função
    logS3(`==== Estratégia de Investigação com Spray e Corrupção CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_SprayInvestigate';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Investigação com Spray e Corrupção ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - Spray & Investigate";

    // 1. (Opcional) Validar a corrupção 0x6C separadamente primeiro
    // await runRetypeOOB_AB_Strategy();
    // await PAUSE_S3(MEDIUM_PAUSE_S3);

    // 2. Executar a investigação com spray e corrupção
    await runSprayAndInvestigateStrategy();
    
    logS3(`\n==== Script 3 CONCLUÍDO (Investigação com Spray) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (!document.title.includes("SUCCESS") && !document.title.includes("FAIL") && !document.title.includes("ERRO") && !document.title.includes("Concluída")) {
         document.title = "Script 3 Concluído - Spray & Investigate";
    }
}
