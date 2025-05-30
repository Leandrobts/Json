// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importar o wrapper do teste com getter
import { executeRetypeOOB_AB_Test_Wrapper } from './testRetypeOOB_AB_ViaShadowCraft.mjs';

async function runGetterInteractionStrategy_v13a() {
    const FNAME_RUNNER = "runGetterInteractionStrategy_v13a";
    logS3(`==== INICIANDO Estratégia: ${FNAME_RUNNER} ====`, 'test', FNAME_RUNNER);
    await executeRetypeOOB_AB_Test_Wrapper(); // Chama o wrapper que itera os padrões
    logS3(`==== Estratégia ${FNAME_RUNNER} CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_GetterTest_v13a';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME);
    logS3(`==== INICIANDO Script 3: Teste de Interação com Getter e Corrupção 0x70->0x6C (lógica v13a) ====`,'test', FNAME);
    document.title = `Iniciando Script 3 - Getter Test v13a`;

    await runGetterInteractionStrategy_v13a(); 
    
    logS3(`\n==== Script 3 CONCLUÍDO (lógica v13a) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (!document.title.includes("Getter Test:") && !document.title.includes("FALHOU")) {
        document.title = "Script 3 v13a Concluído";
    }
}
