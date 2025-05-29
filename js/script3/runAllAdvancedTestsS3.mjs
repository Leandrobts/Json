// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Atualizar a importação
import { sprayAndInvestigateObjectExposure, executeRetypeOOB_AB_Test } from './testRetypeOOB_AB_ViaShadowCraft.mjs'; // attemptWebKitBaseLeakStrategy_OLD removida da chamada principal por enquanto

// A função runRetypeOOB_AB_Strategy pode ser mantida se você quiser executar o teste 0x6C separadamente
async function runRetypeOOB_AB_Strategy() {
    const FNAME_RUNNER = "runRetypeOOB_AB_Strategy";
    logS3(`==== INICIANDO Estratégia de "Re-Tipagem" do oob_array_buffer_real ====`, 'test', FNAME_RUNNER);
    await executeRetypeOOB_AB_Test();
    logS3(`==== Estratégia de "Re-Tipagem" do oob_array_buffer_real CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}


async function runSprayAndInvestigateStrategy() {
    const FNAME_RUNNER = "runSprayAndInvestigateStrategy";
    logS3(`==== INICIANDO Estratégia de Investigação com Spray e Corrupção ====`, 'test', FNAME_RUNNER);
    await sprayAndInvestigateObjectExposure(); // Chamando a nova função
    logS3(`==== Estratégia de Investigação com Spray e Corrupção CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_SprayInvestigate_v2';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Investigação Focada com Spray e Corrupção ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - Spray & Investigate v2";

    // Opcional: validar a corrupção 0x6C primeiro
    // logS3(`\n==== VALIDANDO CORRUPÇÃO 0x6C (Pré-teste) ====`,'test', FNAME);
    // await runRetypeOOB_AB_Strategy();
    // await PAUSE_S3(MEDIUM_PAUSE_S3);

    // Foco principal: Investigar os efeitos da corrupção após o spray
    logS3(`\n==== FOCO: Investigando Exposição de ArrayBufferView via Corrupção 0x6C após Spray ====`,'test', FNAME);
    await runSprayAndInvestigateStrategy();
    
    logS3(`\n==== Script 3 CONCLUÍDO (Investigação com Spray v2) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (!document.title.includes("Corrompido") && !document.title.includes("FAIL") && !document.title.includes("ERRO") && !document.title.includes("Concluída")) {
         document.title = "Script 3 Concluído - Spray & Investigate v2";
    }
}
