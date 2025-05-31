// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypeConfusionExploitTest_v34, // Nome da função de teste atualizado
    FNAME_MODULE_V34 
} from './testTypeConfusionExploitation.mjs'; 
// ... (outras importações como OOB_CONFIG, JSC_OFFSETS, toHex podem ser removidas daqui se não usadas diretamente)

async function runExploitTCStrategy_v34() { // Nome da estratégia atualizado
    const FNAME_RUNNER = "runExploitTCStrategy_v34";
    logS3(`==== INICIANDO Estratégia de Exploração de Type Confusion (v34) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypeConfusionExploitTest_v34();

    // ... (lógica de logging do resultado similar à v31, adaptada para v34) ...
    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
    } else if (result.potentiallyCrashed) {
         logS3(`   RESULTADO: CONGELAMENTO POTENCIAL. Detalhes da toJSON (se chamada): ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "critical", FNAME_RUNNER);
    } else {
        logS3(`   RESULTADO: Completou. Detalhes da toJSON: ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "good", FNAME_RUNNER);
    }
    logS3(`   Título da página final: ${document.title}`, "info");

    logS3(`==== Estratégia de Exploração de Type Confusion (v34) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_V34}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Explorando TC com Estrutura Fake (v34) ====`, 'test', FNAME_ORCHESTRATOR);

    await runExploitTCStrategy_v34();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    // ... (lógica de título final similar à v31) ...
     if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_V34)) {
        if (!document.title.includes("CRASH") && !document.title.includes("R/W PRIMITIVE") && !document.title.includes("SUCCESS")) {
            document.title = `${FNAME_MODULE_V34} Concluído`;
        }
    }
}
