// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeTypeConfusionExploitTest, // Importa a nova função de teste
    FNAME_MODULE_V29 
} from './testTypeConfusionExploitation.mjs'; // Nome do NOVO arquivo
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs'; 
import { toHex } from '../utils.mjs';

async function runTypeConfusionExploitStrategy() {
    const FNAME_RUNNER = "runTypeConfusionExploitStrategy_v29";
    logS3(`==== INICIANDO Estratégia de Exploração de Type Confusion (v29) ====`, 'test', FNAME_RUNNER);

    const result = await executeTypeConfusionExploitTest();

    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
    } else if (result.potentiallyCrashed) {
         logS3(`   RESULTADO: CONGELAMENTO POTENCIAL. Detalhes da toJSON (se chamada): ${JSON.stringify(result.toJSON_details)}`, "critical", FNAME_RUNNER);
    } else {
        logS3(`   RESULTADO: Completou. Detalhes da toJSON: ${JSON.stringify(result.toJSON_details)}`, "good", FNAME_RUNNER);
    }
    logS3(`   Título da página: ${document.title}`, "info");

    logS3(`==== Estratégia de Exploração de Type Confusion (v29) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_V29}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Explorando Type Confusion com victim_ab (v29) ====`, 'test', FNAME_ORCHESTRATOR);

    await runTypeConfusionExploitStrategy();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_V29)) {
        if (!document.title.includes("CRASH") && !document.title.includes("PROBLEM") && !document.title.includes("SUCCESS") && !document.title.includes("ERR") && !document.title.includes("TYPE CONFUSION")) {
            document.title = `${FNAME_MODULE_V29} Concluído`;
        }
    }
}
