// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeReplicateAndExploitTCTest_v31, // Importa a nova função de teste
    FNAME_MODULE_V31 
} from './testTypeConfusionExploitation.mjs'; // Mantendo o nome do arquivo, mas a lógica interna mudou
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs'; 
import { toHex } from '../utils.mjs';

async function runReplicateTCAndExploitStrategy_v31() {
    const FNAME_RUNNER = "runReplicateTCAndExploitStrategy_v31";
    logS3(`==== INICIANDO Estratégia de Replicação e Exploração de Type Confusion (v31) ====`, 'test', FNAME_RUNNER);

    const result = await executeReplicateAndExploitTCTest_v31();

    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
    } else if (result.potentiallyCrashed) {
         logS3(`   RESULTADO: CONGELAMENTO POTENCIAL. Detalhes da toJSON (se chamada): ${JSON.stringify(result.toJSON_details)}`, "critical", FNAME_RUNNER);
    } else {
        logS3(`   RESULTADO: Completou. Detalhes da toJSON: ${JSON.stringify(result.toJSON_details)}`, "good", FNAME_RUNNER);
    }
    // O título da página deve ser atualizado dentro de executeReplicateAndExploitTCTest_v31
    logS3(`   Título da página final: ${document.title}`, "info");

    logS3(`==== Estratégia de Replicação e Exploração de Type Confusion (v31) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_V31}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Replicando TC e Tentando Exploração (v31) ====`, 'test', FNAME_ORCHESTRATOR);

    await runReplicateTCAndExploitStrategy_v31();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    // Fallback para o título se não foi setado por sucesso/erro específico
    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_V31)) {
        if (!document.title.includes("CRASH") && !document.title.includes("PROBLEM") && 
            !document.title.includes("SUCCESS") && !document.title.includes("ERR") && 
            !document.title.includes("TYPE CONFUSION") && !document.title.includes("R/W PRIMITIVE")) {
            document.title = `${FNAME_MODULE_V31} Concluído`;
        }
    }
}
