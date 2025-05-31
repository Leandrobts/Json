// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeMinimalTCReplicationTest_v31, // Nome antigo, vamos renomear a importação
    FNAME_MODULE_V31 // Nome antigo
} from './testMinimalTCReplication.mjs'; // Nome do NOVO arquivo
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs'; 
import { toHex } from '../utils.mjs';

// Renomear a função importada para refletir o v31 (embora o módulo interno seja v32)
const executeTestV31Logic = executeMinimalTCReplicationTest_v31;
const FNAME_MODULE_FOR_ORCHESTRATOR = FNAME_MODULE_V31;


async function runReplicateTC_v31_Strategy() {
    const FNAME_RUNNER = "runReplicateTC_v31_Strategy";
    logS3(`==== INICIANDO Estratégia de Replicação de Type Confusion (v31 - baseada em v26) ====`, 'test', FNAME_RUNNER);

    const result = await executeTestV31Logic(); // Chama a função de teste v31 (que contém a lógica v32)

    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
    } else if (result.potentiallyCrashed) {
         logS3(`   RESULTADO: CONGELAMENTO POTENCIAL. Detalhes da toJSON (se chamada): ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "critical", FNAME_RUNNER);
    } else {
        logS3(`   RESULTADO: Completou. Detalhes da toJSON: ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "good", FNAME_RUNNER);
    }
    logS3(`   Título da página final: ${document.title}`, "info");

    logS3(`==== Estratégia de Replicação de Type Confusion (v31) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_FOR_ORCHESTRATOR}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Replicando TC de v26 (Teste v31) ====`, 'test', FNAME_ORCHESTRATOR);

    await runReplicateTC_v31_Strategy();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_FOR_ORCHESTRATOR)) {
        if (!document.title.includes("CRASH") && !document.title.includes("PROBLEM") && 
            !document.title.includes("SUCCESS") && !document.title.includes("ERR") && 
            !document.title.includes("TYPE CONFUSION") && !document.title.includes("REPLICATED")) {
            document.title = `${FNAME_MODULE_FOR_ORCHESTRATOR} Concluído`;
        }
    }
}
