// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeMinimalTCReplicationTest_v32, // Corrigido nome da função importada se necessário
    FNAME_MODULE_V32 // CORREÇÃO: Importar FNAME_MODULE_V32
} from './testMinimalTCReplication.mjs'; 
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs'; 
import { toHex } from '../utils.mjs';

async function runReplicateTC_Strategy() { // Nome da função pode ser genérico
    const FNAME_RUNNER = `runReplicateTC_Strategy_Using_${FNAME_MODULE_V32}`;
    logS3(`==== INICIANDO Estratégia de Replicação de Type Confusion (Baseada em v26/v32) ====`, 'test', FNAME_RUNNER);

    const result = await executeMinimalTCReplicationTest_v32(); // Chamando a função correta

    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
    } else if (result.potentiallyCrashed) {
         logS3(`   RESULTADO: CONGELAMENTO POTENCIAL. Detalhes da toJSON (se chamada): ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "critical", FNAME_RUNNER);
    } else {
        logS3(`   RESULTADO: Completou. Detalhes da toJSON: ${result.toJSON_details ? JSON.stringify(result.toJSON_details) : 'N/A'}`, "good", FNAME_RUNNER);
    }
    logS3(`   Título da página final: ${document.title}`, "info");

    logS3(`==== Estratégia de Replicação de Type Confusion CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_V32}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Replicando TC (Teste ${FNAME_MODULE_V32}) ====`, 'test', FNAME_ORCHESTRATOR);

    await runReplicateTC_Strategy();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    // Ajustar a lógica do título final
    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_V32)) {
        if (!document.title.includes("CRASH") && !document.title.includes("REPLICATED") && !document.title.includes("ERR")) {
            document.title = `${FNAME_MODULE_V32} Concluído`;
        }
    }
}
