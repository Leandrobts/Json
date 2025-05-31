// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeArrayBufferVictimCrashTest, // Importa a nova função de teste
    FNAME_MODULE_V28 // Importa o nome do módulo para logging
} from './testArrayBufferVictimCrash.mjs'; // Nome do arquivo atualizado
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs'; 
import { toHex } from '../utils.mjs';

async function runHeisenbugReproStrategy_ABVictim() {
    const FNAME_RUNNER = "runHeisenbugReproStrategy_ABVictim";
    logS3(`==== INICIANDO Estratégia de Reprodução do Heisenbug com ArrayBuffer Vítima ====`, 'test', FNAME_RUNNER);

    const result = await executeArrayBufferVictimCrashTest();

    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
        if (result.errorOccurred.name === 'RangeError') {
            logS3(`     RangeError: Maximum call stack size exceeded OCORREU!`, "vuln", FNAME_RUNNER);
            document.title = `Heisenbug (AB) RangeError!`;
         } else {
            document.title = `Heisenbug (AB) ERR: ${result.errorOccurred.name}`;
         }
    } else if (result.potentiallyCrashed) {
         logS3(`   RESULTADO: CONGELAMENTO POTENCIAL (nenhum erro JS capturado). Detalhes da toJSON (se chamada): ${JSON.stringify(result.toJSON_details)}`, "critical", FNAME_RUNNER);
         if (!document.title.includes("CONGELOU")) document.title = `Heisenbug (AB) CRASH/FREEZE?`;
    } else {
        logS3(`   RESULTADO: Completou. Detalhes da toJSON: ${JSON.stringify(result.toJSON_details)}`, "good", FNAME_RUNNER);
        if (result.toJSON_details && result.toJSON_details.error_in_toJSON) {
            logS3(`     ERRO INTERNO NA toJSON: ${result.toJSON_details.error_in_toJSON}`, "warn", FNAME_RUNNER);
            document.title = `Heisenbug (AB) toJSON_ERR`;
        } else if (result.toJSON_details && result.toJSON_details.probe_called && result.toJSON_details.this_type_in_toJSON !== "[object ArrayBuffer]") {
            logS3(`     !!!! TYPE CONFUSION NO 'victim_ab' DETECTADA DENTRO DA toJSON !!!! Tipo de 'this': ${result.toJSON_details.this_type_in_toJSON}`, "critical", FNAME_RUNNER);
            document.title = `Heisenbug (AB) TYPE CONFUSION!`;
        } else if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_V28) || document.title.includes("Probing")) {
            document.title = `Heisenbug (AB) Test OK`;
        }
    }
    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Reprodução do Heisenbug com ArrayBuffer Vítima CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_V28}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Reproduzindo Heisenbug com ArrayBuffer Vítima ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugReproStrategy_ABVictim();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_V28)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && !document.title.includes("SUCCESS") && !document.title.includes("ERR") && !document.title.includes("TYPE CONFUSION")) {
            document.title = `${FNAME_MODULE_V28} Concluído`;
        }
    }
}
