// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeObjectKeysHeisenbugTest, // Importa a nova função de teste
    FNAME_MODULE_V27 // Importa o nome do módulo para logging
} from './testRetypeOOB_AB_ViaShadowCraft.mjs'; // O nome do arquivo ainda é este
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs'; 
import { toHex } from '../utils.mjs';

async function runHeisenbugObjectKeysStrategy() {
    const FNAME_RUNNER = "runHeisenbugObjectKeysStrategy";
    logS3(`==== INICIANDO Estratégia de Investigação do Heisenbug com Object.keys() ====`, 'test', FNAME_RUNNER);

    const result = await executeObjectKeysHeisenbugTest();

    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
         if (result.errorOccurred.name === 'RangeError') {
            logS3(`     RangeError: Maximum call stack size exceeded OCORREU! Este é o heisenbug que estávamos procurando.`, "vuln", FNAME_RUNNER);
            document.title = `RangeError HEISENBUG HIT!`;
         } else {
            document.title = `ERR ObjectKeys Test: ${result.errorOccurred.name}`;
         }
    } else if (result.potentiallyCrashed) {
         logS3(`   RESULTADO: CONGELAMENTO POTENCIAL. Últimos detalhes da toJSON: ${JSON.stringify(result.lastToJSONProbeDetails)}`, "error", FNAME_RUNNER);
         if (!document.title.includes("CONGELOU")) document.title = `CRASH? ObjectKeys Test`;
    } else {
        logS3(`   RESULTADO: Completou. Últimos detalhes da toJSON: ${JSON.stringify(result.lastToJSONProbeDetails)}`, "good", FNAME_RUNNER);
        if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_V27) || document.title.includes("Probing")) {
            document.title = `ObjectKeys Test OK`;
        }
    }
    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Investigação do Heisenbug com Object.keys() CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE_V27}_MainOrchestrator`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Investigando Heisenbug com Object.keys() ====`, 'test', FNAME_ORCHESTRATOR);

    await runHeisenbugObjectKeysStrategy();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE_V27)) {
        if (!document.title.includes("CRASH") && !document.title.includes("RangeError") && !document.title.includes("SUCCESS") && !document.title.includes("ERR") && !document.title.includes("HIT")) {
            document.title = `${FNAME_MODULE_V27} Concluído`;
        }
    }
}
