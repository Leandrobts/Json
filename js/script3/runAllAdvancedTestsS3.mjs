// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeDirectVictimProbeTest,
    FNAME_MODULE 
} from './testVictimABInteractionAfterCorruption.mjs'; 
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs'; 
import { toHex } from '../utils.mjs';

async function runDirectVictimProbingStrategy() {
    const FNAME_RUNNER = "runDirectVictimProbingStrategy";
    logS3(`==== INICIANDO Estratégia de Sondagem Direta em victim_ab Pós-Corrupção ====`, 'test', FNAME_RUNNER);

    // Definir a constante aqui para uso no log de resultados, para corresponder ao que está em testVictimABInteractionAfterCorruption.mjs
    const VICTIM_AB_SIZE_CONST_FOR_LOG = 64; 
    const result = await executeDirectVictimProbeTest();

    if (result.errorOccurred) {
        logS3(`   RESULTADO: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
        document.title = `ERR DirectProbe: ${result.errorOccurred.name}`;
    } else if (result.potentiallyCrashed) {
         logS3(`   RESULTADO: CONGELAMENTO POTENCIAL.`, "error", FNAME_RUNNER);
         if (!document.title.includes("CONGELOU")) document.title = `CRASH? DirectProbe`;
    } else {
        logS3(`   RESULTADO: Completou. victim_ab.byteLength: ${result.victim_byteLength_observed}, DataView Read: ${result.dataview_read_observed}, Slice OK: ${result.slice_ok_observed}`, "good", FNAME_RUNNER);
        // CORREÇÃO: Usar VICTIM_AB_SIZE_CONST_FOR_LOG para a comparação
        if (result.victim_byteLength_observed !== VICTIM_AB_SIZE_CONST_FOR_LOG && typeof result.victim_byteLength_observed === 'number') { 
             logS3(`     !!!! ALTERAÇÃO DE TAMANHO NO VICTIM_AB DETECTADA !!!! Original: ${VICTIM_AB_SIZE_CONST_FOR_LOG}, Novo: ${result.victim_byteLength_observed}`, "critical", FNAME_RUNNER);
             document.title = `DirectProbe: Size Altered!`;
        } else {
            document.title = `DirectProbe OK`;
        }
    }
    logS3(`   Título da página: ${document.title}`, "info");
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`==== Estratégia de Sondagem Direta em victim_ab CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE}_MainOrchestrator_v26_FixRefErr`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Sondagem Direta em victim_ab Pós-Corrupção ====`, 'test', FNAME_ORCHESTRATOR);

    await runDirectVictimProbingStrategy();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE)) {
        if (!document.title.includes("CRASH") && !document.title.includes("PROBLEM") && !document.title.includes("SUCCESS") && !document.title.includes("ERR") && !document.title.includes("Altered")) {
            document.title = `${FNAME_MODULE} (v26_FixRefErr) Concluído`;
        }
    }
}
