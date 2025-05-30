// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { executeInvestigatePropertyAccessInRangeError } from './testInvestigatePropertyAccessInRangeError.mjs';

async function runInvestigateForInRangeErrorStrategy() {
    const FNAME_RUNNER = "runInvestigateForInRangeErrorStrategy_v22";
    logS3(`==== INICIANDO ${FNAME_RUNNER}: Investigar Acesso de Propriedade no RangeError ====`, 'test', FNAME_RUNNER);

    const result = await executeInvestigatePropertyAccessInRangeError();

    if (result && result.error) {
        logS3(`   RESULTADO DO TESTE: Erro ${result.error.name} - ${result.error.message}`, "error", FNAME_RUNNER);
        if (result.error.name === 'RangeError') {
            logS3(`       RangeError confirmado. Última propriedade tentada na toJSON: ${result.stringifyResult?.last_prop_attempted}`, "vuln", FNAME_RUNNER);
        }
    } else {
        logS3(`   RESULTADO DO TESTE: Completou sem erro explícito no stringify.`, "good", FNAME_RUNNER);
    }
    logS3(`       Detalhes da toJSON: ${JSON.stringify(result.stringifyResult)}`, "info", FNAME_RUNNER);
    logS3(`==== ${FNAME_RUNNER} CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_InvestigatePropAccessInRERR_v22';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME);
    logS3(`==== INICIANDO Script 3: ${FNAME} ====`, 'test', FNAME);
    document.title = `S3 - ${FNAME}`;

    await runInvestigateForInRangeErrorStrategy();

    logS3(`\n==== Script 3 CONCLUÍDO (${FNAME}) ====`, 'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (document.title.includes("ERRO") || document.title.includes("FAIL") || document.title.includes("RangeError")) {
         // Manter título se indicar problema
    } else if (!document.title.startsWith("S3 -")) {
        document.title = "S3 Concluído";
    }
}
