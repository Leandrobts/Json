// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeProbeComplexObjectWithMinimalToJSONs,
    toJSON_RangeErrorVariants
} from './testIsolateForInRangeError.mjs';

async function runIsolateV4OnlyStrategy() {
    const FNAME_RUNNER = "runIsolateV4OnlyStrategy_v30";
    logS3(`==== INICIANDO ${FNAME_RUNNER}: Teste Focado APENAS em V4_LoopInWithAccess_Limited ====`, 'test', FNAME_RUNNER);

    const variant_to_test = "V4_LoopInWithAccess_Limited";
    
    if (!toJSON_RangeErrorVariants[variant_to_test]) {
        logS3(`ERRO: Variante toJSON '${variant_to_test}' não encontrada. Abortando.`, "critical", FNAME_RUNNER);
        return;
    }

    const toJSON_function_to_use = toJSON_RangeErrorVariants[variant_to_test];
    logS3(`\n--- EXECUTANDO TESTE FOCO APENAS com toJSON: ${variant_to_test} ---`, "subtest", FNAME_RUNNER);
    document.title = `Test Focus - ${variant_to_test}`;

    logS3(`   [${FNAME_RUNNER}] Preparando para chamar executeProbeComplexObjectWithMinimalToJSONs com ${variant_to_test}...`, "info");
    const result = await executeProbeComplexObjectWithMinimalToJSONs(
        toJSON_function_to_use,
        variant_to_test
    );
    logS3(`   [${FNAME_RUNNER}] Chamada a executeProbeComplexObjectWithMinimalToJSONs com ${variant_to_test} RETORNOU.`, "info");

    if (result && result.error) {
        logS3(`   RESULTADO PARA ${variant_to_test}: Erro ${result.error.name} - ${result.error.message}`, "error", FNAME_RUNNER);
        if (result.error.name === 'RangeError') {
            logS3(`       RangeError confirmado com ${variant_to_test}.`, "vuln", FNAME_RUNNER);
            document.title = `RangeError w/ ${variant_to_test}!`;
        } else {
             document.title = `Error w/ ${variant_to_test}!`;
        }
    } else if (result && result.stringifyResult && result.stringifyResult.error_during_loop) {
        logS3(`   RESULTADO PARA ${variant_to_test}: Erro DENTRO do loop da toJSON: ${result.stringifyResult.error_during_loop}`, "error", FNAME_RUNNER);
         if (String(result.stringifyResult.error_during_loop).toLowerCase().includes('call stack')) {
             logS3(`       RangeError (interno) confirmado com ${variant_to_test}.`, "vuln", FNAME_RUNNER);
             document.title = `RangeError (internal) w/ ${variant_to_test}!`;
         }
    } else {
        logS3(`   RESULTADO PARA ${variant_to_test}: Completou sem erro explícito no stringify.`, "good", FNAME_RUNNER);
    }
    logS3(`       Detalhes da toJSON para ${variant_to_test}: ${result.stringifyResult ? JSON.stringify(result.stringifyResult) : 'N/A'}`, "info", FNAME_RUNNER);

    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`==== ${FNAME_RUNNER} CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_FocusV4_v30';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME);
    logS3(`==== INICIANDO Script 3: ${FNAME} ====`, 'test', FNAME);
    document.title = `S3 - ${FNAME}`;

    await runIsolateV4OnlyStrategy(); // Chama a estratégia focada

    logS3(`\n==== Script 3 CONCLUÍDO (${FNAME}) ====`, 'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (document.title.includes("ERRO") || document.title.includes("FAIL") || document.title.includes("RangeError")) {
    } else if (!document.title.startsWith("S3 -")) {
        document.title = "S3 Concluído";
    }
}
