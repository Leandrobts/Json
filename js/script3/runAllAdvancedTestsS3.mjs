// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeProbeComplexObjectWithMinimalToJSONs,
    toJSON_RangeErrorVariants // Importa o objeto com as variantes
} from './testIsolateForInRangeError.mjs'; // Certifique-se que este é o nome do arquivo que você está usando

async function runIsolateRangeErrorStrategy() {
    const FNAME_RUNNER = "runIsolateRangeErrorStrategy_v25_NoPause"; // Nova versão do runner
    logS3(`==== INICIANDO ${FNAME_RUNNER}: Investigação Detalhada do RangeError (Sem Pausa Chave) ====`, 'test', FNAME_RUNNER);

    let foundRangeErrorInV4OrV5 = false;

    for (const variant_name of Object.keys(toJSON_RangeErrorVariants)) {
        const toJSON_function_to_use = toJSON_RangeErrorVariants[variant_name];
        logS3(`\n--- EXECUTANDO SUB-TESTE com toJSON: ${variant_name} ---`, "subtest", FNAME_RUNNER);
        document.title = `RangeError Test - ${variant_name}`;

        const result = await executeProbeComplexObjectWithMinimalToJSONs(
            toJSON_function_to_use,
            variant_name
        );

        if (result && result.error) {
            logS3(`   RESULTADO PARA ${variant_name}: Erro ${result.error.name} - ${result.error.message}`, "error", FNAME_RUNNER);
            if (result.error.name === 'RangeError') {
                logS3(`       RangeError confirmado com ${variant_name}.`, "vuln", FNAME_RUNNER);
                document.title = `RangeError w/ ${variant_name}!`;
                if (variant_name === "V4_LoopInWithAccess_Limited" || variant_name === "V5_ObjectKeysThenAccess_Limited") {
                    foundRangeErrorInV4OrV5 = true;
                }
            }
        } else if (result && result.stringifyResult && result.stringifyResult.error_during_loop) {
            logS3(`   RESULTADO PARA ${variant_name}: Erro DENTRO do loop da toJSON: ${result.stringifyResult.error_during_loop}`, "error", FNAME_RUNNER);
             if (String(result.stringifyResult.error_during_loop).toLowerCase().includes('call stack')) {
                 foundRangeErrorInV4OrV5 = true;
                 logS3(`       RangeError (interno) confirmado com ${variant_name}.`, "vuln", FNAME_RUNNER);
                 document.title = `RangeError (internal) w/ ${variant_name}!`;
             }
        } else {
            logS3(`   RESULTADO PARA ${variant_name}: Completou sem erro explícito no stringify.`, "good", FNAME_RUNNER);
        }
        logS3(`       Detalhes da toJSON para ${variant_name}: ${result.stringifyResult ? JSON.stringify(result.stringifyResult) : 'N/A'}`, "info", FNAME_RUNNER);

        await PAUSE_S3(MEDIUM_PAUSE_S3); 
        if (foundRangeErrorInV4OrV5 && (variant_name === "V4_LoopInWithAccess_Limited" || variant_name === "V5_ObjectKeysThenAccess_Limited")){
             logS3(`RangeError detectado com variante de loop (${variant_name}). Verifique os logs para a última propriedade acessada.`, "warn", FNAME_RUNNER);
        }
    }
    logS3(`==== ${FNAME_RUNNER} CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_IsolateRangeError_v25_NoPause';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME);
    logS3(`==== INICIANDO Script 3: ${FNAME} ====`, 'test', FNAME);
    document.title = `S3 - ${FNAME}`;

    await runIsolateRangeErrorStrategy();

    logS3(`\n==== Script 3 CONCLUÍDO (${FNAME}) ====`, 'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (document.title.includes("ERRO") || document.title.includes("FAIL") || document.title.includes("RangeError")) {
    } else if (!document.title.startsWith("S3 -")) {
        document.title = "S3 Concluído";
    }
}
