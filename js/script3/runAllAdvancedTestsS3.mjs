// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs'; 
import {
    executeProbeComplexObjectWithMinimalToJSONs,
    toJSON_RangeErrorVariants // Importa o objeto com as variantes
} from './testInvestigatePropertyAccessInRangeError.mjs'; // ATUALIZE O NOME DO ARQUIVO SE VOCÊ SALVOU DIFERENTE

async function runIsolateRangeErrorStrategy() {
    const FNAME_RUNNER = "runIsolateRangeErrorStrategy_v21";
    logS3(`==== INICIANDO ${FNAME_RUNNER}: Investigação Detalhada do RangeError com MyComplexObject ====`, 'test', FNAME_RUNNER);

    for (const variant_name of Object.keys(toJSON_RangeErrorVariants)) {
        const toJSON_function_to_use = toJSON_RangeErrorVariants[variant_name];
        await PAUSE_S3(1000); // Pausa mais longa entre sub-testes para estabilidade

        const result = await executeProbeComplexObjectWithMinimalToJSONs(
            toJSON_function_to_use,
            variant_name
        );

        if (result && result.error) {
            logS3(`   RESULTADO PARA ${variant_name}: Erro ${result.error.name} - ${result.error.message}`, "error", FNAME_RUNNER);
            if (result.error.name === 'RangeError') {
                logS3(`       RangeError confirmado com ${variant_name}. Esta pode ser a causa da recursão.`, "vuln", FNAME_RUNNER);
                document.title = `RangeError w/ ${variant_name}!`;
                // Decidir se quer parar após o primeiro RangeError
                // logS3("RangeError encontrado, interrompendo mais variantes para análise.", "warn", FNAME_RUNNER);
                // break;
            }
        } else {
            logS3(`   RESULTADO PARA ${variant_name}: Completou sem erro explícito.`, "good", FNAME_RUNNER);
        }
    }

    logS3(`==== ${FNAME_RUNNER} CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_IsolateRangeError_v21';
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
         // Manter título se indicar problema
    } else if (!document.title.startsWith("S3 -")) {
        document.title = "S3 Concluído";
    }
}
