// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeProbeComplexObjectWithMinimalToJSONs,
    toJSON_RangeErrorVariants
} from './testIsolateForInRangeError.mjs';

async function runIsolateV4CrashStrategy() {
    const FNAME_RUNNER = "runIsolateV4CrashStrategy_v26";
    logS3(`==== INICIANDO ${FNAME_RUNNER}: Isolando Ponto de Travamento com V4_LoopInWithAccess_Limited ====`, 'test', FNAME_RUNNER);

    const variants_to_test_specifically = [
        "V4_LoopInWithAccess_Limited",
        "V4_Dummy" // Para ver se a definição de uma função complexa vs simples importa
    ];
    
    // Testar V0_EmptyReturn antes como linha de base estável
    logS3(`\n--- EXECUTANDO SUB-TESTE LINHA DE BASE com toJSON: V0_EmptyReturn ---`, "subtest", FNAME_RUNNER);
    document.title = `RangeError Test - V0_EmptyReturn`;
    await executeProbeComplexObjectWithMinimalToJSONs(
        toJSON_RangeErrorVariants["V0_EmptyReturn"],
        "V0_EmptyReturn"
    );
    await PAUSE_S3(MEDIUM_PAUSE_S3);


    for (const variant_name of variants_to_test_specifically) {
        if (!toJSON_RangeErrorVariants[variant_name]) {
            logS3(`AVISO: Variante toJSON '${variant_name}' não encontrada. Pulando.`, "warn", FNAME_RUNNER);
            continue;
        }
        const toJSON_function_to_use = toJSON_RangeErrorVariants[variant_name];
        logS3(`\n--- EXECUTANDO SUB-TESTE FOCO com toJSON: ${variant_name} ---`, "subtest", FNAME_RUNNER);
        document.title = `RangeError Test Focus - ${variant_name}`;

        const result = await executeProbeComplexObjectWithMinimalToJSONs(
            toJSON_function_to_use,
            variant_name
        );

        if (result && result.error) {
            logS3(`   RESULTADO PARA ${variant_name}: Erro ${result.error.name} - ${result.error.message}`, "error", FNAME_RUNNER);
            if (result.error.name === 'RangeError') {
                logS3(`       RangeError confirmado com ${variant_name}.`, "vuln", FNAME_RUNNER);
                document.title = `RangeError w/ ${variant_name}!`;
            }
        } else if (result && result.stringifyResult && result.stringifyResult.error_during_loop) {
            logS3(`   RESULTADO PARA ${variant_name}: Erro DENTRO do loop da toJSON: ${result.stringifyResult.error_during_loop}`, "error", FNAME_RUNNER);
             if (String(result.stringifyResult.error_during_loop).toLowerCase().includes('call stack')) {
                 logS3(`       RangeError (interno) confirmado com ${variant_name}.`, "vuln", FNAME_RUNNER);
                 document.title = `RangeError (internal) w/ ${variant_name}!`;
             }
        } else {
            logS3(`   RESULTADO PARA ${variant_name}: Completou sem erro explícito no stringify.`, "good", FNAME_RUNNER);
        }
        logS3(`       Detalhes da toJSON para ${variant_name}: ${result.stringifyResult ? JSON.stringify(result.stringifyResult) : 'N/A'}`, "info", FNAME_RUNNER);

        await PAUSE_S3(MEDIUM_PAUSE_S3); // Pausa mais longa para permitir observação/recuperação do navegador
        if (document.title.includes("RangeError")) {
            logS3(`RangeError ocorreu com ${variant_name}. Verifique os logs para a última propriedade acessada se V4_LoopInWithAccess_Limited.`, "warn", FNAME_RUNNER);
            // Não vamos parar, mas pode ser útil parar aqui em testes manuais.
        }
    }

    logS3(`==== ${FNAME_RUNNER} CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_IsolateV4Crash_v26';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME);
    logS3(`==== INICIANDO Script 3: ${FNAME} ====`, 'test', FNAME);
    document.title = `S3 - ${FNAME}`;

    await runIsolateV4CrashStrategy();

    logS3(`\n==== Script 3 CONCLUÍDO (${FNAME}) ====`, 'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (document.title.includes("ERRO") || document.title.includes("FAIL") || document.title.includes("RangeError")) {
    } else if (!document.title.startsWith("S3 -")) {
        document.title = "S3 Concluído";
    }
}
