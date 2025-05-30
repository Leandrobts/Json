// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs'; // MEDIUM_PAUSE_S3 ainda pode ser usado no final.
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeProbeComplexObjectWithMinimalToJSONs,
    toJSON_RangeErrorVariants
} from './testIsolateForInRangeError.mjs';

async function runIsolateV4CrashStrategy() {
    const FNAME_RUNNER = "runIsolateV4CrashStrategy_v27_NoIntermediatePause";
    logS3(`==== INICIANDO ${FNAME_RUNNER}: Isolando Ponto de Travamento (Sem Pausa Intermediária) ====`, 'test', FNAME_RUNNER);

    const variants_to_test_specifically = [
        "V4_Dummy", // Testar a definição de uma função toJSON simples primeiro
        "V4_LoopInWithAccess_Limited"
    ];
    
    // Testar V0_EmptyReturn antes como linha de base estável
    logS3(`\n--- EXECUTANDO SUB-TESTE LINHA DE BASE com toJSON: V0_EmptyReturn ---`, "subtest", FNAME_RUNNER);
    document.title = `RangeError Test - V0_EmptyReturn`;
    await executeProbeComplexObjectWithMinimalToJSONs(
        toJSON_RangeErrorVariants["V0_EmptyReturn"],
        "V0_EmptyReturn"
    );
    // await PAUSE_S3(MEDIUM_PAUSE_S3); // <<<<<<< PAUSA REMOVIDA AQUI >>>>>>>>>


    for (const variant_name of variants_to_test_specifically) {
        if (!toJSON_RangeErrorVariants[variant_name]) {
            logS3(`AVISO: Variante toJSON '${variant_name}' não encontrada. Pulando.`, "warn", FNAME_RUNNER);
            continue;
        }
        const toJSON_function_to_use = toJSON_RangeErrorVariants[variant_name];
        logS3(`\n--- EXECUTANDO SUB-TESTE FOCO com toJSON: ${variant_name} ---`, "subtest", FNAME_RUNNER);
        document.title = `RangeError Test Focus - ${variant_name}`;

        // Adicionar um log antes de chamar executeProbeComplexObjectWithMinimalToJSONs para o V4
        logS3(`   [${FNAME_RUNNER}] Preparando para chamar executeProbeComplexObjectWithMinimalToJSONs com ${variant_name}...`, "info");

        const result = await executeProbeComplexObjectWithMinimalToJSONs(
            toJSON_function_to_use,
            variant_name
        );

        logS3(`   [${FNAME_RUNNER}] Chamada a executeProbeComplexObjectWithMinimalToJSONs com ${variant_name} RETORNOU.`, "info");


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

        await PAUSE_S3(SHORT_PAUSE_S3); // Pausa curta entre os testes V4_Dummy e V4_LoopInWithAccess_Limited
        if (document.title.includes("RangeError")) {
            logS3(`RangeError ocorreu com ${variant_name}.`, "warn", FNAME_RUNNER);
        }
    }

    logS3(`==== ${FNAME_RUNNER} CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_IsolateV4Crash_v27_NoIntermediatePause';
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
