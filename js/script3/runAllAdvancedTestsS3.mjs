// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeProbeComplexObjectWithMinimalToJSONs,
    toJSON_RangeErrorVariants
} from './testIsolateForInRangeError.mjs';

async function runIsolateV4CrashStrategy() {
    const FNAME_RUNNER = "runIsolateV4CrashStrategy_v29_NoLoopPause";
    logS3(`==== INICIANDO ${FNAME_RUNNER}: Isolando Ponto de Travamento/RangeError (Sem Pausa no Loop) ====`, 'test', FNAME_RUNNER);

    const variants_to_test_in_order = [
        "V0_EmptyReturn",
        "V1_AccessThisId",
        "V2_ToStringCallThis",
        "V3_LoopInEmpty_Limited",
        "V4_Dummy",
        "V4_LoopInWithAccess_Limited", // O principal suspeito do RangeError
        "V5_ObjectKeysThenAccess_Limited"
    ];
    
    let criticalErrorOccurred = false;

    for (const variant_name of variants_to_test_in_order) {
        if (criticalErrorOccurred && (variant_name === "V4_LoopInWithAccess_Limited" || variant_name === "V5_ObjectKeysThenAccess_Limited")) {
            logS3(`\n--- PULANDO SUB-TESTE com toJSON: ${variant_name} devido a erro crítico anterior ---`, "warn", FNAME_RUNNER);
            continue;
        }

        if (!toJSON_RangeErrorVariants[variant_name]) {
            logS3(`AVISO: Variante toJSON '${variant_name}' não encontrada. Pulando.`, "warn", FNAME_RUNNER);
            continue;
        }
        const toJSON_function_to_use = toJSON_RangeErrorVariants[variant_name];
        logS3(`\n--- EXECUTANDO SUB-TESTE com toJSON: ${variant_name} ---`, "subtest", FNAME_RUNNER);
        document.title = `Test - ${variant_name}`;

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
                criticalErrorOccurred = true; 
            } else {
                 document.title = `Error w/ ${variant_name}!`;
            }
        } else if (result && result.stringifyResult && result.stringifyResult.error_during_loop) {
            logS3(`   RESULTADO PARA ${variant_name}: Erro DENTRO do loop da toJSON: ${result.stringifyResult.error_during_loop}`, "error", FNAME_RUNNER);
             if (String(result.stringifyResult.error_during_loop).toLowerCase().includes('call stack')) {
                 logS3(`       RangeError (interno) confirmado com ${variant_name}.`, "vuln", FNAME_RUNNER);
                 document.title = `RangeError (internal) w/ ${variant_name}!`;
                 criticalErrorOccurred = true;
             }
        } else {
            logS3(`   RESULTADO PARA ${variant_name}: Completou sem erro explícito no stringify.`, "good", FNAME_RUNNER);
        }
        logS3(`       Detalhes da toJSON para ${variant_name}: ${result.stringifyResult ? JSON.stringify(result.stringifyResult) : 'N/A'}`, "info", FNAME_RUNNER);

        // await PAUSE_S3(SHORT_PAUSE_S3); // <<<<<<< PAUSA REMOVIDA DENTRO DO LOOP >>>>>>>>>
                                        // Uma pausa maior será feita após o loop.
        if (criticalErrorOccurred && (variant_name === "V4_LoopInWithAccess_Limited" || variant_name === "V5_ObjectKeysThenAccess_Limited")) {
            logS3(`RangeError detectado com variante de loop (${variant_name}). Verifique os logs.`, "warn", FNAME_RUNNER);
        }
    }
    await PAUSE_S3(MEDIUM_PAUSE_S3); // Pausa no final do loop de todas as variantes
    logS3(`==== ${FNAME_RUNNER} CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_IsolateRangeError_v29_NoLoopPause';
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
