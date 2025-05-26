// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeInvestigateForInRCETest,
    toJSON_ForIn_V0_LoopOnly,
    toJSON_ForIn_V1_LoopAndHasOwnProperty,
    toJSON_ForIn_V2_LoopAndAccess,
    toJSON_ForIn_V3_LoopAccessAndString,
    toJSON_ForIn_V5_AssignToLocalVar, // Nova variante
    toJSON_ForIn_V4_OriginalAttempt   // A que causava erro
} from './testInvestigateForInRCE.mjs';

async function runForInRCEInvestigationStrategy() {
    const FNAME_RUNNER = "runForInRCEInvestigationStrategy";
    logS3(`==== INICIANDO Estratégia de Investigação do RangeError com for...in (v2) ====`, 'test', FNAME_RUNNER);

    const toJSON_variants_to_test = [
        { name: "toJSON_ForIn_V0_LoopOnly", func: toJSON_ForIn_V0_LoopOnly },
        { name: "toJSON_ForIn_V1_LoopAndHasOwnProperty", func: toJSON_ForIn_V1_LoopAndHasOwnProperty },
        { name: "toJSON_ForIn_V2_LoopAndAccess", func: toJSON_ForIn_V2_LoopAndAccess },
        { name: "toJSON_ForIn_V3_LoopAccessAndString", func: toJSON_ForIn_V3_LoopAccessAndString },
        { name: "toJSON_ForIn_V5_AssignToLocalVar", func: toJSON_ForIn_V5_AssignToLocalVar }, // TESTE CHAVE
        { name: "toJSON_ForIn_V4_OriginalAttempt", func: toJSON_ForIn_V4_OriginalAttempt },   // RECONFIRMAÇÃO DO ERRO
    ];

    for (const variant of toJSON_variants_to_test) {
        logS3(`\nExecutando sub-teste com toJSON: ${variant.name}`, "info", FNAME_RUNNER);
        const result = await executeInvestigateForInRCETest(variant.func, variant.name);

        if (result && result.setupError) {
            logS3(`   Falha na configuração do teste para ${variant.name}: ${result.setupError.message}. Abortando mais variantes.`, "error", FNAME_RUNNER);
            break;
        }
        if (result && result.stringifyError && result.stringifyError.name === 'RangeError') {
            logS3(`   !!!!!! RangeError OCORREU com ${variant.name} no objeto ${result.targetObjectId} !!!!!!`, "critical", FNAME_RUNNER);
            document.title = `RangeError with ${variant.name}!`;
            // Decida se quer parar no primeiro RangeError para focar nele. Por ora, continua.
            // break;
        } else if (result && result.stringifyError) {
            logS3(`   Outro erro (${result.stringifyError.name}) ocorreu com ${variant.name} no objeto ${result.targetObjectId}.`, "error", FNAME_RUNNER);
        } else {
            logS3(`   Sub-teste com ${variant.name} completou sem erro de stringify no objeto ${result.targetObjectId}.`, "good", FNAME_RUNNER);
        }
        await PAUSE_S3(MEDIUM_PAUSE_S3);
        // Parar se um RangeError for encontrado para facilitar a análise desse caso específico.
        if (document.title.includes("RangeError") || document.title.includes("CRASH")) {
             logS3("RangeError ou Crash detectado, interrompendo a sequência de variantes toJSON.", "warn", FNAME_RUNNER);
            break;
        }
    }

    logS3(`==== Estratégia de Investigação do RangeError com for...in (v2) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_InvestigateForInRCE_v2';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Investigação do RangeError com for...in (v2) Pós-Corrupção ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - Investiga ForIn RCE v2";

    await runForInRCEInvestigationStrategy();

    logS3(`\n==== Script 3 CONCLUÍDO (Investigação ForIn RCE v2) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes("CONGELOU?")) {
        // Manter
    } else if (document.title.includes("RangeError") || document.title.includes("ERRO") || document.title.includes("CRASH")) {
        // Manter títulos que indicam resultados específicos
    }
    else {
        document.title = "Script 3 Concluído - Investiga ForIn RCE v2";
    }
}
