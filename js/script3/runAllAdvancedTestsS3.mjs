// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a função de teste principal e as novas toJSONs
import {
    executeVictimABInstabilityTest,
    toJSON_AB_Probe_V1,
    toJSON_AB_Probe_V2,
    toJSON_AB_Probe_V3
} from './testVictimABInstability.mjs'; // Nome do arquivo atualizado

async function runVictimABInstabilityInvestigation() {
    const FNAME_RUNNER = "runVictimABInstabilityInvestigation";
    logS3(`==== INICIANDO Investigação de Instabilidade em victim_ab (ArrayBuffer) ====`, 'test', FNAME_RUNNER);

    const toJSON_variants_to_test = [
        { name: "toJSON_AB_Probe_V1", func: toJSON_AB_Probe_V1 },
        { name: "toJSON_AB_Probe_V2", func: toJSON_AB_Probe_V2 },
        { name: "toJSON_AB_Probe_V3", func: toJSON_AB_Probe_V3 },
    ];

    for (const variant of toJSON_variants_to_test) {
        logS3(`\nExecutando sub-teste com toJSON: ${variant.name} (alvo: victim_ab)`, "info", FNAME_RUNNER);
        const result = await executeVictimABInstabilityTest(variant.func, variant.name);

        if (result && result.setupError) {
            logS3(`   Falha na configuração do teste para ${variant.name}: ${result.setupError.message}. Abortando mais variantes.`, "error", FNAME_RUNNER);
            break;
        }

        let problemSummary = "Nenhum problema óbvio.";
        if (result && result.stringifyError) {
            problemSummary = `Erro no stringify: ${result.stringifyError.name} - ${result.stringifyError.message}`;
        } else if (result && result.toJSONReturn && result.toJSONReturn.error) {
            problemSummary = `Erro interno na toJSON: ${result.toJSONReturn.error}`;
        } else if (result && result.toJSONReturn && result.toJSONReturn.toJSON_variant === "toJSON_AB_Probe_V1") {
            if (!result.toJSONReturn.is_array_buffer_instance || result.toJSONReturn.byteLength_prop !== 64 || !result.toJSONReturn.dv_rw_match) {
                problemSummary = `Falha na V1: isAB=${result.toJSONReturn.is_array_buffer_instance}, len=${result.toJSONReturn.byteLength_prop}, rwMatch=${result.toJSONReturn.dv_rw_match}`;
            }
        }
        // Adicionar mais checagens específicas para V2 e V3 se necessário

        if (result && result.stringifyError && result.stringifyError.name === 'RangeError') {
            logS3(`   !!!!!! RangeError OCORREU com ${variant.name} para victim_ab !!!!!!`, "critical", FNAME_RUNNER);
            document.title = `RangeError with ${variant.name} on victim_ab!`;
            // break; // Descomente para parar no primeiro RangeError
        } else if (result && result.stringifyError) {
            logS3(`   Erro (${result.stringifyError.name}) ocorreu com ${variant.name} para victim_ab.`, "error", FNAME_RUNNER);
        } else {
            logS3(`   Sub-teste com ${variant.name} para victim_ab completou. Sumário: ${problemSummary}`, (problemSummary === "Nenhum problema óbvio." ? "good" : "warn"), FNAME_RUNNER);
        }

        await PAUSE_S3(MEDIUM_PAUSE_S3);
        if (document.title.includes("RangeError") || document.title.includes("CRASH")) break;
    }

    logS3(`==== Investigação de Instabilidade em victim_ab CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_VictimABInstability';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Investigação de Instabilidade em victim_ab (ArrayBuffer) Pós-Corrupção ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - Investiga victim_ab Instability";

    await runVictimABInstabilityInvestigation();

    logS3(`\n==== Script 3 CONCLUÍDO (Investigação victim_ab Instability) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes("CONGELOU?")) {
        // Manter
    } else if (document.title.includes("RangeError") || document.title.includes("ERRO") || document.title.includes("CRASH") || document.title.includes("alterado")) {
        // Manter títulos que indicam resultados específicos
    }
    else {
        document.title = "Script 3 Concluído - Investiga victim_ab Instability";
    }
}
