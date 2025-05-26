// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeVictimABInstabilityTest,
    toJSON_AB_Probe_V1,
    toJSON_AB_Probe_V2_Detailed, // Nova versão detalhada
    toJSON_AB_Probe_V3
} from './testVictimABInstability.mjs';

async function runVictimABInstabilityInvestigation_Detailed() {
    const FNAME_RUNNER = "runVictimABInstabilityInvestigation_Detailed";
    logS3(`==== INICIANDO Investigação DETALHADA de Instabilidade em victim_ab (ArrayBuffer) ====`, 'test', FNAME_RUNNER);

    const toJSON_variants_to_test = [
        { name: "toJSON_AB_Probe_V1", func: toJSON_AB_Probe_V1 },
        { name: "toJSON_AB_Probe_V2_Detailed", func: toJSON_AB_Probe_V2_Detailed }, // Teste chave
        { name: "toJSON_AB_Probe_V3", func: toJSON_AB_Probe_V3 }, // Para ver se também mostra TypeConfusion
    ];

    for (const variant of toJSON_variants_to_test) {
        logS3(`\nExecutando sub-teste com toJSON: ${variant.name} (alvo: victim_ab)`, "info", FNAME_RUNNER);
        const result = await executeVictimABInstabilityTest(variant.func, variant.name);

        if (result && result.setupError) {
            logS3(`   Falha na configuração do teste para ${variant.name}: ${result.setupError.message}. Abortando mais variantes.`, "error", FNAME_RUNNER);
            break;
        }

        let problemFoundInVariant = false;
        if (result && result.stringifyError) {
            problemFoundInVariant = true;
        } else if (result && result.toJSONReturn && result.toJSONReturn.error) {
             problemFoundInVariant = true;
        } else if (result && result.toJSONReturn && result.toJSONReturn.toJSON_variant === "toJSON_AB_Probe_V1") {
            if (!result.toJSONReturn.is_array_buffer_instance_entry || !result.toJSONReturn.dv_rw_match) {
                problemFoundInVariant = true;
            }
        } else if (result && result.toJSONReturn && result.toJSONReturn.toJSON_variant === "toJSON_AB_Probe_V2_Detailed") {
            if (String(result.toJSONReturn.error).toLowerCase().includes("type confusion") ||
                (result.toJSONReturn.is_array_buffer_instance_entry &&
                 (result.toJSONReturn.this_type_in_loop !== "[object ArrayBuffer]" && result.toJSONReturn.this_type_in_loop !== "N/A") )) {
                problemFoundInVariant = true;
            }
        }


        if (problemFoundInVariant) {
            logS3(`   PROBLEMA DETECTADO com ${variant.name}. Verifique logs detalhados do sub-teste.`, "critical", FNAME_RUNNER);
            // Se um problema sério como Type Confusion ou RangeError for detectado, parar.
            if (document.title.includes("TypeConfusion") || document.title.includes("RangeError") || document.title.includes("CRASH")) {
                 logS3("Problema crítico detectado, interrompendo a sequência de variantes toJSON.", "warn", FNAME_RUNNER);
                break;
            }
        } else {
            logS3(`   Sub-teste com ${variant.name} para victim_ab completou sem problemas óbvios.`, "good", FNAME_RUNNER);
        }
        await PAUSE_S3(MEDIUM_PAUSE_S3);
    }
    logS3(`==== Investigação DETALHADA de Instabilidade em victim_ab CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_VictimABInstability_Detailed';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Investigação DETALHADA de Instabilidade em victim_ab Pós-Corrupção ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - Detalhe victim_ab";

    await runVictimABInstabilityInvestigation_Detailed();

    logS3(`\n==== Script 3 CONCLUÍDO (Investigação Detalhada victim_ab) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes("CONGELOU?")) {
        // Manter
    } else if (document.title.includes("RangeError") || document.title.includes("ERRO") || document.title.includes("CRASH") || document.title.includes("TypeConfusion") || document.title.includes("alterado")) {
        // Manter títulos que indicam resultados específicos
    }
    else {
        document.title = "Script 3 Concluído - Detalhe victim_ab";
    }
}
