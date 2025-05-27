// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a nova função de teste
import { executeProbeOOB_AB_SelfTest } from './testProbeOOB_AB_Self.mjs'; // Atualizado

async function runProbeOOB_AB_SelfStrategy() { // Nome da estratégia atualizado
    const FNAME_RUNNER = "runProbeOOB_AB_SelfStrategy";
    logS3(`==== INICIANDO Estratégia de Sondagem do oob_array_buffer_real ====`, 'test', FNAME_RUNNER);

    await executeProbeOOB_AB_SelfTest();

    logS3(`==== Estratégia de Sondagem do oob_array_buffer_real CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_ProbeOOB_AB_Self'; // Nome do teste principal atualizado
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Sondar oob_array_buffer_real Usando Getter como Checkpoint ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - Probe oob_array_buffer_real";

    await runProbeOOB_AB_SelfStrategy(); // Chama a nova estratégia

    logS3(`\n==== Script 3 CONCLUÍDO (Probe oob_array_buffer_real) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    // Ajuste final do título
    if (document.title.startsWith("Iniciando") || document.title.includes("CONGELOU?")) {
        // Manter
    } else if (document.title.includes("SUCCESS") || document.title.includes("ERRO") || document.title.includes("LEAK") || document.title.includes("PROBLEM") || document.title.includes("Called")) {
        // Manter títulos que indicam resultados específicos
    }
    else {
        document.title = "Script 3 Concluído - Probe oob_array_buffer_real";
    }
}
