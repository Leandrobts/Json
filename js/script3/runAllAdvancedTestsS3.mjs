// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a nova função de teste
import { executeRetypeOOB_AB_Test } from './testRetypeOOB_AB_ViaShadowCraft.mjs'; // ATUALIZADO AQUI

async function runRetypeOOB_AB_Strategy() { // ATUALIZADO AQUI
    const FNAME_RUNNER = "runRetypeOOB_AB_Strategy"; // ATUALIZADO AQUI
    logS3(`==== INICIANDO Estratégia de "Re-Tipagem" do oob_array_buffer_real ====`, 'test', FNAME_RUNNER); // ATUALIZADO AQUI

    await executeRetypeOOB_AB_Test(); // ATUALIZADO AQUI

    logS3(`==== Estratégia de "Re-Tipagem" do oob_array_buffer_real CONCLUÍDA ====`, 'test', FNAME_RUNNER); // ATUALIZADO AQUI
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_RetypeOOB_AB'; // ATUALIZADO AQUI
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Tentativa de "Re-Tipar" oob_array_buffer_real ====`,'test', FNAME); // ATUALIZADO AQUI
    document.title = "Iniciando Script 3 - Retype OOB_AB"; // ATUALIZADO AQUI

    await runRetypeOOB_AB_Strategy(); // ATUALIZADO AQUI

    logS3(`\n==== Script 3 CONCLUÍDO (Retype OOB_AB) ====`,'test', FNAME); // ATUALIZADO AQUI
    if (runBtn) runBtn.disabled = false;

    if (!document.title.includes("SUCCESS")) {
         document.title = "Script 3 Concluído - Retype OOB_AB"; // ATUALIZADO AQUI
    }
}
