// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs'; // SHORT_PAUSE_S3 não é usado diretamente aqui
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a função de teste atualizada do arquivo correto
import { sprayAndAttemptSuperArray_v31 } from './testRetypeOOB_AB_ViaShadowCraft.mjs';

async function runBackToSuperArrayStrategy() {
    const FNAME_RUNNER = "runBackToSuperArrayStrategy_v31";
    logS3(`==== INICIANDO ${FNAME_RUNNER}: Tentativa Básica de Super Array ====`, 'test', FNAME_RUNNER);
    await sprayAndAttemptSuperArray_v31();
    logS3(`==== ${FNAME_RUNNER} CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_SuperArrayBasic_v31';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME);
    logS3(`==== INICIANDO Script 3: ${FNAME} ====`, 'test', FNAME);
    document.title = `S3 - ${FNAME}`;

    await runBackToSuperArrayStrategy();

    logS3(`\n==== Script 3 CONCLUÍDO (${FNAME}) ====`, 'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (document.title.includes("ERRO") || document.title.includes("FAIL") || document.title.includes("Não Encontrado")) {
        // Manter título se indicar problema ou não sucesso
    } else if (document.title.includes("Encontrado")) {
        // Manter título de sucesso
    }
    else if (!document.title.startsWith("S3 -")) {
        document.title = "S3 Concluído";
    }
}
