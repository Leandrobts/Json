// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { sprayAndInvestigateObjectExposure } from './testRetypeOOB_AB_ViaShadowCraft.mjs';

async function runSprayAndCorruptStrategy_v9_wrapper() { // Nome da função wrapper atualizado
    const FNAME_RUNNER = "runSprayAndCorruptStrategy_v9_wrapper";
    logS3(`==== INICIANDO Estratégia Wrapper: ${FNAME_RUNNER} ====`, 'test', FNAME_RUNNER);
    // sprayAndInvestigateObjectExposure é a função exportada que contém a lógica v9.
    await sprayAndInvestigateObjectExposure();
    logS3(`==== Estratégia Wrapper ${FNAME_RUNNER} CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_SprayCorrupt_v9_Main'; // Atualizado para v9
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== User Agent: ${navigator.userAgent} ====`,'info', FNAME);
    logS3(`==== INICIANDO Script 3: Corrupção de ABView e Leitura Absoluta (lógica v9) ====`,'test', FNAME);
    document.title = `Iniciando Script 3 - Corrupt & Read v9`;

    await runSprayAndCorruptStrategy_v9_wrapper(); // Chama a estratégia atualizada
    
    logS3(`\n==== Script 3 CONCLUÍDO (lógica v9) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    // A lógica de atualização do título já está dentro de sprayAndInvestigateObjectExposure
    // e será refletida. Podemos adicionar uma genérica aqui se nenhum dos casos específicos for atingido.
    if (!document.title.includes("SUPER_ARRAY") && !document.title.includes("SuperArray") && !document.title.includes("FALHOU")) {
        document.title = "Script 3 v9 Concluído (Estado Desconhecido)";
    }
}
