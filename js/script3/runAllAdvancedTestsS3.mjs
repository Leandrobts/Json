// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a nova função de teste
import { sprayAndInvestigateObjectExposure } from './testRetypeOOB_AB_ViaShadowCraft.mjs'; // Assumindo que a função exportada ainda se chama assim

export async function runAllAdvancedTestsS3() {
    const FNAME = FNAME_MAIN; // Usará o FNAME_MAIN do módulo importado
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: ${FNAME} ====`, 'test', FNAME);
    document.title = `Iniciando Script 3 - ${FNAME}`;
    
    // A função sprayAndInvestigateObjectExposure agora contém a lógica de ExploitLogic_v23_RevisitOriginalCrash
    await sprayAndInvestigateObjectExposure(); 
    
    logS3(`\n==== Script 3 CONCLUÍDO (${FNAME}) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;
    
    // A lógica de atualização do título já está no finally da função de teste principal
}
