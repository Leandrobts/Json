// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a nova função de teste
import { executeForInPropertyAccessRETest } from './testForInPropertyAccessRE.mjs'; // Mudamos o nome da função principal no arquivo importado

async function runForInPropertyAccessREDetailedStrategy() { // Nome da estratégia atualizado
    const FNAME_RUNNER = "runForInPropertyAccessREDetailedStrategy";
    logS3(`==== INICIANDO Estratégia de Acesso a Propriedade em 'for...in' (RangeError Check - Log Detalhado) ====`, 'test', FNAME_RUNNER);

    await executeForInPropertyAccessRETest(); // Chama a função com o novo nome

    logS3(`==== Estratégia de Acesso a Propriedade em 'for...in' (RangeError Check - Log Detalhado) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_ForInPropertyAccessREDetailed'; // Nome do teste principal atualizado
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Acesso a Propriedade em 'for...in' Pós-Corrupção (RangeError Check - Log Detalhado) ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - ForIn PropAccess (RE Detailed)";

    await runForInPropertyAccessREDetailedStrategy(); // Chama a estratégia atualizada

    logS3(`\n==== Script 3 CONCLUÍDO (ForIn PropAccess RE Detailed) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes("CONGELOU?")) {
        // Manter
    } else if (document.title.includes("RangeError") || document.title.includes("REPRODUCED") || document.title.includes("ERRO")) {
        // Manter títulos que indicam resultados específicos
    }
    else {
        document.title = "Script 3 Concluído - ForIn PropAccess (RE Detailed)";
    }
}
