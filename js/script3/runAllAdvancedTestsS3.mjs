// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a nova função de teste
import { executePhantomPropertyLeakTest } from './testForInPhantomPropertyLeak.mjs'; // Nome do arquivo atualizado

async function runPhantomPropertyLeakStrategy() { // Nome da estratégia atualizado
    const FNAME_RUNNER = "runPhantomPropertyLeakStrategy";
    logS3(`==== INICIANDO Estratégia de Leitura de Propriedade "Fantasma" (RangeError/Leak Check) ====`, 'test', FNAME_RUNNER);

    await executePhantomPropertyLeakTest(); // Chama a função do arquivo atualizado

    logS3(`==== Estratégia de Leitura de Propriedade "Fantasma" (RangeError/Leak Check) CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_PhantomPropertyLeak'; // Nome do teste principal atualizado
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Leitura de Propriedade "Fantasma" Pós-Corrupção (RangeError/Leak Check) ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - Phantom Prop Leak Test";

    await runPhantomPropertyLeakStrategy(); // Chama a estratégia atualizada

    logS3(`\n==== Script 3 CONCLUÍDO (Phantom Prop Leak Test) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes("CONGELOU?")) {
        // Manter
    } else if (document.title.includes("LEAK") || document.title.includes("RangeError") || document.title.includes("REPRODUCED") || document.title.includes("ERRO")) {
        // Manter títulos que indicam resultados específicos
    }
    else {
        document.title = "Script 3 Concluído - Phantom Prop Leak Test";
    }
}
