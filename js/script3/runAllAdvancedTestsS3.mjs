// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs'; // Removido MEDIUM_PAUSE não usado aqui
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a nova função de teste de vazamento do WebKit
import { attemptLeakWebKitBase } from './runLeakWebKitBaseTest.mjs';
// Mantém a importação do teste de re-tipagem original se você ainda quiser executá-lo separadamente
// import { executeRetypeOOB_AB_Test } from './testRetypeOOB_AB_ViaShadowCraft.mjs'; // Comentado pois agora read_arbitrary_via_retype é usado

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_LeakWebKit';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = ''; // Limpa o log anterior

    logS3(`==== INICIANDO Script 3: Tentativa de Vazar Endereço Base do WebKit ====`,'test', FNAME);
    // Adiciona um pequeno título ao log da página HTML
    if (typeof document !== "undefined" && document.title) {
        document.title = "Teste S3: Vazamento Base WebKit";
    }

    // Chama o novo teste principal
    await attemptLeakWebKitBase();

    // Se você quisesse rodar o teste de re-tipagem original como uma demonstração separada:
    // logS3(`==== EXECUTANDO TESTE DE RE-TIPAGEM ORIGINAL (Demonstração) ====`, 'test', FNAME);
    // await executeRetypeOOB_AB_Test(); // Certifique-se que esta função ainda existe e é exportada se for usá-la.
    // logS3(`==== TESTE DE RE-TIPAGEM ORIGINAL CONCLUÍDO ====`, 'test', FNAME);

    logS3(`==== Script 3: Tentativa de Vazar Endereço Base do WebKit CONCLUÍDA ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;
}
