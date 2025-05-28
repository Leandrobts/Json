// js/script3/runAllAdvancedTestsS3.mjs
console.log("[CONSOLE_LOG][S3_RUNNER] Módulo runAllAdvancedTestsS3.mjs carregado.");
import { logS3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { attemptLeakWebKitBase } from './runLeakWebKitBaseTest.mjs';
import { updateOOBConfigFromUI } from '../config.mjs'; // Importar para atualizar config da UI

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_LeakWebKit';
    console.log(`[CONSOLE_LOG][${FNAME}] Função iniciada.`);
    logS3(`[UI_LOG][${FNAME}] Função iniciada. Verificando botão e output...`, 'info', FNAME);

    // Atualizar config da UI antes de tudo
    if (typeof document !== 'undefined' && document) {
        console.log(`[CONSOLE_LOG][${FNAME}] Chamando updateOOBConfigFromUI no início.`);
        updateOOBConfigFromUI(document);
    }

    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (!runBtn) logS3("AVISO: runBtn (runAdvancedBtnS3) não encontrado!", 'warn', FNAME);
    if (!outputDiv) {
        console.error(`[CONSOLE_LOG][${FNAME}] DIV DE OUTPUT (output-advanced) NÃO ENCONTRADA! Logs da UI não funcionarão.`);
    }

    if (runBtn) runBtn.disabled = true;
    // Limpar o log SÓ SE a div for encontrada.
    if (outputDiv) outputDiv.innerHTML = '';
    else logS3("Div de output não encontrada, não é possível limpar logs anteriores da UI.", "warn", FNAME);


    logS3(`==== INICIANDO Script 3: Tentativa de Vazar Endereço Base do WebKit ====`,'test', FNAME);
    if (typeof document !== "undefined" && document.title) {
        document.title = "Teste S3: Vazamento Base WebKit";
    }

    try {
        logS3("Chamando attemptLeakWebKitBase...", 'info', FNAME);
        console.log(`[CONSOLE_LOG][${FNAME}] Prestes a chamar await attemptLeakWebKitBase().`);
        await attemptLeakWebKitBase();
        console.log(`[CONSOLE_LOG][${FNAME}] await attemptLeakWebKitBase() concluído.`);
        logS3("attemptLeakWebKitBase finalizado.", 'info', FNAME);
    } catch (e) {
        logS3(`ERRO CRÍTICO em ${FNAME} ao chamar attemptLeakWebKitBase: ${e.message}`, 'critical', FNAME);
        console.error(`[CONSOLE_LOG][${FNAME}] ERRO CRÍTICO em attemptLeakWebKitBase:`, e);
    }

    logS3(`==== Script 3: Tentativa de Vazar Endereço Base do WebKit CONCLUÍDA ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;
    console.log(`[CONSOLE_LOG][${FNAME}] Função concluída.`);
}
