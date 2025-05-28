// js/run_isolated_test.mjs
import { testJsonTypeConfusionUAFSpeculative } from './script3/testJsonTypeConfusionUAFSpeculative.mjs';
import { getElementById } from './dom_elements.mjs'; // Para interagir com o botão e a div

function initializeAndRunTest() {
    const runBtn = getElementById('runIsolatedTestBtn');
    const outputDiv = getElementById('output-advanced');

    if (!outputDiv) {
        console.error("DIV 'output-advanced' não encontrada. O log não será exibido na página.");
    }

    if (runBtn) {
        runBtn.addEventListener('click', async () => {
            if (runBtn.disabled) return;
            runBtn.disabled = true;
            
            if (outputDiv) {
                outputDiv.innerHTML = ''; // Limpa logs anteriores
            }
            console.log("Iniciando teste isolado: testJsonTypeConfusionUAFSpeculative...");

            try {
                await testJsonTypeConfusionUAFSpeculative();
            } catch (e) {
                console.error("Erro crítico durante a execução do teste isolado:", e);
                if (outputDiv) {
                    // Tenta logar o erro na div também
                    const timestamp = `[${new Date().toLocaleTimeString()}]`;
                    outputDiv.innerHTML += `<span class="log-critical">${timestamp} [ERRO CRÍTICO NO TESTE] ${String(e.message).replace(/</g, "&lt;").replace(/>/g, "&gt;")}\n</span>`;
                }
            } finally {
                console.log("Teste isolado concluído.");
                if (outputDiv) {
                     const timestamp = `[${new Date().toLocaleTimeString()}]`;
                    outputDiv.innerHTML += `<span class="log-test">${timestamp} Teste isolado finalizado. Verifique o console para mais detalhes, especialmente se o navegador travou.\n</span>`;
                }
                runBtn.disabled = false;
            }
        });
    } else {
        console.error("Botão 'runIsolatedTestBtn' não encontrado.");
    }
}

// Garante que o DOM esteja pronto
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeAndRunTest);
} else {
    initializeAndRunTest();
}
