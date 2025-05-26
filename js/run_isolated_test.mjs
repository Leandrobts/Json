// js/run_isolated_test.mjs
import { getElementById } from './dom_elements.mjs'; // Para interagir com o botão e a div
// Importa a função de teste principal do Script 3 (que agora inclui a lógica de variação de valor)
import { runAllAdvancedTestsS3 } from './script3/runAllAdvancedTestsS3.mjs';

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
            console.log("Iniciando teste isolado: Variação de Valor de Corrupção e Sondagem de Objetos Complexos...");

            try {
                // Chama a função principal do Script 3 que orquestra os testes
                await runAllAdvancedTestsS3();
            } catch (e) {
                console.error("Erro crítico durante a execução do teste isolado:", e);
                if (outputDiv) {
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
