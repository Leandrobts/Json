// js/main.mjs
console.log("[CONSOLE_LOG][MAIN] Módulo main.mjs carregado.");

import { getRunBtnAdvancedS3 } from './dom_elements.mjs'; // Caminho para dom_elements.mjs
import { runAllAdvancedTestsS3 } from './script3/runAllAdvancedTestsS3.mjs'; // Caminho para o runner do S3
import { updateOOBConfigFromUI } from './config.mjs'; // Para garantir que a config seja lida da UI ao carregar

document.addEventListener('DOMContentLoaded', () => {
    console.log("[CONSOLE_LOG][MAIN] DOMContentLoaded acionado.");

    // Tenta ler a config da UI assim que o DOM estiver pronto
    // para que OOB_CONFIG já tenha os valores da UI se existirem.
    if (typeof document !== 'undefined' && document) {
        console.log("[CONSOLE_LOG][MAIN] Chamando updateOOBConfigFromUI de DOMContentLoaded.");
        updateOOBConfigFromUI(document);
    }


    const runS3Button = getRunBtnAdvancedS3();
    if (runS3Button) {
        console.log("[CONSOLE_LOG][MAIN] Botão S3 (runAdvancedBtnS3) encontrado.");
        runS3Button.addEventListener('click', async () => {
            console.log("[CONSOLE_LOG][MAIN_CLICK] Botão S3 (runAdvancedBtnS3) CLICADO! Iniciando runAllAdvancedTestsS3...");
            try {
                await runAllAdvancedTestsS3();
                console.log("[CONSOLE_LOG][MAIN_CLICK] runAllAdvancedTestsS3 concluído após clique.");
            } catch (e) {
                console.error("[CONSOLE_LOG][MAIN_CLICK] Erro ao executar runAllAdvancedTestsS3 a partir do main.mjs:", e);
                // Tentar logar na UI se possível
                if (typeof logS3 === 'function') { // logS3 pode não estar no escopo aqui
                    logS3(`ERRO FATAL no main.mjs ao executar testes: ${e.message}`, 'critical', 'MAIN_EVENT_HANDLER');
                }
            }
        });
        console.log("[CONSOLE_LOG][MAIN] Event listener para o botão S3 (runAdvancedBtnS3) ANEXADO.");
    } else {
        console.error("[CONSOLE_LOG][MAIN] Botão S3 (runAdvancedBtnS3) NÃO encontrado no DOM!");
    }

    // Adicione listeners para botões S1 e S2 aqui se necessário
    console.log("[CONSOLE_LOG][MAIN] Configuração de listeners de evento concluída.");
});

console.log("[CONSOLE_LOG][MAIN] Fim do script main.mjs (processamento síncrono).");
