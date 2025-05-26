// js/main.mjs
import { 
    getRunBtnS1, getRunBtnCanvasS2, getRunBtnAdvancedS3, 
    getBuildRopChainBtn, getViewMemoryBtn, cacheCommonElements,
    getInteractiveCanvasS2 // Necessário para o cleanup do S2
} from './dom_elements.mjs';

// Importar os runners de cada script
import { runAllTestsS1 } from './script1/runAllTestsS1.mjs';
import { runCanvasTest } from './script2/runCanvasTestSequence.mjs'; 
import { runAllAdvancedTestsS3 } from './script3/runAllAdvancedTestsS3.mjs';

// Importar handlers para ferramentas interativas do Script 3
import { buildRopChainFromUI } from './script3/rop_builder.mjs'; // Nome usado no exemplo anterior
import { viewMemoryFromUI } from './script3/memory_viewer.mjs'; // Nome usado no exemplo anterior

// Para o cleanup do S2
import { getCanvasClickListenerS2, getCanvasMoveListenerS2, getGpuDeviceS2, clearS2State } from './state.mjs';


function initialize() {
    console.log("Initializing Vulnerability Suite (Modular - Full Orchestration)...");
    cacheCommonElements(); // Opcional: Pré-cache de elementos DOM comuns

    // Botão Script 1
    const btnS1 = getRunBtnS1();
    if (btnS1) {
        btnS1.addEventListener('click', async () => {
            console.log("Botão S1 (runAllTestsS1) Clicado");
            try {
                await runAllTestsS1();
            } catch (e) {
                console.error("Erro ao executar testes do Script 1:", e);
                alert(`Erro Script 1: ${e.message}`);
            }
        });
    } else { console.warn("Botão 'runBtnS1' não encontrado."); }

    // Botão Script 2 (Canvas)
    const btnS2 = getRunBtnCanvasS2();
    if (btnS2) {
        btnS2.addEventListener('click', async () => {
            console.log("Botão S2 (runCanvasTest) Clicado");
            try {
                await runCanvasTest();
            } catch (e) {
                console.error("Erro ao executar testes do Script 2 (Canvas):", e);
                alert(`Erro Script 2: ${e.message}`);
            }
        });
    } else { console.warn("Botão 'runCanvasBtnS2' não encontrado."); }

    // Botão Script 3 (Testes Avançados Automatizados)
    const btnS3 = getRunBtnAdvancedS3();
    if (btnS3) {
        btnS3.addEventListener('click', async () => {
            console.log("Botão S3 (runAllAdvancedTestsS3) Clicado");
            try {
                await runAllAdvancedTestsS3();
            } catch (e) {
                console.error("Erro ao executar testes avançados do Script 3:", e);
                alert(`Erro Script 3: ${e.message}`);
            }
        });
    } else { console.warn("Botão 'runAdvancedBtnS3' não encontrado."); }
    
    // Botão Construtor ROP (Script 3 Interativo)
    const btnRop = getBuildRopChainBtn();
    if (btnRop) {
        btnRop.addEventListener('click', () => {
            console.log("Botão Construir Cadeia ROP Clicado");
            try {
                if (typeof buildRopChainFromUI === 'function') {
                    buildRopChainFromUI();
                } else {
                    console.error("Função buildRopChainFromUI não carregada/importada corretamente.");
                    alert("Erro: Função ROP Builder não disponível.");
                }
            } catch (e) {
                console.error("Erro ao chamar buildRopChainFromUI:", e);
                alert(`Erro ROP Builder: ${e.message}`);
            }
        });
    } else { console.warn("Botão 'buildRopChainBtn' não encontrado."); }

    // Botão Visualizador de Memória (Script 3 Interativo)
    const btnMemView = getViewMemoryBtn();
    if (btnMemView) {
        btnMemView.addEventListener('click', () => {
            console.log("Botão Visualizar Memória Clicado");
            try {
                if (typeof viewMemoryFromUI === 'function') {
                    viewMemoryFromUI();
                } else {
                    console.error("Função viewMemoryFromUI não carregada/importada corretamente.");
                    alert("Erro: Função Memory Viewer não disponível.");
                }
            } catch (e) {
                console.error("Erro ao chamar viewMemoryFromUI:", e);
                alert(`Erro Memory Viewer: ${e.message}`);
            }
        });
    } else { console.warn("Botão 'viewMemoryBtn' não encontrado."); }
    
    // Configura cleanup para listeners do S2 no unload (lógica original do HTML)
    window.addEventListener('unload', () => {
        console.log("[main.mjs] Tentando limpeza no evento 'unload'...");
        try {
            const canvasElementS2 = getInteractiveCanvasS2(); // Usa o getter de dom_elements
            const clickListener = getCanvasClickListenerS2(); // Pega do estado
            const moveListener = getCanvasMoveListenerS2();   // Pega do estado

            if (clickListener && canvasElementS2) {
                canvasElementS2.removeEventListener('click', clickListener);
                console.log("Listener de clique do Canvas S2 removido.");
            }
            if (moveListener && canvasElementS2) {
                canvasElementS2.removeEventListener('mousemove', moveListener);
                console.log("Listener de movimento do mouse do Canvas S2 removido.");
            }
            
            const gpuDev = getGpuDeviceS2(); // Pega do estado
            if (gpuDev && typeof gpuDev.destroy === 'function') {
                // A especificação WebGPU sugere que 'destroy' deve ser chamado para liberar recursos.
                // No entanto, chamar no 'unload' pode ser problemático ou desnecessário se o navegador já o faz.
                // gpuDev.destroy(); 
                // console.log("Dispositivo WebGPU (S2) .destroy() chamado.");
            }
            clearS2State(); // Limpa o estado relacionado ao S2
            console.log("Estado do S2 limpo.");

        } catch (e) {
            console.warn("[main.mjs] Erro durante a limpeza no 'unload':", e);
        }
        console.log("[main.mjs] Limpeza no 'unload' tentada.");
    });

    console.log("Vulnerability Suite (Modular - Full Orchestration) Inicializada.");
}

// Garante que o DOM esteja pronto antes de executar a inicialização
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initialize);
} else {
    initialize(); // DOM já carregado
}
