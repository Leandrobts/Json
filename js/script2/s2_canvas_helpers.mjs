// js/script2/s2_canvas_helpers.mjs
import { 
    getCanvasContext2D_S2, getCurrentLeakDataS2, interactiveAreasS2 as stateInteractiveAreas, 
    imgSquaresS2 as stateImgSquares, getCurrentHoverTargetS2, setCurrentHoverTargetS2,
    getLeakedValueS1, setCurrentLeakDataS2
} from '../state.mjs';
import { getInteractiveCanvasS2, getCanvasCoordStatusS2, getRunBtnCanvasS2 } from '../dom_elements.mjs';
import { logS2, toHexS2 } from './s2_utils.mjs';

// Funções de desenho (internas, chamadas por redrawAllS2)
function drawInteractiveAreasS2_internal() {
    const ctx = getCanvasContext2D_S2();
    const currentHoverTarget = getCurrentHoverTargetS2();
    if (!ctx) return;
    try {
        stateInteractiveAreas.forEach(a => {
            ctx.fillStyle = (currentHoverTarget === a.id) ? a.hoverColor : a.color;
            ctx.fillRect(a.x, a.y, a.w, a.h);
            ctx.fillStyle = "#FFF";
            ctx.font = "bold 10px mono";
            ctx.textAlign = "center";
            ctx.textBaseline = "middle";
            ctx.fillText(a.text, a.x + a.w / 2, a.y + a.h / 2 + 1);
        });
        ctx.textAlign = "start"; // Reset
        ctx.textBaseline = "alphabetic"; // Reset
    } catch (e) { logS2(`Erro drawInteractiveAreasS2_internal: ${e.message}`, 'error', 'CanvasHelper'); }
}

function drawImageSquaresS2_internal() {
    const ctx = getCanvasContext2D_S2();
    if (!ctx) return;
    try {
        stateImgSquares.forEach(sq => {
            ctx.fillStyle = sq.hover ? '#FFFF88' : sq.color; // Cor de hover para o quadrado
            ctx.fillRect(sq.x, sq.y, sq.size, sq.size);
            ctx.strokeStyle = '#AAA';
            ctx.lineWidth = 1;
            ctx.strokeRect(sq.x, sq.y, sq.size, sq.size);
            if (sq.text) {
                ctx.fillStyle = "#FFF";
                ctx.font = "bold 9px mono";
                ctx.textAlign = "center";
                ctx.textBaseline = "middle";
                ctx.fillText(sq.text, sq.x + sq.size / 2, sq.y + sq.size / 2);
            }
            if (sq.url) { 
                ctx.fillStyle = "#6cf"; // Cor diferente para indicar link
                ctx.font = "bold 8px mono";
                ctx.textAlign = "center";
                ctx.textBaseline = "alphabetic"; // Ajuste para posicionar abaixo
                ctx.fillText("LINK", sq.x + sq.size / 2, sq.y + sq.size - 6);
            }
        });
        ctx.textAlign = "start"; // Reset
        ctx.textBaseline = "alphabetic"; // Reset
    } catch (e) { logS2(`Erro drawImageSquaresS2_internal: ${e.message}`, 'error', 'CanvasHelper'); }
}

export function redrawAllS2() {
    const ctx = getCanvasContext2D_S2();
    const canvasElement = getInteractiveCanvasS2();
    const currentLeakData = getCurrentLeakDataS2();

    if (!ctx || !canvasElement) {
        logS2("Contexto 2D ou elemento canvas não encontrado para redrawAllS2.", "warn", "CanvasHelper");
        return;
    }
    try {
        ctx.save();
        ctx.clearRect(0, 0, canvasElement.width, canvasElement.height);
        ctx.fillStyle = "#334"; // Fundo do canvas
        ctx.fillRect(0, 0, canvasElement.width, canvasElement.height);
        
        drawInteractiveAreasS2_internal();
        drawImageSquaresS2_internal();   
        
        // Desenha o texto do leak do Script 1
        if (currentLeakData) {
            ctx.fillStyle = currentLeakData.color;
            ctx.font = "10px mono";
            ctx.textAlign = "start";
            ctx.textBaseline = "alphabetic";
            ctx.fillText(currentLeakData.text, 10, canvasElement.height - 5);
        }
        ctx.restore();
    } catch (e) { logS2(`Erro redrawAllS2: ${e.message}`, 'error', 'redrawAllS2'); }
}

// Lógica dos Manipuladores de Evento
export function canvasMoveListenerS2_logic(event) {
    const canvasElement = getInteractiveCanvasS2();
    const coordStatusDiv = getCanvasCoordStatusS2();
    if (!canvasElement || !coordStatusDiv) return;

    const rect = canvasElement.getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;
    let needsRedraw = false;
    let newHoverTarget = null;
    let cursorStyle = 'default';

    stateInteractiveAreas.forEach(a => {
        if (x >= a.x && x <= a.x + a.w && y >= a.y && y <= a.y + a.h) {
            newHoverTarget = a.id;
            cursorStyle = 'pointer';
        }
    });

    stateImgSquares.forEach(sq => {
        let oldHover = sq.hover;
        sq.hover = false; // Reseta o hover
        if (x >= sq.x && x <= sq.x + sq.size && y >= sq.y && y <= sq.y + sq.size) {
            newHoverTarget = sq.id;
            cursorStyle = sq.action ? 'crosshair' : (sq.url ? 'pointer' : 'default');
            sq.hover = true; // Define hover para o quadrado atual
        }
        if (oldHover !== sq.hover) needsRedraw = true;
    });

    const currentGlobalHoverTarget = getCurrentHoverTargetS2();
    if (newHoverTarget !== currentGlobalHoverTarget) {
        setCurrentHoverTargetS2(newHoverTarget);
        needsRedraw = true;
    }

    try {
        if (needsRedraw) { redrawAllS2(); }
        canvasElement.style.cursor = cursorStyle;
        coordStatusDiv.textContent = `Coords: X=${x.toFixed(0)}, Y=${y.toFixed(0)}`;
    } catch (e) { 
        logS2(`Erro no mousemove S2: ${e.message}`, 'error', 'MouseMoveS2'); 
        console.error(e); 
    }
}

export async function canvasClickListenerS2_logic(event) {
    const FNAME_CLICK = 'CanvasClickS2';
    const canvasElement = getInteractiveCanvasS2();
    const runBtnCanvas = getRunBtnCanvasS2();
    if (!canvasElement) return;

    try {
        const rect = canvasElement.getBoundingClientRect();
        const x = event.clientX - rect.left;
        const y = event.clientY - rect.top;
        let clickedArea = null;
        stateInteractiveAreas.forEach(a => {
            if (x >= a.x && x <= a.x + a.w && y >= a.y && y <= a.y + a.h) { clickedArea = a; }
        });
        
        let clickedSquare = null;
        stateImgSquares.forEach((sq) => {
            if (x >= sq.x && x <= sq.x + sq.size && y >= sq.y && y <= sq.y + sq.size) { clickedSquare = sq; }
        });

        if (clickedArea) {
            logS2(`Click Área S2: ${clickedArea.text} (ID: ${clickedArea.id})`, 'info', FNAME_CLICK);
            switch (clickedArea.id) {
                case 'rect-log-s2': 
                    logS2('Click no botão de log (S2). Exemplo de ação.', 'info', FNAME_CLICK); 
                    break;
                case 'rect-link-s2': 
                    logS2('Abrindo link externo (google.com)...', 'info', FNAME_CLICK); 
                    try { window.open('https://google.com', '_blank'); } 
                    catch (e) { logS2('Erro window.open: ' + e.message, 'error', FNAME_CLICK); } 
                    break;
                case 'rect-rerun-s2':
                    logS2('Re-lendo leak S1...', 'info', FNAME_CLICK);
                    try {
                        const l = getLeakedValueS1(); 
                        if (l) { 
                            const ls = l.type === 'U64' ? `L(S1):U64 H=${toHexS2(l.high)} L=${toHexS2(l.low)}@${l.offset}` : `L(S1):U32 ${toHexS2(l.low)}@${l.offset}`; 
                            logS2(`-> Re-read Leak S1: ${ls}`, 'leak', FNAME_CLICK); 
                            setCurrentLeakDataS2({ text: ls, color: "#FF9800" }); 
                        } else { 
                            logS2(`-> Re-read Leak S1: Nulo`, 'warn', FNAME_CLICK); 
                            setCurrentLeakDataS2({ text: "L(S1):NULO", color: "#FFC107" }); 
                        }
                    } catch (e) { 
                        logS2(`Erro re-ler leak S1: ${e.message}`, 'error', FNAME_CLICK); 
                        setCurrentLeakDataS2({ text: "L(S1):ERRO", color: "#F44336" });
                    }
                    redrawAllS2();
                    break;
            }
        } else if (clickedSquare) {
            logS2(`Click Quadrado S2 ID: ${clickedSquare.id} (Texto: ${clickedSquare.text})`, 'vuln', FNAME_CLICK);
            if (clickedSquare.url) {
                logS2(`Abrindo URL: ${clickedSquare.url}`, 'info', FNAME_CLICK);
                try { window.open(clickedSquare.url, '_blank'); } 
                catch (e) { logS2('Erro window.open: ' + e.message, 'error', FNAME_CLICK); }
            } else if (clickedSquare.action && typeof clickedSquare.action === 'function') {
                let actionError = null;
                if (runBtnCanvas) runBtnCanvas.disabled = true;
                logS2(`Executando ação do quadrado S2: ${clickedSquare.id} (${clickedSquare.action.name || 'anon_action'})...`, 'test', FNAME_CLICK);
                try {
                    await clickedSquare.action(); // Chama a função de teste associada ao quadrado
                    logS2(`Ação S2 ${clickedSquare.id} concluída.`, 'good', FNAME_CLICK);
                } catch (e) {
                    logS2(`Erro durante ação S2 ${clickedSquare.id}: ${e.message}`, 'error', FNAME_CLICK);
                    console.error(`Erro ação S2 ${clickedSquare.id}:`, e);
                    actionError = e;
                } finally {
                    clickedSquare.color = actionError ? '#FFA500' : '#8A2BE2'; 
                    redrawAllS2();
                    if (runBtnCanvas) runBtnCanvas.disabled = false;
                    logS2(`Ação S2 ${clickedSquare.id} finalizada.`, 'test', FNAME_CLICK);
                }
            } else {
                logS2(`Nenhuma ação definida para o quadrado S2 ${clickedSquare.id}.`, 'info', FNAME_CLICK);
                clickedSquare.text = (clickedSquare.text || "") + "*"; // Marca como clicado
                redrawAllS2();
            }
        }
    } catch (e) {
        logS2(`Erro GERAL no listener de clique S2: ${e.message}`, 'error', FNAME_CLICK);
        console.error("Erro Clique S2:", e);
        if (runBtnCanvas) runBtnCanvas.disabled = false; // Garante que o botão seja reativado em caso de erro
    }
}
