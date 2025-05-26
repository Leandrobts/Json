// js/script2/runCanvasTestSequence.mjs
import {
    logS2, PAUSE_S2, SHORT_PAUSE_S2, MEDIUM_PAUSE_S2,
    IMG_SQUARE_SIZE_S2, IMG_SQUARE_SPACING_S2, IMG_SQUARES_START_Y_S2
} from './s2_utils.mjs';
import {
    getOutputCanvasS2, getRunBtnCanvasS2, getInteractiveCanvasS2, getCanvasCoordStatusS2
} from '../dom_elements.mjs';
import {
    getLeakedValueS1, setCanvasContext2D_S2, setCurrentLeakDataS2,
    interactiveAreasS2 as stateInteractiveAreas, imgSquaresS2 as stateImgSquares,
    setCanvasClickListenerS2, setCanvasMoveListenerS2,
    getCanvasClickListenerS2, getCanvasMoveListenerS2, clearS2State,
    setGlContextS2, getGlContextS2, // <--- CORREÇÃO: getGlContextS2 adicionado aqui
    setGpuAdapterS2, setGpuDeviceS2
} from '../state.mjs';
import { redrawAllS2, canvasMoveListenerS2_logic, canvasClickListenerS2_logic } from './s2_canvas_helpers.mjs';

// Importar TODAS as funções de teste do Script 2
import { testWebGLCheckS2 } from './testWebGLCheck.mjs';
import { testAdvancedPPS2 } from './testAdvancedPP.mjs';
import { testOOBReadEnhancedS2 } from './testOOBReadEnhanced.mjs';
import { testOOBWriteMetadataS2 } from './testOOBWriteMetadata.mjs';
import { testWebGLDeeperPlusS2 } from './testWebGLDeeperPlus.mjs';
import { testOOBWriteToImageDataCheckS2 } from './testOOBWriteToImageData.mjs';
import { testOOBWriteOnlyS2 } from './testOOBWriteOnly.mjs';
import { testFileSystemAccessS2 } from './testFileSystemAccess.mjs';
import { testWebGPUCheckS2 } from './testWebGPUCheck.mjs';


export async function runCanvasTestSequenceS2() {
    const FNAME = 'runCanvasTestSequenceS2';
    const runBtnCanvas = getRunBtnCanvasS2();
    const outputDivCanvasS2 = getOutputCanvasS2();
    const canvasElementS2 = getInteractiveCanvasS2();
    const coordStatusDivS2 = getCanvasCoordStatusS2();

    if (!outputDivCanvasS2 || !runBtnCanvas || !canvasElementS2 || !coordStatusDivS2) {
        console.error("FATAL: Elementos essenciais S2 não encontrados para runCanvasTestSequenceS2!");
        return;
    }

    if (runBtnCanvas) runBtnCanvas.disabled = true;
    clearS2State();
    setGlContextS2(null, false);
    setGpuAdapterS2(null); setGpuDeviceS2(null);
    if (outputDivCanvasS2) outputDivCanvasS2.innerHTML = '';
    logS2("Iniciando sequência completa do Script 2 (v19.0 - Modular)...", "test", FNAME);

    try {
        const ctx = canvasElementS2.getContext('2d');
        if (!ctx) throw new Error("Falha ao obter Ctx 2D para S2.");
        setCanvasContext2D_S2(ctx);
    } catch (e) {
        logS2(`Falha Ctx 2D (S2): ${e.message}`, 'critical', FNAME);
        if (runBtnCanvas) runBtnCanvas.disabled = false;
        return;
    }

    stateInteractiveAreas.length = 0;
    stateInteractiveAreas.push(
        { id: 'rect-log-s2', x: 10, y: 10, w: 70, h: 25, color: '#FF5733', hoverColor: '#FF8C66', text: 'Log Clk' },
        { id: 'rect-link-s2', x: 90, y: 10, w: 80, h: 25, color: '#337BFF', hoverColor: '#66A3FF', text: 'Abrir Link' },
        { id: 'rect-rerun-s2', x: 180, y: 10, w: 100, h: 25, color: '#4CAF50', hoverColor: '#80C883', text: 'Re-ler Leak S1' }
    );

    stateImgSquares.length = 0;
    let sqX = 10;
    let sqY = IMG_SQUARES_START_Y_S2;
    const squareDefsS2Config = [
        { id: 's2-sq-meta', text: 'Meta', color: '#FF5733', action: testOOBWriteMetadataS2 },
        { id: 's2-sq-pp', text: 'PP++', color: '#C70039', action: testAdvancedPPS2 },
        { id: 's2-sq-oobrd', text: 'OOBRd', color: '#E67E22', action: testOOBReadEnhancedS2 },
        { id: 's2-sq-imgdt', text: 'ImgDt', color: '#900C3F', action: testOOBWriteToImageDataCheckS2 },
        { id: 's2-sq-file', text: 'File', color: '#581845', action: testFileSystemAccessS2 },
        { id: 's2-sq-gpu', text: 'WebGPU', color: '#337BFF', action: testWebGPUCheckS2 },
        { id: 's2-sq-webgl', text: 'WebGL+', color: '#2ECC71', action: testWebGLDeeperPlusS2 },
    ];

    squareDefsS2Config.forEach(def => {
        if (sqX + IMG_SQUARE_SIZE_S2 + IMG_SQUARE_SPACING_S2 > canvasElementS2.width - 5 && sqX > 10) {
            sqX = 10;
            sqY += IMG_SQUARE_SIZE_S2 + IMG_SQUARE_SPACING_S2;
        }
        if (sqY + IMG_SQUARE_SIZE_S2 > canvasElementS2.height - 15) {
            logS2(`AVISO: Não há espaço para o quadrado ${def.id} no canvas (Y: ${sqY}). Pulando.`, 'warn', FNAME);
            return;
        }
        stateImgSquares.push({
            id: def.id, x: sqX, y: sqY,
            size: IMG_SQUARE_SIZE_S2, color: def.color,
            text: def.text, hover: false, url: def.url, action: def.action
        });
        sqX += IMG_SQUARE_SIZE_S2 + IMG_SQUARE_SPACING_S2;
    });

    redrawAllS2();
    await PAUSE_S2();

    try {
        const l = getLeakedValueS1();
        if (l) {
            const ls = l.type === 'U64' ? `L(S1):U64 H=${toHexS2(l.high)} L=${toHexS2(l.low)}@${l.offset}` : `L(S1):U32 ${toHexS2(l.low)}@${l.offset}`;
            setCurrentLeakDataS2({ text: ls, color: "#FF9800" });
        } else {
            setCurrentLeakDataS2({ text: "L(S1):NULO", color: "#FFC107" });
        }
    } catch (e) {
        setCurrentLeakDataS2({ text: "L(S1):ERRO", color: "#F44336" });
    }
    redrawAllS2();
    await PAUSE_S2();

    await testWebGLCheckS2(); await PAUSE_S2(SHORT_PAUSE_S2);
    await testAdvancedPPS2(); await PAUSE_S2(SHORT_PAUSE_S2);
    await testOOBReadEnhancedS2(); await PAUSE_S2(SHORT_PAUSE_S2);
    await testOOBWriteMetadataS2(); await PAUSE_S2(SHORT_PAUSE_S2);

    logS2("--- Iniciando Teste de Interação OOB Write -> WebGL (S2) ---", 'test', FNAME);
    const oobWriteInteractionOK_S2 = await testOOBWriteOnlyS2();
    await testWebGLDeeperPlusS2();
    // Agora getGlContextS2() está corretamente importado e pode ser chamado
    if (oobWriteInteractionOK_S2 && getGlContextS2()) {
        logS2(` ---> *** ALERTA POTENCIAL S2: WebGL funcionou após OOB Write. Investigar. ***`, 'escalation', FNAME);
    }
    logS2("--- Teste Interação OOB Write -> WebGL (S2) Concluído ---", 'test', FNAME);
    await PAUSE_S2(SHORT_PAUSE_S2);

    await testOOBWriteToImageDataCheckS2();
    await PAUSE_S2(SHORT_PAUSE_S2);

    await testFileSystemAccessS2(); await PAUSE_S2(SHORT_PAUSE_S2);
    await testWebGPUCheckS2(); await PAUSE_S2(SHORT_PAUSE_S2);

    logS2("--- Sequência principal de testes S2 focados concluída ---", 'test', FNAME);
    await PAUSE_S2(100);

    const oldClickListener = getCanvasClickListenerS2();
    if (oldClickListener && canvasElementS2) {
        try { canvasElementS2.removeEventListener('click', oldClickListener); } catch (e) {}
    }
    const oldMoveListener = getCanvasMoveListenerS2();
    if (oldMoveListener && canvasElementS2) {
        try { canvasElementS2.removeEventListener('mousemove', oldMoveListener); } catch (e) {}
    }

    setCanvasMoveListenerS2(canvasMoveListenerS2_logic);
    setCanvasClickListenerS2(canvasClickListenerS2_logic);
    canvasElementS2.addEventListener('mousemove', canvasMoveListenerS2_logic);
    canvasElementS2.addEventListener('click', canvasClickListenerS2_logic);

    redrawAllS2();

    logS2("--- Fim da execução Script 2 (v19.0 - Modular Completo) ---", 'test', FNAME);
    if (runBtnCanvas) runBtnCanvas.disabled = false;
}

export async function runCanvasTest() {
    await runCanvasTestSequenceS2();
}
