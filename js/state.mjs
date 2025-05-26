// js/state.mjs

// --- Script 1 State ---
export let leakedValueFromOOB_S1 = null;

export function setLeakedValueS1(value) {
    leakedValueFromOOB_S1 = value;
}
export function getLeakedValueS1() {
    return leakedValueFromOOB_S1;
}

// --- Script 2 State ---
export let canvasContextS2 = null; // For 2D context
export let glContextS2 = null;     // For WebGL context
export let isWebGL2S2 = false;
export let gpuAdapterS2 = null;
export let gpuDeviceS2 = null;
export let currentLeakDataS2 = { text: "Leak(S1): N/A", color: "#AAAAAA" }; // For display on canvas

// Canvas interaction state (simplified, original has more)
export let canvasClickListenerS2_handler = null;
export let canvasMoveListenerS2_handler = null;
export let currentHoverTargetS2 = null;
export const interactiveAreasS2 = []; // Populated by s2_canvas_helpers or runCanvasTestSequence
export const imgSquaresS2 = [];       // Populated by s2_canvas_helpers or runCanvasTestSequence


export function setCanvasContext2D_S2(ctx) { canvasContextS2 = ctx; }
export function getCanvasContext2D_S2() { return canvasContextS2; }
export function setGlContextS2(gl, is2) { glContextS2 = gl; isWebGL2S2 = is2; }
export function getGlContextS2() { return glContextS2; }
export function getIsWebGL2S2() { return isWebGL2S2; }
export function setGpuAdapterS2(adapter) { gpuAdapterS2 = adapter; }
export function getGpuAdapterS2() { return gpuAdapterS2; }
export function setGpuDeviceS2(device) { gpuDeviceS2 = device; }
export function getGpuDeviceS2() { return gpuDeviceS2; }
export function setCurrentLeakDataS2(data) { currentLeakDataS2 = data; }
export function getCurrentLeakDataS2() { return currentLeakDataS2; }

export function setCanvasClickListenerS2(handler) { canvasClickListenerS2_handler = handler; }
export function getCanvasClickListenerS2() { return canvasClickListenerS2_handler; }
export function setCanvasMoveListenerS2(handler) { canvasMoveListenerS2_handler = handler; }
export function getCanvasMoveListenerS2() { return canvasMoveListenerS2_handler; }
export function setCurrentHoverTargetS2(target) { currentHoverTargetS2 = target; }
export function getCurrentHoverTargetS2() { return currentHoverTargetS2; }


export function clearS2State() { // Call when re-running S2 tests
    canvasContextS2 = null;
    glContextS2 = null;
    isWebGL2S2 = false;
    gpuAdapterS2 = null;
    gpuDeviceS2 = null;
    currentLeakDataS2 = { text: "Leak(S1): N/A", color: "#AAAAAA" };
    interactiveAreasS2.length = 0;
    imgSquaresS2.length = 0;
    currentHoverTargetS2 = null;
    // Note: listener handlers themselves are not cleared here, but their attachment might be.
}
