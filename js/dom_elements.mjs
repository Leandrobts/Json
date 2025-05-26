// js/dom_elements.mjs

const elementsCache = {};

export function getElementById(id) {
    if (elementsCache[id] && document.body.contains(elementsCache[id])) {
        return elementsCache[id];
    }
    const element = document.getElementById(id);
    if (element) {
        elementsCache[id] = element;
    }
    return element;
}

// Para o teste de instabilidade do ArrayBuffer
export const getRunVictimTestBtn = () => getElementById('runVictimTestBtn');
export const getOutputAdvancedDiv = () => getElementById('output-advanced'); // Reutilizando a div de log avançado

// Mantendo outros getters caso sejam usados por scripts importados indiretamente
export const getOutputDivS1 = () => getElementById('output');
export const getXssTargetDiv = () => getElementById('xss-target-div');
export const getRunBtnS1 = () => getElementById('runBtnS1');

export const getOutputCanvasS2 = () => getElementById('output-canvas');
export const getInteractiveCanvasS2 = () => getElementById('interactive-canvas');
export const getCanvasCoordStatusS2 = () => getElementById('canvas-coord-status');
export const getRunBtnCanvasS2 = () => getElementById('runCanvasBtnS2');

export const getOutputAdvancedS3 = () => getElementById('output-advanced'); // Alias para consistência
export const getRopGadgetsInput = () => getElementById('rop-gadgets-input');
export const getRopChainInput = () => getElementById('rop-chain-input');
export const getMemViewAddrInput = () => getElementById('mem-view-addr');
export const getMemViewSizeInput = () => getElementById('mem-view-size');
export const getRunBtnAdvancedS3 = () => getElementById('runAdvancedBtnS3');
export const getBuildRopChainBtn = () => getElementById('buildRopChainBtn');
export const getViewMemoryBtn = () => getElementById('viewMemoryBtn');


export function cacheCommonElements() {
    // Chamar para pré-cachear elementos se o app se tornar grande
    getRunVictimTestBtn();
    getOutputAdvancedDiv();
}
