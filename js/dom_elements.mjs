// js/dom_elements.mjs
console.log("[CONSOLE_LOG][DOM_ELEMENTS] Módulo dom_elements.mjs carregado.");

const elementsCache = {};

export function getElementById(id) {
    if (typeof document === 'undefined' || typeof document.getElementById !== 'function') {
        console.warn(`[CONSOLE_LOG][DOM_ELEMENTS] getElementById(${id}) chamada em ambiente sem 'document'.`);
        return null;
    }
    if (elementsCache[id] && document.body && document.body.contains(elementsCache[id])) {
        return elementsCache[id];
    }
    const element = document.getElementById(id);
    if (element) {
        elementsCache[id] = element;
    } else {
        console.warn(`[CONSOLE_LOG][DOM_ELEMENTS] Elemento com ID "${id}" não encontrado no DOM.`);
    }
    return element;
}

// Script 3 (único relevante para este teste)
export const getOutputAdvancedS3 = () => getElementById('output-advanced');
export const getRunBtnAdvancedS3 = () => getElementById('runAdvancedBtnS3');

// Inputs da UI para OOB_CONFIG (se você os usa para atualizar config.mjs)
export const getOobAllocSizeInput = () => getElementById('oobAllocSize');
export const getBaseOffsetInput = () => getElementById('baseOffset');

// Adicione getters para S1 e S2 se necessário para outros testes
