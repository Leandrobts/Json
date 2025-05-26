// js/script2/s2_utils.mjs
import { logToDiv } from '../logger.mjs';
import { PAUSE as genericPause, toHex as genericToHex } from '../utils.mjs';
import { isPotentialPointer64S1, isPotentialData32S1 } from '../script1/s1_utils.mjs'; // Reutilizando do S1

export const SHORT_PAUSE_S2 = 50;
export const MEDIUM_PAUSE_S2 = 500;
export const IMG_SQUARE_SIZE_S2 = 28;
export const IMG_SQUARE_SPACING_S2 = 5;
export const IMG_SQUARES_START_Y_S2 = 45;


export const logS2 = (message, type = 'info', funcName = '') => {
    logToDiv('output-canvas', message, type, funcName);
};

export const PAUSE_S2 = (ms = SHORT_PAUSE_S2) => genericPause(ms);
export const toHexS2 = (val, bits = 32) => genericToHex(val, bits);

// Reutilizando verificadores do S1, podem ser específicos para S2 se necessário
export const isPotentialPointer64_S2_FUNC = (high, low) => isPotentialPointer64S1(high, low);
export const isPotentialData32_S2_FUNC = (val) => isPotentialData32S1(val);
