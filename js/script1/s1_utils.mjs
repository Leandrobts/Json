// js/script1/s1_utils.mjs
import { logToDiv } from '../logger.mjs';
import { PAUSE as genericPause, toHex as genericToHex } from '../utils.mjs';

export const SHORT_PAUSE_S1 = 50;
export const MEDIUM_PAUSE_S1 = 500;

export const logS1 = (message, type = 'info', funcName = '') => {
    logToDiv('output', message, type, funcName);
};

export const PAUSE_S1 = (ms = SHORT_PAUSE_S1) => genericPause(ms);
export const toHexS1 = (val, bits = 32) => genericToHex(val, bits);

export const isPotentialPointer64S1 = (high, low) => {
    if (high === null || low === null || typeof high !== 'number' || typeof low !== 'number') return false;
    if (high === 0 && low === 0) return false;
    if ((high >>> 0) === 0xFFFFFFFF && (low >>> 0) === 0xFFFFFFFF) return false;
    if ((high >>> 0) === 0xAAAAAAAA && (low >>> 0) === 0xAAAAAAAA) return false;
    // A common heuristic: pointers are usually not very small values.
    if (high === 0 && (low >>> 0) < 0x100000) return false; 
    return true;
};

export const isPotentialData32S1 = (val) => {
    if (val === null || typeof val !== 'number') return false;
    val = val >>> 0;
    if (val === 0 || val === 0xFFFFFFFF || val === 0xAAAAAAAA || val === 0xAAAAAAEE) return false;
    // Heuristic: data values are often not extremely small.
    if (val < 0x1000) return false; 
    return true;
};
