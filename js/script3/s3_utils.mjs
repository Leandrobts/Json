// js/script3/s3_utils.mjs
import { logToDiv } from '../logger.mjs';
import { PAUSE as genericPause } from '../utils.mjs';

export const SHORT_PAUSE_S3 = 50;
export const MEDIUM_PAUSE_S3 = 500;

export const logS3 = (message, type = 'info', funcName = '') => {
    logToDiv('output-advanced', message, type, funcName);
};

export const PAUSE_S3 = (ms = SHORT_PAUSE_S3) => genericPause(ms);

export function stringToAdvancedInt64Array(str) {
    let result = [];
    let buffer = new ArrayBuffer(str.length * 2); // UTF-16
    let view = new Uint16Array(buffer);
    for (let i = 0; i < str.length; i++) {
        view[i] = str.charCodeAt(i);
    }
    // Converter para AdvancedInt64 (8 bytes por vez)
    let u32View = new Uint32Array(buffer);
    for (let i = 0; i < u32View.length; i += 2) {
        let low = u32View[i];
        let high = (i + 1 < u32View.length) ? u32View[i+1] : 0; // Cuidado com o fim
        result.push(new AdvancedInt64(low, high));
    }
    // Adicionar terminador nulo se necessário (ex: um AdvancedInt64 zero)
    // result.push(AdvancedInt64.Zero); 
    return result;
}
