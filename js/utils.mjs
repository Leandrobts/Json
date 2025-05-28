// js/script3/s3_utils.mjs
console.log("[CONSOLE_LOG][S3_UTILS] Módulo s3_utils.mjs carregado.");
import { logToDiv } from '../logger.mjs';
import { PAUSE as genericPause } from '../utils.mjs';

export const SHORT_PAUSE_S3 = 50;
export const MEDIUM_PAUSE_S3 = 500;

export const logS3 = (message, type = 'info', funcName = '') => {
    // console.log(`[S3_LOG_CALL] ${funcName} - ${type}: ${message}`); // Log de chamada para depuração
    logToDiv('output-advanced', message, type, funcName);
};

export const PAUSE_S3 = (ms = SHORT_PAUSE_S3) => genericPause(ms);
