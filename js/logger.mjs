// js/logger.mjs
console.log("[CONSOLE_LOG][LOGGER] Módulo logger.mjs carregado.");
import { getElementById } from './dom_elements.mjs';

export function logToDiv(divId, message, type = 'info', funcName = '') {
    const outputDiv = getElementById(divId);
    const timestamp = `[${new Date().toLocaleTimeString()}]`;
    const prefix = funcName ? `[${funcName}] ` : '';
    const sanitizedMessage = String(message).replace(/</g, "&lt;").replace(/>/g, "&gt;"); // Sanitize
    const logClass = ['info', 'test', 'subtest', 'vuln', 'good', 'warn', 'error', 'leak', 'ptr', 'critical', 'escalation', 'tool'].includes(type) ? type : 'info';

    if (!outputDiv) {
        console.error(`${timestamp} [LOGGER_FALLBACK] Log target div "${divId}" not found. Message: ${prefix}${sanitizedMessage} (Type: ${type})`);
        return;
    }
    try {
        if(outputDiv.innerHTML.length > 600000){ // Log truncation
            const lastPart = outputDiv.innerHTML.substring(outputDiv.innerHTML.length - 300000);
            outputDiv.innerHTML = `<span class="log-info">${timestamp} [Log Truncado...]</span>\n` + lastPart;
        }
        outputDiv.innerHTML += `<span class="log-${logClass}">${timestamp} ${prefix}${sanitizedMessage}\n</span>`;
        outputDiv.scrollTop = outputDiv.scrollHeight;
    } catch(e) {
        console.error(`${timestamp} [LOGGER_ERROR] Error in logToDiv for ${divId}: ${e.message}. Original Msg: ${prefix}${sanitizedMessage}`);
    }
}
