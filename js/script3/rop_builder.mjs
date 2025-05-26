// js/script3/rop_builder.mjs
import { logS3 } from './s3_utils.mjs';
import { getRopGadgetsInput, getRopChainInput } from '../dom_elements.mjs';
import { AdvancedInt64 } from '../utils.mjs';

export function buildRopChainFromUI() { // Renomeado no exemplo anterior, mantendo para consistência
    const FNAME = "buildRopChainFromUI"; // Nome da função JS
    logS3("--- Construtor de Cadeia ROP (Conceitual - S3) ---", "tool", FNAME);
    
    const gadgetsInputEl = getRopGadgetsInput();
    const chainInputEl = getRopChainInput();

    if (!gadgetsInputEl || !chainInputEl) {
        logS3("Elementos de input ROP não encontrados.", "error", FNAME);
        return;
    }
    const gadgetsInput = gadgetsInputEl.value.trim();
    const chainInput = chainInputEl.value.trim();

    if (!gadgetsInput || !chainInput) {
        logS3("Entrada de gadgets ou cadeia ROP está vazia.", "warn", FNAME);
        return;
    }

    const gadgetMap = new Map();
    try {
        gadgetsInput.split('\n').forEach(line => {
            if (line.trim()) {
                const parts = line.split('=');
                if (parts.length === 2) {
                    // Tenta criar AdvancedInt64, mas captura erros se o formato do endereço for inválido
                    try {
                        const addr = new AdvancedInt64(parts[0].trim());
                        gadgetMap.set(parts[1].trim(), addr);
                    } catch (addrError) {
                        logS3(`AVISO: Endereço de gadget inválido '${parts[0].trim()}' para '${parts[1].trim()}'. Pulando. Erro: ${addrError.message}`, 'warn', FNAME);
                    }
                }
            }
        });
        logS3(`Gadgets carregados: ${gadgetMap.size}`, "info", FNAME);
        gadgetMap.forEach((addr, name) => logS3(`  ${name} : ${addr.toString(true)}`, "info"));

    } catch (e) {
        logS3(`Erro ao processar gadgets (S3): ${e.message}`, "error", FNAME);
        return;
    }

    const ropChain = [];
    const chainSteps = chainInput.split('\n');

    logS3("Construindo cadeia ROP (S3):", "info", FNAME);
    for (const step of chainSteps) {
        const trimmedStep = step.trim();
        if (!trimmedStep) continue;

        if (gadgetMap.has(trimmedStep)) { 
            const gadgetAddr = gadgetMap.get(trimmedStep);
            ropChain.push(gadgetAddr);
            logS3(`  [GADGET] ${trimmedStep} -> ${gadgetAddr.toString(true)}`, "info", FNAME);
        } else { 
            try {
                // Tenta interpretar como um valor numérico (hex ou dec)
                const value = trimmedStep.toLowerCase().startsWith("0x") 
                              ? new AdvancedInt64(trimmedStep) 
                              : new AdvancedInt64(parseInt(trimmedStep, 10)); // Assumir decimal se não for 0x
                ropChain.push(value);
                logS3(`  [VALOR]  ${trimmedStep} -> ${value.toString(true)}`, "info", FNAME);
            } catch (e) {
                logS3(`AVISO: '${trimmedStep}' não é um gadget conhecido nem um valor numérico válido. Tratando como string/placeholder.`, "warn", FNAME);
                ropChain.push(trimmedStep); // Adiciona como string se não puder ser convertido
            }
        }
    }

    if (ropChain.length > 0) {
        logS3("Cadeia ROP construída (endereços/valores - S3):", "good", FNAME);
        ropChain.forEach((item, index) => {
            logS3(`    ${index}: ${(item instanceof AdvancedInt64) ? item.toString(true) : String(item)}`, "info");
        });
        logS3("Nota: Esta é uma representação. A execução real requereria controle do ponteiro de stack (RSP) e um 'ret' inicial.", "info", FNAME);
    } else {
        logS3("Nenhuma cadeia ROP construída (S3).", "warn", FNAME);
    }
}
