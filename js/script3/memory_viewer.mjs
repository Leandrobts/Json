// js/script3/memory_viewer.mjs
import { logS3 } from './s3_utils.mjs';
import { getMemViewAddrInput, getMemViewSizeInput } from '../dom_elements.mjs';
import { AdvancedInt64 } from '../utils.mjs';

export function viewMemoryFromUI() { // Renomeado no exemplo anterior, mantendo para consistência
    const FNAME = "viewMemoryFromUI"; // Nome da função JS
    logS3("--- Visualizador de Memória (Conceitual - S3) ---", "tool", FNAME);
    
    const addrStrEl = getMemViewAddrInput();
    const sizeStrEl = getMemViewSizeInput();

    if (!addrStrEl || !sizeStrEl) {
        logS3("Elementos de input do visualizador de memória não encontrados.", "error", FNAME);
        return;
    }
    const addrStr = addrStrEl.value;
    const sizeStr = sizeStrEl.value;

    if (!addrStr || !sizeStr) {
        logS3("Endereço ou tamanho não fornecido para visualização de memória.", "warn", FNAME);
        return;
    }
    try {
        const startAddr = new AdvancedInt64(addrStr);
        const size = parseInt(sizeStr, 10);

        if (isNaN(size) || size <= 0 || size > 1024) { 
            logS3("Tamanho inválido ou muito grande (max 1024 bytes para esta demo).", "error", FNAME);
            return;
        }

        logS3(`Simulando leitura de ${size} bytes a partir de ${startAddr.toString(true)}:`, "info", FNAME);
        logS3("Conteúdo simulado (exemplo - bytes aleatórios):", "info", FNAME);

        let outputLines = [];
        let currentLineHex = "";
        let currentLineAscii = "";

        for (let i = 0; i < size; i++) {
            if (i % 16 === 0) { // Nova linha no hexdump
                if (i > 0) {
                    outputLines.push(`${currentLineHex} |${currentLineAscii}|`);
                }
                // Prepara o endereço para a nova linha
                const currentAddrOffset = startAddr.add(new AdvancedInt64(i));
                currentLineHex = `${currentAddrOffset.toString(true)}: `;
                currentLineAscii = "";
            }

            const randomByte = Math.floor(Math.random() * 256);
            currentLineHex += randomByte.toString(16).padStart(2, '0') + " ";
            // Caracteres imprimíveis (ASCII 32-126), senão '.'
            currentLineAscii += (randomByte >= 32 && randomByte <= 126) ? String.fromCharCode(randomByte) : ".";
        }
        // Adiciona a última linha se não estiver vazia
        if (currentLineHex.length > startAddr.toString(true).length + 2) { // Verifica se tem mais que só o endereço
             // Preenche com espaços para alinhar a parte ASCII se a linha for curta
            while (currentLineHex.length < (startAddr.toString(true).length + 2 + (16 * 3))) {
                currentLineHex += "   ";
            }
            outputLines.push(`${currentLineHex} |${currentLineAscii}|`);
        }
        
        outputLines.forEach(line => logS3(line, "info", FNAME));

        logS3("Nota: Uma primitiva de leitura real (ex: DataView sobre um ArrayBuffer corrompido) seria necessária para ler memória real.", "info", FNAME);

    } catch (e) {
        logS3(`Erro ao processar entrada do visualizador de memória (S3): ${e.message}`, "error", FNAME);
    }
}
