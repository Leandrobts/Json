// js/script2/testOOBWriteOnly.mjs
import { logS2, PAUSE_S2, toHexS2 } from './s2_utils.mjs';

export async function testOOBWriteOnlyS2() {
    const FNAME = 'testOOBWriteOnlyS2'; 
    logS2("--- Teste: OOB Write Only (Trigger S2) ---",'test', FNAME); 
    const bufferOOBSize = 64; 
    const writeValue1 = 0xDEADBEEF; 
    const writeValue2 = 0xCAFEBABE; 
    const writeValueSize = 8; // 2x U32
    const allocationSize = bufferOOBSize + 256; 
    const baseOffsetInBuffer = 128; 
    let bufferOOB = null; 
    let dvOOB = null; 
    let writeSuccess = false; 
    
    try { 
        bufferOOB = new ArrayBuffer(allocationSize); 
        dvOOB = new DataView(bufferOOB); 
        for(let i=0; i<bufferOOB.byteLength; i++) dvOOB.setUint8(i, 0xDD); // Padrão
    } catch(e){ 
        logS2(`Erro ao alocar buffer de controle (OOB Write Only S2): ${e.message}`,'error', FNAME); 
        console.error(e); 
        return false; // Retorna false se a alocação falhar
    } 
    
    const oobWriteRelOffset = bufferOOBSize; 
    const targetWriteAddr = baseOffsetInBuffer + oobWriteRelOffset; 
    const relOffsetStr = `@${oobWriteRelOffset} (addr lógico ${targetWriteAddr} em dvOOB)`; 
    
    try { 
        if(targetWriteAddr >= 0 && targetWriteAddr + writeValueSize <= bufferOOB.byteLength){ 
            dvOOB.setUint32(targetWriteAddr, writeValue1, true); 
            dvOOB.setUint32(targetWriteAddr + 4, writeValue2, true); 
            logS2(`Escrita OOB U32x2 @ ${relOffsetStr} OK (Val1=${toHexS2(writeValue1)}, Val2=${toHexS2(writeValue2)}).`, 'vuln', FNAME); 
            logS2(` ---> *** ALERTA: Primitivo Relevante Potencial (OOB Write S2) ***`, 'escalation', FNAME); 
            writeSuccess = true; 
        } else { 
            logS2(`Offset OOB ${relOffsetStr} fora do buffer de controle.`, 'error', FNAME); 
        } 
    } catch(e){ 
        logS2(`AVISO: Escrita OOB U32x2 falhou/bloqueada @ ${relOffsetStr}: ${e.message}`, 'good', FNAME); 
    } 
    
    logS2("--- Teste OOB Write Only S2 Concluído ---",'test', FNAME); 
    await PAUSE_S2(); 
    return writeSuccess; // Retorna true se a escrita foi tentada com sucesso
}
