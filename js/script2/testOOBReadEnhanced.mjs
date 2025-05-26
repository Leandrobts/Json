// js/script2/testOOBReadEnhanced.mjs
import { logS2, PAUSE_S2, toHexS2, isPotentialPointer64_S2_FUNC, isPotentialData32_S2_FUNC } from './s2_utils.mjs';

export async function testOOBReadEnhancedS2() {
    const FNAME = 'testOOBReadEnhancedS2'; 
    logS2("--- Teste: OOB Read Enhanced Scan (S2) ---",'test', FNAME); 
    const bufferSize = 32; 
    const readRangeStart = -128; 
    const readRangeEnd = bufferSize + 128; 
    const allocationSize = bufferSize + 512; // Buffer maior para scan
    const baseOffsetInBuffer = 256; // Offset dentro da alocação
    let potentialLeakFoundCount = 0; 
    const foundPointers = []; // Para armazenar informações sobre leaks encontrados
    
    try { 
        const buffer = new ArrayBuffer(allocationSize); 
        const dataView = new DataView(buffer); 
        // Preenche com um padrão para identificar memória não inicializada vs leaks
        for(let i=0; i<buffer.byteLength; i++){ dataView.setUint8(i, 0xCC); } 
        
        for(let readOffset = readRangeStart; readOffset < readRangeEnd; readOffset += 4){ 
            const readTargetAddress = baseOffsetInBuffer + readOffset; 
            const relOffsetStr = `@${readOffset} (addr lógico ${readTargetAddress})`; 
            
            // Tenta ler como U64 (ponteiro potencial)
            if(readTargetAddress >= 0 && readTargetAddress + 8 <= buffer.byteLength){ 
                try { 
                    const low = dataView.getUint32(readTargetAddress,true); 
                    const high = dataView.getUint32(readTargetAddress+4,true); 
                    // Evita logar o padrão de preenchimento
                    if (low === 0xCCCCCCCC && high === 0xCCCCCCCC) continue; 
                    
                    if(isPotentialPointer64_S2_FUNC(high,low)){ 
                        const valueStr=`H=${toHexS2(high)} L=${toHexS2(low)}`; 
                        logS2(` -> PTR? U64 ${relOffsetStr}: ${valueStr}`,'ptr', FNAME); 
                        potentialLeakFoundCount++; 
                        const leakInfo = {offset:readOffset, type:'U64', high, low, hex:valueStr}; 
                        foundPointers.push(leakInfo); 
                        logS2(` ---> *** ALERTA: Primitivo Relevante Potencial (OOB Read Pointer Leak S2) ***`, 'escalation', FNAME); 
                        logS2(` ---> INSIGHT: O valor vazado ${valueStr} (U64) em ${relOffsetStr} é um candidato a ponteiro. (...)`, 'info', FNAME); 
                    } 
                } catch(e){/* Leitura fora dos limites esperada */} 
            } 
            // Tenta ler como U32 (dado potencial) se não foi logado como ponteiro U64
            else if(readTargetAddress >= 0 && readTargetAddress + 4 <= buffer.byteLength){ 
                try { 
                    const val32 = dataView.getUint32(readTargetAddress,true); 
                    if (val32 === 0xCCCCCCCC) continue; // Evita logar padrão

                    // Verifica se já foi logado como parte de um U64
                    let alreadyLoggedAsPtr64 = foundPointers.some(p => p.offset === readOffset && p.type === 'U64');
                    if(!alreadyLoggedAsPtr64 && isPotentialData32_S2_FUNC(val32) && !isPotentialPointer64_S2_FUNC(0,val32)){ 
                        logS2(` -> Leak U32? ${relOffsetStr}: ${toHexS2(val32)}`,'leak', FNAME); 
                        potentialLeakFoundCount++; 
                        const leakInfo = {offset:readOffset, type:'U32', value:val32, hex:toHexS2(val32)}; 
                        foundPointers.push(leakInfo); 
                        logS2(` ---> *** ALERTA: Potencial Vazamento Info OOB Read U32 (S2) ***`, 'escalation', FNAME); 
                    } 
                } catch(e){/* Leitura fora dos limites esperada */} 
            } 
            if(readOffset % 64 === 0) await PAUSE_S2(1); // Pequena pausa para não sobrecarregar
        } 
    } catch(e){ 
        logS2(`Erro fatal no Teste OOB Read Scan S2: ${e.message}`,'error', FNAME); 
        console.error(e); 
    } finally { 
        logS2(`--- Teste OOB Read Scan S2 Concluído (${potentialLeakFoundCount} leaks potenciais encontrados) ---`,'test', FNAME); 
        if(foundPointers.length === 0){ 
            logS2("Nenhum leak potencial óbvio encontrado no OOB Read Scan S2.", 'good', FNAME); 
        } else { 
            // Para depuração, pode ser útil ver os leaks no console
            console.log("Potenciais Leaks (OOB Read Enhanced S2):", foundPointers); 
        } 
    } 
    await PAUSE_S2(); 
    return foundPointers; // Retorna os leaks encontrados para possível análise posterior
}
