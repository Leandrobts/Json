// js/script1/testOOBOtherTypes.mjs
import { logS1, PAUSE_S1, SHORT_PAUSE_S1 } from './s1_utils.mjs';
// AdvancedInt64 e readWriteUtils não são usados diretamente nesta função,
// mas DataView é usado, que é uma API padrão do JS.

export async function testOOBOtherTypesS1() {
    const FNAME = 'testOOBOtherTypesS1'; 
    logS1("--- Iniciando Teste 4: OOB Write/Read (Float64/BigInt64) ---", 'test', FNAME); 
    const bufferSize = 64; 
    const oobWriteOffset = bufferSize; // Onde a escrita OOB ocorre
    const allocationSize = bufferSize + 128; // Tamanho total do buffer para permitir escrita OOB
    const baseOffset = 64; // "Início" conceitual do buffer dentro da alocação maior
    
    let buffer = null; 
    let dv = null; 
    let writeF64OK = false; 
    let writeB64OK = false; 
    let readF64OK = false; 
    let readB64OK = false; 
    
    try { 
        buffer = new ArrayBuffer(allocationSize); 
        dv = new DataView(buffer); 
        // Preenche o buffer com um padrão
        for (let i = 0; i < buffer.byteLength; i++) dv.setUint8(i, 0xDD); 
        
        const targetAddr = baseOffset + oobWriteOffset; // Endereço real da escrita OOB
        const writeValF64 = Math.PI; 
        const writeValB64 = BigInt("0x1122334455667788"); // Valor BigInt para teste
        
        logS1(`Tentando escrita OOB Float64 @${oobWriteOffset} (addr lógico ${targetAddr} em dv)`, 'info', FNAME); 
        try { 
            // Verifica se o endereço de escrita está dentro dos limites do ArrayBuffer real
            if (targetAddr >= 0 && targetAddr + 8 <= buffer.byteLength) {
                dv.setFloat64(targetAddr, writeValF64, true); // Escrita OOB de Float64
                logS1(`Escrita OOB Float64 parece OK.`, 'vuln', FNAME); 
                writeF64OK = true; 
            } else {
                logS1(`Offset F64 OOB (${targetAddr}) fora do buffer real.`, 'warn', FNAME);
            }
        } catch(e) { 
            logS1(`Escrita OOB Float64 FALHOU/Bloqueada: ${e.message}`, 'good', FNAME); 
        } 
        
        if (writeF64OK) { 
            try { 
                const readVal = dv.getFloat64(targetAddr, true); // Leitura OOB
                if (readVal === writeValF64) { 
                    logS1(`Leitura OOB Float64 CONFIRMADA (${readVal}). R/W OK.`, 'vuln', FNAME); 
                    logS1(`---> *** ALERTA: Primitivo R/W OOB Float64 confirmado ***`, 'escalation', FNAME); 
                    readF64OK = true; 
                } else { 
                    logS1(`Leitura OOB Float64 retornou valor inesperado: ${readVal}`, 'warn', FNAME); 
                } 
            } catch(e) { 
                logS1(`Leitura OOB Float64 FALHOU/Bloqueada: ${e.message}`, 'good', FNAME); 
            } 
        } 
        
        await PAUSE_S1(); 
        
        // Verifica se o navegador suporta BigInt64 em DataView
        if (typeof DataView.prototype.setBigInt64 !== 'undefined') { 
            logS1(`Tentando escrita OOB BigInt64 @${oobWriteOffset} (addr lógico ${targetAddr} em dv)`, 'info', FNAME); 
            try { 
                if (targetAddr >= 0 && targetAddr + 8 <= buffer.byteLength) {
                    dv.setBigInt64(targetAddr, writeValB64, true); // Escrita OOB de BigInt64
                    logS1(`Escrita OOB BigInt64 parece OK.`, 'vuln', FNAME); 
                    writeB64OK = true; 
                } else {
                     logS1(`Offset B64 OOB (${targetAddr}) fora do buffer real.`, 'warn', FNAME);
                }
            } catch(e) { 
                logS1(`Escrita OOB BigInt64 FALHOU/Bloqueada: ${e.message}`, 'good', FNAME); 
            } 
            
            if (writeB64OK) { 
                try { 
                    const readVal = dv.getBigInt64(targetAddr, true); // Leitura OOB
                    if (readVal === writeValB64) { 
                        logS1(`Leitura OOB BigInt64 CONFIRMADA (0x${readVal.toString(16)}). R/W OK.`, 'vuln', FNAME); 
                        logS1(`---> *** ALERTA: Primitivo R/W OOB BigInt64 confirmado ***`, 'escalation', FNAME); 
                        readB64OK = true; 
                    } else { 
                        logS1(`Leitura OOB BigInt64 retornou valor inesperado: 0x${readVal.toString(16)}`, 'warn', FNAME); 
                    } 
                } catch(e) { 
                    logS1(`Leitura OOB BigInt64 FALHOU/Bloqueada: ${e.message}`, 'good', FNAME); 
                } 
            } 
        } else { 
            logS1("BigInt64 em DataView não suportado neste navegador.", 'warn', FNAME); 
        } 
    } catch(e) { 
        logS1(`Erro fatal no Teste 4 (OOB Types): ${e.message}`, 'error', FNAME); 
        console.error(e); 
    } finally { 
        buffer = null; 
        dv = null; 
        logS1(`--- Teste 4 Concluído (F64 R/W: ${readF64OK}, B64 R/W: ${readB64OK}) ---`, 'test', FNAME); 
        /* Comentário de Contexto para Exploração: 
        Primitivas de Leitura/Escrita OOB estáveis para diferentes tipos de dados são versáteis. 
        Elas podem ser usadas para vazar informações (ler ponteiros, dados sensíveis) 
        ou corromper memória (escrever sobre ponteiros de função, metadados de objetos, etc.) 
        como parte de uma cadeia de exploração maior.
        */
    }
}
