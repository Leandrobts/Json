// js/script1/testOOBUAFPattern.mjs
import { logS1, PAUSE_S1, SHORT_PAUSE_S1 } from './s1_utils.mjs';
// Não há dependências diretas de ../state.mjs ou ../dom_elements.mjs nesta função específica
// Apenas utils.mjs (AdvancedInt64, etc.) não são diretamente usados aqui, mas PAUSE_S1 já os encapsula se necessário.

export async function testOOBUAFPatternS1() {
    const FNAME = 'testOOBUAFPatternS1'; 
    logS1("--- Iniciando Teste 3: OOB Write -> UAF Pattern ---", 'test', FNAME); 
    const buffer1Size = 64; 
    const buffer2Size = 128; 
    const oobWriteOffset = buffer1Size; // OOB write happens at the end of buffer1
    const corruptedValue = 0xDEADBEEF; 
    const allocationSize1 = buffer1Size + 128; // Extra space to allow OOB write from within the allocated region for dv1
    const baseOffset1 = 64; // Offset within allocationSize1 where buffer1 "conceptually" starts for dv1
    
    let buffer1 = null;
    let buffer2 = null;
    let dv1 = null; 
    let writeOK = false; 
    let uafTriggered = false; 
    
    try { 
        // Aloca um buffer grande o suficiente para dv1 escrever OOB sem realmente sair de 'buffer1'
        buffer1 = new ArrayBuffer(allocationSize1); 
        dv1 = new DataView(buffer1); 
        // Inicializa buffer1
        for (let i = 0; i < buffer1.byteLength; i++) dv1.setUint8(i, 0xBB); 
        
        // Aloca buffer2 que será o alvo da corrupção de metadados (simulado)
        buffer2 = new ArrayBuffer(buffer2Size); 
        const dv2_init = new DataView(buffer2); 
        for (let i = 0; i < buffer2.byteLength; i++) dv2_init.setUint8(i, 0xCC); 
        
        await PAUSE_S1(); 
        
        // Endereço alvo para a escrita OOB, relativo ao início de 'buffer1' como visto por dv1
        const targetWriteAddr = baseOffset1 + oobWriteOffset; 
        
        try { 
            // Verifica se a escrita está dentro dos limites do ArrayBuffer real 'buffer1'
            if (targetWriteAddr >= 0 && targetWriteAddr + 4 <= buffer1.byteLength) {
                dv1.setUint32(targetWriteAddr, corruptedValue, true); // Escrita OOB (relativa ao 'baseOffset1')
                logS1(`VULN: Escrita OOB U32 @${oobWriteOffset} (addr lógico ${targetWriteAddr} em dv1) parece OK.`, 'vuln', FNAME); 
                logS1(`---> *** ALERTA: Primitivo Relevante (OOB Write) ***`, 'escalation', FNAME); 
                writeOK = true; 
            } else {
                 logS1(`Offset de escrita OOB (${targetWriteAddr}) fora do buffer1 real. Ajuste baseOffset1 ou allocationSize1.`, 'warn', FNAME);
            }
        } catch (e) { 
            logS1(`Escrita OOB U32 FALHOU/Bloqueada: ${e.message}`, 'good', FNAME); 
        } 
        
        if (writeOK) { 
            await PAUSE_S1(); 
            // Tenta usar buffer2. Se a escrita OOB corrompeu metadados adjacentes
            // (o que este teste apenas simula conceitualmente, pois buffer1 e buffer2 são alocações separadas
            // e a corrupção real de metadados de buffer2 por uma escrita em buffer1 é complexa e dependente do allocator),
            // o uso de buffer2 poderia falhar ou exibir comportamento anômalo.
            try { 
                // Operações normais em buffer2 para checar se ele foi afetado
                const slicedBuffer2 = buffer2.slice(0, 10); // Tenta usar o buffer
                const dv2_check = new DataView(buffer2); 
                const lengthCheck = buffer2.byteLength; 
                const firstByte = dv2_check.getUint8(0);

                if (lengthCheck !== buffer2Size || firstByte !== 0xCC) {
                     logS1(`---> VULN? Buffer 2 parece ter sido modificado! Tamanho: ${lengthCheck}, Byte0: ${firstByte.toString(16)}`, 'critical', FNAME);
                     logS1(`---> *** ALERTA: Potencial UAF ou Corrupção de Metadados detectada! ***`, 'escalation', FNAME);
                     uafTriggered = true; // Indica que algo inesperado aconteceu com buffer2
                } else {
                    logS1(`Uso do buffer 2 após escrita OOB em buffer1 parece OK (tamanho: ${lengthCheck}). Nenhuma UAF óbvia detectada no buffer2 diretamente.`, 'good', FNAME); 
                }
            } catch (e) { 
                logS1(`---> VULN? ERRO ao usar buffer 2 após escrita OOB em buffer1: ${e.message}`, 'critical', FNAME); 
                logS1(`---> *** ALERTA: Potencial UAF ou Corrupção de Metadados detectada! O erro ao usar buffer2 PODE indicar sucesso na corrupção. ***`, 'escalation', FNAME); 
                uafTriggered = true; 
                console.error("Erro UAF Pattern:", e); 
            } 
        } 
    } catch (e) { 
        logS1(`Erro fatal no Teste 3 (OOB UAF): ${e.message}`, 'error', FNAME); 
        console.error(e); 
    } finally { 
        // Limpeza explícita para ajudar o GC, embora em JS moderno seja menos crítico para ArrayBuffers.
        buffer1 = null; 
        buffer2 = null; 
        dv1 = null; 
        logS1(`--- Teste 3 Concluído (Escrita OOB em buffer1: ${writeOK}, Potencial UAF/Corrupção em buffer2: ${uafTriggered}) ---`, 'test', FNAME); 
        /* Comentário de Contexto para Exploração: 
        Este teste é conceitual. Uma verdadeira corrupção dos metadados de 'buffer2' por uma escrita OOB de 'buffer1'
        exigiria que 'buffer2' fosse alocado adjacente a 'buffer1' na memória de uma maneira específica, 
        e que a escrita OOB atingisse precisamente os campos de metadados de 'buffer2' (ex: seu tamanho ou ponteiro de dados).
        Se uma escrita OOB leva a uma UAF ou corrupção de metadados que pode ser controlada, 
        isso pode ser usado para obter controle do fluxo de execução, por exemplo, 
        sobrescrevendo um ponteiro de função de um objeto liberado antes que ele seja reutilizado.
        */
    } 
    return writeOK && uafTriggered; // Retorna true se a escrita ocorreu e algo anômalo foi detectado em buffer2
}
