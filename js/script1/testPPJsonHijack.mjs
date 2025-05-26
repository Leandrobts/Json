// js/script1/testPPJsonHijack.mjs
import { logS1, PAUSE_S1, toHexS1 } from './s1_utils.mjs';
import { getLeakedValueS1 } from '../state.mjs'; // Para acessar o valor vazado pelo teste OOB

export async function testPPJsonHijackS1() {
    const FNAME = 'testPPJsonHijackS1'; 
    logS1("--- Iniciando Teste 6: PP Hijack (JSON.stringify) ---", 'test', FNAME); 
    const origStringify = JSON.stringify; // Guarda a função original
    let okH = false; // Hijack bem-sucedido
    let okL = false; // Leitura do leak OOB bem-sucedida dentro do hijack
    let okR = false; // Retorno da função sequestrada verificado
    
    try { 
        // Tenta sequestrar JSON.stringify
        JSON.stringify = function hijacked(v, r, s) { 
            logS1("===> VULN: JSON.stringify SEQUESTRADO! <===", 'vuln', FNAME); 
            okH = true; 
            
            try { 
                const l = getLeakedValueS1(); // Tenta ler o valor vazado pelo teste OOB
                let lStr = "NULO ou Indefinido"; 
                if (l) { 
                    lStr = l.type === 'U64' ? `U64 H=${toHexS1(l.high)} L=${toHexS1(l.low)} @${l.offset}` : `U32 ${toHexS1(l.low)} @${l.offset}`; 
                    okL = true; 
                    logS1(` ---> INFO: Interação Hijack + OOB Read Leak OK.`, 'escalation', FNAME); 
                } 
                logS1(` -> Valor OOB lido dentro do hijack: ${lStr}`, okL ? 'leak' : 'warn', FNAME); 
            } catch(ie) { 
                logS1(` -> Erro ao tentar ler leak OOB dentro do hijack: ${ie.message}`, 'error', FNAME); 
                console.error(ie); 
            } 
            
            // Retorna um valor que indica que o hijack funcionou
            const hijackReturnValue = '{"hijacked": true, "leak_read_success": ' + okL + '}'; 
            return hijackReturnValue; 
        }; 
        
        await PAUSE_S1(); 
        
        const testObject = {a:1, b: 'test'}; 
        const result = JSON.stringify(testObject); // Chama a função (potencialmente sequestrada)
        
        if (result && result.includes('"hijacked": true')) { 
            logS1("VULN: Retorno da função JSON.stringify sequestrada verificado!", 'vuln', FNAME); 
            okR = true; 
        } else if (okH) { 
            // Se okH é true mas o retorno não é o esperado, algo aconteceu mas não como planejado
            logS1("AVISO: JSON.stringify sequestrado, mas retorno inesperado.", 'warn', FNAME); 
        } else { 
            logS1("JSON.stringify não foi sequestrado.", 'good', FNAME); 
        } 
    } catch (e) { 
        logS1(`Erro fatal durante Teste 6: ${e.message}`, 'error', FNAME); 
        console.error(e); 
    } finally { 
        // Restaura a função original JSON.stringify
        const currentStringify = JSON.stringify;
        JSON.stringify = origStringify; 
        if (currentStringify !== origStringify && JSON.stringify !== origStringify) { 
             // Isso não deveria acontecer se a restauração for bem-sucedida.
            logS1("ERRO CRÍTICO: FALHA ao restaurar JSON.stringify!", 'critical', FNAME); 
        } else if (JSON.stringify === origStringify) {
            logS1("JSON.stringify restaurado.", 'good', 'Cleanup');
        } else {
            logS1("AVISO: JSON.stringify pode não ter sido restaurado corretamente.", 'warn', 'Cleanup');
        }
    } 
    logS1(`--- Teste 6 Concluído (Hijack: ${okH}, Retorno Sequestrado: ${okR}, Leitura Leak OOB: ${okL}) ---`, 'test', FNAME); 
    return okR && okL; // Sucesso se o retorno foi sequestrado E o leak foi lido
}
