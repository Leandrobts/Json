// js/script1/testBasicPP.mjs
import { logS1, PAUSE_S1 } from './s1_utils.mjs';

export async function testBasicPPS1() {
    const FNAME = 'testBasicPPS1'; 
    logS1("--- Iniciando Teste 5: PP (Básica) ---", 'test', FNAME); 
    const prop = '__pp_basic__'; 
    const val = 'Polluted!'; 
    let ok = false; 
    let testObj = null; 
    
    try { 
        // Tenta poluir Object.prototype
        Object.prototype[prop] = val; 
        await PAUSE_S1(); 
        
        testObj = {}; // Cria um novo objeto
        const inheritedValue = testObj[prop]; // Verifica se ele herdou a propriedade poluída
        
        if (inheritedValue === val) { 
            logS1(`VULN: PP Básica OK! Objeto herdou a propriedade poluída.`, 'vuln', FNAME); 
            ok = true; 
        } else { 
            logS1(`PP Básica falhou ou não detectada. testObj[${prop}] = ${inheritedValue}`, 'good', FNAME); 
        } 
    } catch (e) { 
        logS1(`Erro durante teste PP Básico: ${e.message}`, 'error', FNAME); 
        console.error(e); 
    } finally { 
        // Limpa a poluição
        try { 
            delete Object.prototype[prop]; 
        } catch(e){ 
            logS1(`Erro ao limpar Object.prototype.${prop}: ${e.message}`, 'error', FNAME); 
        } 
    } 
    logS1(`--- Teste 5 Concluído (PP Básica ${ok ? 'OK' : 'Falhou'}) ---`, 'test', FNAME); 
    return ok;
}
