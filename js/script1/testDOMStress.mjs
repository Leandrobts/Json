// js/script1/testDOMStress.mjs
import { logS1, PAUSE_S1 } from './s1_utils.mjs';
// Não depende de state.mjs
// Usa document diretamente, o que é ok para scripts do lado do cliente.

export async function testDOMStressS1() {
    const FNAME = 'testDOMStressS1'; 
    logS1("--- Iniciando Teste 10: DOM Stress ---", 'test', FNAME); 
    const container = document.body; // Pode ser um div específico se preferir
    const elementCount = 200; // Número de elementos a criar/remover por ciclo
    const cycles = 5; // Número de ciclos de stress
    let errors = 0; 
    
    logS1(`Iniciando ${cycles} ciclos de stress com ${elementCount} elementos cada...`, 'info', FNAME); 
    
    try { 
        for (let c = 0; c < cycles; c++) { 
            logS1(`Ciclo ${c + 1}/${cycles}...`, 'info', FNAME); 
            const elements = []; 
            for (let i = 0; i < elementCount; i++) { 
                try { 
                    const el = document.createElement('div'); 
                    el.textContent = `StressS1-${c}-${i}`; 
                    el.style.position = 'absolute'; // Para evitar reflows massivos
                    el.style.left = `${(i * 5) % 300}px`; 
                    // Posiciona fora da tela para minimizar impacto visual e de renderização
                    el.style.top = `-${10 + (c*20) + i*2}px`; 
                    el.style.color = `rgb(${Math.floor(Math.random()*255)},${Math.floor(Math.random()*255)},${Math.floor(Math.random()*255)})`; 
                    container.appendChild(el); 
                    elements.push(el); 
                } catch (e) { 
                    errors++; 
                    logS1(`Erro ao criar/adicionar elemento ${i} no ciclo ${c+1}: ${e.message}`, 'warn', FNAME); 
                } 
            } 
            
            await PAUSE_S1(50); // Pausa curta para permitir que o DOM processe
            
            elements.forEach(el => { 
                try { 
                    container.removeChild(el); 
                } catch(e) { 
                    // Pode acontecer se o elemento já foi removido por algum motivo
                    errors++; 
                    logS1(`Erro ao remover elemento no ciclo ${c+1}: ${e.message}`, 'warn', FNAME);
                } 
            }); 
            await PAUSE_S1(10); // Pausa curta entre ciclos
        } 
        logS1("Ciclos de stress DOM concluídos.", 'good', FNAME); 
    } catch (e) { 
        logS1(`Erro GERAL durante DOM Stress S1: ${e.message}`, 'error', FNAME); 
        errors++; 
        console.error("DOM Stress Error S1:", e); 
    } finally { 
        logS1(`--- Teste 10 Concluído (Erros reportados: ${errors}) ---`, 'test', FNAME); 
    }
}
