// js/script2/testWebGLCheck.mjs
import { logS2, PAUSE_S2 } from './s2_utils.mjs';
import { getInteractiveCanvasS2 } from '../dom_elements.mjs';
import { setGlContextS2, getGlContextS2 as getStateGlContext, getIsWebGL2S2 as getStateIsWebGL2 } from '../state.mjs';

export async function testWebGLCheckS2() {
    const FNAME = 'testWebGLCheckS2'; 
    logS2("--- Teste: Verificação WebGL ---",'test', FNAME); 
    
    const canvasElementS2 = getInteractiveCanvasS2();
    if (!canvasElementS2) {
        logS2("Elemento Canvas S2 não encontrado!", "error", FNAME);
        setGlContextS2(null, false); // Atualiza o estado global
        return;
    }

    let glContext = null; 
    let isWebGL2 = false; 
    
    try { 
        glContext = canvasElementS2.getContext('webgl') || canvasElementS2.getContext('experimental-webgl'); 
        if(glContext){ 
            const glVersion = glContext.getParameter(glContext.VERSION); 
            logS2(`WebGL OK! V:${String(glVersion).substring(0,30)}`, 'good', FNAME); 
            try { 
                let gl2 = canvasElementS2.getContext('webgl2'); 
                if(gl2){ 
                    const gl2Version = gl2.getParameter(gl2.VERSION); 
                    logS2(`WebGL2 OK! V:${String(gl2Version).substring(0,30)}`, 'good', FNAME); 
                    isWebGL2 = true; 
                    glContext = gl2; 
                } else { 
                    logS2("WebGL2 não disponível.", 'good', FNAME); 
                } 
            } catch(e2){ 
                logS2("WebGL2 não disponível (erro check).", 'good', FNAME); 
            } 
        } else { 
            logS2('WebGL N/A.', 'good', FNAME); 
        } 
    } catch(e){ 
        logS2(`Erro ao verificar WebGL: ${e.message}`, 'error', FNAME); 
        console.error(e); 
        glContext = null; 
        isWebGL2 = false;
    } 
    
    setGlContextS2(glContext, isWebGL2); // Atualiza o estado global
    
    logS2(`--- Teste Verificação WebGL Concluído (Ativo: ${!!getStateGlContext()}, WebGL2: ${getStateIsWebGL2()}) ---`, 'test', FNAME); 
    await PAUSE_S2();
}
