// js/script1/testCSPBypass.mjs
import { logS1, PAUSE_S1, SHORT_PAUSE_S1 } from './s1_utils.mjs';
import { getXssTargetDiv } from '../dom_elements.mjs';

export async function testCSPBypassS1() {
    const FNAME = 'testCSPBypassS1'; 
    logS1("--- Iniciando Teste 1: XSS Básico (Script 1) ---", 'test', FNAME);
    const xssTargetDiv = getXssTargetDiv();

    try { 
        const payloadJS = `try { document.getElementById('output').innerHTML += '<span class="log-vuln">[${new Date().toLocaleTimeString()}] [XSS Payload] Alerta data: URI executado!</span>\\n'; alert('XSS S1 via Data URI!'); } catch(e) { document.getElementById('output').innerHTML += '<span class="log-good">[${new Date().toLocaleTimeString()}] [XSS Payload] Alerta data: URI bloqueado: ' + e.message + '</span>\\n'; }`; 
        const encodedPayload = btoa(payloadJS); 
        const scriptTag = document.createElement('script'); 
        scriptTag.src = 'data:text/javascript;base64,' + encodedPayload; 
        scriptTag.onerror = (e) => { logS1(`ERRO: Falha carregar script data: URI! Event: ${e.type}`, 'error', FNAME); }; 
        document.body.appendChild(scriptTag); 
        await PAUSE_S1(SHORT_PAUSE_S1 * 2); 
        document.body.removeChild(scriptTag); 
    } catch (e) { 
        logS1(`Erro ao criar/adicionar script data: URI: ${e.message}`, 'error', FNAME); 
    }
    
    await PAUSE_S1();
    
    try { 
        const imgTag = document.createElement('img'); 
        const imgSrc = 'invalid_img_' + Date.now(); 
        imgTag.src = imgSrc; 
        const onerrorPayload = ` try { const target = document.getElementById('xss-target-div'); if (target) { target.innerHTML += '<br><span class="log-vuln">XSS S1 DOM via ONERROR Executado!</span>'; document.getElementById('output').innerHTML += '<span class="log-vuln">[${new Date().toLocaleTimeString()}] [ONERROR Payload] XSS DOM via onerror OK!</span>\\n'; } else { document.getElementById('output').innerHTML += '<span class="log-error">[${new Date().toLocaleTimeString()}] [ONERROR Payload] Alvo XSS DOM não encontrado.</span>\\n'; } alert('XSS_S1_DOM_ONERROR'); } catch(e) { document.getElementById('output').innerHTML += '<span class="log-warn">[${new Date().toLocaleTimeString()}] [ONERROR Payload] Erro payload onerror: ' + e.message + '</span>\\n'; } `; 
        imgTag.setAttribute('onerror', onerrorPayload); 
        document.body.appendChild(imgTag); 
        await PAUSE_S1(SHORT_PAUSE_S1 * 2); 
        document.body.removeChild(imgTag); 
    } catch (e) { 
        logS1(`Erro ao criar/adicionar img onerror: ${e.message}`, 'error', FNAME); 
    }
    
    await PAUSE_S1();
    
    if (xssTargetDiv) {
        try { 
            const link = document.createElement('a'); 
            link.href = "javascript:try{document.getElementById('output').innerHTML += '<span class=\"log-vuln\">[${new Date().toLocaleTimeString()}] [XSS Payload JS Href] Executado!</span>\\n'; alert('XSS S1 via JS Href!');}catch(e){document.getElementById('output').innerHTML += '<span class=\"log-good\">[${new Date().toLocaleTimeString()}] [XSS Payload JS Href] Bloqueado: '+e.message+'</span>\\n';}"; 
            link.textContent = "[Test Link JS Href - Clique Manual]"; 
            link.style.display = 'block'; 
            link.style.color = 'cyan'; 
            xssTargetDiv.appendChild(link); 
            logS1("Adicionado link javascript: href para teste manual.", 'info', FNAME); 
        } catch(e) { 
            logS1(`Erro ao criar link js: href: ${e.message}`, 'error', FNAME); 
        }
    } else {
        logS1("Elemento xss-target-div não encontrado para link JS Href.", "warn", FNAME);
    }
    logS1("--- Teste 1 Concluído ---", 'test', FNAME);
}
