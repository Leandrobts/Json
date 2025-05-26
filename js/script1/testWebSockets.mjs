// js/script1/testWebSockets.mjs
import { logS1, PAUSE_S1 } from './s1_utils.mjs';

export async function testWebSocketsS1() {
    const FNAME = 'testWebSocketsS1'; 
    logS1("--- Iniciando Teste 7: WebSockets ---", 'test', FNAME); 
    const wsUrl = "wss://websocket-echo.com/"; // URL de um servidor WebSocket de eco público
    let ws = null; 
    let connected = false; 
    let messageReceived = false; 
    let errorOccurred = false; 
    const ppProp = '__ws_polluted__'; 
    let ppDetected = false;
    
    // Testa se a poluição de protótipo afeta instâncias de WebSocket
    Object.prototype[ppProp] = 'WS Polluted!'; 
    
    const connectionPromise = new Promise((resolve, reject) => { 
        try { 
            ws = new WebSocket(wsUrl); 
            
            try { 
                if (ws && ws[ppProp] === 'WS Polluted!') { 
                    logS1(`VULN: PP afetou instância WebSocket ('${ppProp}')!`, 'vuln', FNAME); 
                    ppDetected = true; 
                } 
            } catch(e){
                logS1(`Erro ao checar propriedade poluída em WebSocket: ${e.message}`, 'warn', FNAME);
            }
            // Limpa a poluição de protótipo imediatamente após o teste
            delete Object.prototype[ppProp]; 
            
            ws.onopen = (event) => { 
                logS1("WebSocket Conectado!", 'good', FNAME); 
                connected = true; 
                try { 
                    const testMsg = "Hello WebSocket Test " + Date.now(); 
                    ws.send(testMsg); 
                    // Tenta enviar outros tipos de dados
                    try { ws.send(new Blob(["blob data test S1"])); } catch(e) { logS1(`Erro ao enviar Blob: ${e.message}`, 'warn', FNAME); } 
                    try { ws.send(new ArrayBuffer(16)); } catch(e) { logS1(`Erro ao enviar ArrayBuffer: ${e.message}`, 'warn', FNAME); } 
                    try { 
                        const largeSize = 1 * 1024 * 1024; // 1MB
                        const largeBuffer = new Uint8Array(largeSize).fill(0x41); 
                        ws.send(largeBuffer); 
                        logS1("Enviado buffer grande (1MB) via WebSocket.", 'info', FNAME);
                    } catch(e) { 
                        logS1(`Erro ao enviar buffer grande: ${e.message}`, 'warn', FNAME); 
                    } 
                } catch (e) { 
                    logS1(`Erro ao enviar mensagem WebSocket: ${e.message}`, 'error', FNAME); 
                    errorOccurred = true; 
                    reject(e); 
                } 
            }; 
            
            ws.onmessage = (event) => { 
                logS1(`Mensagem recebida do WebSocket: ${String(event.data).substring(0, 100)}${String(event.data).length > 100 ? '...' : ''}`, 'good', FNAME); 
                messageReceived = true; 
                if (ws && ws.readyState === WebSocket.OPEN) { 
                    ws.close(1000, "Test Completed S1"); 
                } 
                resolve(); 
            }; 
            
            ws.onerror = (event) => { 
                // O evento de erro em si pode não ter muitos detalhes, tipo 'error'
                logS1(`Erro no WebSocket: Tipo de evento - ${event.type}`, 'error', FNAME); 
                errorOccurred = true; 
                reject(new Error("WebSocket onerror triggered")); 
            }; 
            
            ws.onclose = (event) => { 
                logS1(`WebSocket Fechado. Código: ${event.code}, Razão: "${event.reason}", Limpo: ${event.wasClean}`, event.wasClean ? 'good' : 'warn', FNAME); 
                if (!connected && !errorOccurred && !messageReceived) { // Se fechou antes de qualquer coisa
                     reject(new Error("WebSocket fechado prematuramente."));
                } else {
                    resolve(); // Resolve mesmo se fechou após conexão/mensagem ou com erro já tratado
                }
            }; 
            
            // Timeout para a conexão/comunicação
            setTimeout(() => { 
                if (!connected || !messageReceived) { 
                    try { if (ws && ws.readyState !== WebSocket.CLOSED && ws.readyState !== WebSocket.CLOSING) ws.close(1001, "Timeout S1"); } catch(e){} 
                    reject(new Error("WebSocket timeout (10s)")); 
                } 
            }, 10000); 
            
        } catch (e) { 
            logS1(`Erro CRÍTICO ao criar WebSocket: ${e.message}`, 'critical', FNAME); 
            errorOccurred = true; 
            console.error(e); 
            // Limpa a poluição em caso de erro na criação também
            delete Object.prototype[ppProp];
            reject(e); 
        } 
    }); 
    
    try { 
        await connectionPromise; 
    } catch(e) { 
        // Erros já são logados pelos handlers ou pelo catch do new Promise
        if (!errorOccurred) { // Loga se o erro não foi de um evento específico
            logS1(`Falha na promessa WebSocket: ${e.message}`, 'error', FNAME);
        }
    } finally { 
        try { 
            if (ws && ws.readyState !== WebSocket.CLOSED) {
                ws.close(1000, "Cleanup S1"); 
            }
        } catch (e) { /* ignore erros no cleanup */ } 
        ws = null; 
        // Garante que a poluição foi limpa
        if (Object.prototype.hasOwnProperty(ppProp)) {
            delete Object.prototype[ppProp];
            logS1(`Propriedade poluída ${ppProp} limpa no finally.`, 'info', 'Cleanup');
        }
        logS1(`--- Teste 7 Concluído (Conectado: ${connected}, Msg OK: ${messageReceived}, Erro: ${errorOccurred}, PP Detectado: ${ppDetected}) ---`, 'test', FNAME); 
    }
}
