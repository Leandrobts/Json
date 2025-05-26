// js/script1/testWebWorkers.mjs
import { logS1, PAUSE_S1 } from './s1_utils.mjs';

export async function testWebWorkersS1() {
    const FNAME = 'testWebWorkersS1'; 
    logS1("--- Iniciando Teste 8: Web Workers ---", 'test', FNAME); 
    let worker = null; 
    let workerReplied = false; 
    let workerError = false; 
    let ppDetectedWorker = false; 
    const ppPropWorker = '__worker_polluted__'; 
    
    // Tenta poluir Object.prototype para ver se afeta o Worker ou sua comunicação
    Object.prototype[ppPropWorker] = 'Worker Polluted!'; 
    
    // Código que será executado dentro do Web Worker
    const workerCode = ` 
        self.onmessage = function(e) { 
            let response = 'Worker S1 received: ' + e.data; 
            try { 
                // Verifica se a poluição do protótipo é visível DENTRO do worker
                if (self.${ppPropWorker} === 'Worker Polluted!') { 
                    response += ' [PP Detected INSIDE Worker!]'; 
                } 
            } catch(err) {} 
            self.postMessage(response); 
        }; 
        try { 
            // Verifica a poluição no escopo global do worker ao iniciar
            if (self.${ppPropWorker} === 'Worker Polluted!') { 
                self.postMessage('PP Detected on Worker Self at startup S1!'); 
            } 
        } catch(e){} 
    `; 
    
    const workerPromise = new Promise((resolve, reject) => { 
        try { 
            const blob = new Blob([workerCode], { type: 'application/javascript' }); 
            const blobUrl = URL.createObjectURL(blob); 
            worker = new Worker(blobUrl); 
            
            try { 
                // Verifica se a poluição do protótipo afeta a instância do Worker no thread principal
                if (worker && worker[ppPropWorker] === 'Worker Polluted!') { 
                    logS1(`VULN: PP afetou instância Worker no main thread ('${ppPropWorker}')!`, 'vuln', FNAME); 
                    // Nota: ppDetectedWorker é para PP DENTRO do worker, esta é uma detecção diferente.
                } 
            } catch(e){
                 logS1(`Erro ao checar propriedade poluída na instância Worker: ${e.message}`, 'warn', FNAME);
            }
            
            worker.onmessage = (event) => { 
                logS1(`Mensagem do Worker S1: "${event.data}"`, 'good', FNAME); 
                if (String(event.data).includes('PP Detected')) { 
                    logS1(`VULN: PP detectada DENTRO do worker ou na comunicação!`, 'vuln', FNAME); 
                    ppDetectedWorker = true; 
                } 
                workerReplied = true; 
                resolve(); 
            }; 
            
            worker.onerror = (event) => { 
                logS1(`Erro no Worker S1: ${event.message} em ${event.filename}:${event.lineno}`, 'error', FNAME); 
                workerError = true; 
                reject(event.error || new Error(event.message || "Worker error S1")); 
            }; 
            
            worker.postMessage("Hello Worker S1 from main thread " + Date.now()); 
            
            // Timeout para a resposta do worker
            setTimeout(() => { 
                if (!workerReplied) { 
                    workerError = true; 
                    reject(new Error("Worker S1 timeout (5s)")); 
                } 
            }, 5000); 
            
            URL.revokeObjectURL(blobUrl); // Libera o URL do blob
        } catch (e) { 
            logS1(`Erro CRÍTICO ao criar/comunicar com Worker S1: ${e.message}`, 'critical', FNAME); 
            workerError = true; 
            console.error(e); 
            reject(e); 
        } finally {
            // Limpa a poluição do protótipo independentemente do resultado da promessa
            // para evitar que afete outros testes.
            delete Object.prototype[ppPropWorker];
        }
    }); 
    
    try { 
        await workerPromise; 
    } catch(e) { 
        // Erros já são logados pelos handlers ou pelo catch do new Promise
         if (!workerError) { // Loga se o erro não foi de um evento específico
            logS1(`Falha na promessa Worker S1: ${e.message}`, 'error', FNAME);
        }
    } finally { 
        try { 
            if (worker) worker.terminate(); // Termina o worker
        } catch(e) { /* ignore erros no terminate */ } 
        worker = null; 
        // Garante que a poluição foi limpa
        if (Object.prototype.hasOwnProperty(ppPropWorker)) {
             delete Object.prototype[ppPropWorker];
             logS1(`Propriedade poluída ${ppPropWorker} limpa no finally.`, 'info', 'Cleanup');
        }
        logS1(`--- Teste 8 Concluído (Resposta OK: ${workerReplied}, Erro: ${workerError}, PP Dentro/Via Worker: ${ppDetectedWorker}) ---`, 'test', FNAME); 
    }
}
