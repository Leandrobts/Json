// js/script1/testIndexedDB.mjs
import { logS1, PAUSE_S1 } from './s1_utils.mjs';

export async function testIndexedDBS1() {
    const FNAME = 'testIndexedDBS1'; 
    logS1("--- Iniciando Teste 9: IndexedDB ---", 'test', FNAME); 
    const dbName = "TestDB_S1_v19"; 
    const storeName = "TestStoreS1"; 
    let db = null; 
    let errorMsg = null; 
    let addOK = false; 
    let getOK = false; 
    let deleteOK = false; 
    let addComplexOK = false;
    
    // Tenta deletar o banco de dados antigo, se existir, para um teste limpo.
    try { 
        await new Promise((resolve, reject) => { 
            logS1("Tentando deletar DB antigo (se existir)...", 'info', FNAME); 
            const deleteRequest = indexedDB.deleteDatabase(dbName); 
            deleteRequest.onsuccess = () => { 
                logS1("DB antigo deletado ou não existia.", 'good', FNAME); 
                resolve(); 
            }; 
            deleteRequest.onerror = (e) => { 
                logS1(`Erro ao deletar DB antigo: ${e.target.error}`, 'warn', FNAME); 
                resolve(); // Resolve mesmo em erro para não bloquear o teste
            }; 
            deleteRequest.onblocked = () => { 
                logS1("Deleção do DB bloqueada (conexões abertas?). Tente recarregar.", 'warn', FNAME); 
                resolve(); // Resolve para não bloquear
            }; 
            setTimeout(() => {
                logS1("Timeout ao deletar DB antigo.", 'warn', FNAME);
                resolve(); // Resolve em timeout
            }, 3000); 
        }).catch(e => logS1(`Exceção na deleção prévia do DB: ${e.message}`, 'warn', FNAME)); 
    } catch(e) {
        logS1("Erro inesperado durante a tentativa de deleção prévia do DB.", 'warn', FNAME);
    }
            
    await PAUSE_S1(); // Pequena pausa após a tentativa de deleção
            
    try { 
        logS1("Abrindo/Criando IndexedDB...", 'info', FNAME); 
        db = await new Promise((resolve, reject) => { 
            const request = indexedDB.open(dbName, 1); // Versão 1 do DB
            
            request.onupgradeneeded = (event) => { 
                logS1("Evento onupgradeneeded disparado.", 'info', FNAME); 
                try { 
                    const dbInstance = event.target.result; 
                    if (!dbInstance.objectStoreNames.contains(storeName)) { 
                        logS1(`Criando object store: ${storeName}`, 'info', FNAME); 
                        dbInstance.createObjectStore(storeName, { keyPath: "id" }); 
                    } 
                } catch (e) { 
                    logS1(`Erro durante onupgradeneeded: ${e.message}`, 'error', FNAME); 
                    errorMsg = `Upgrade error: ${e.message}`; 
                    reject(e); 
                } 
            }; 
            
            request.onsuccess = (event) => { 
                logS1("IndexedDB aberto com sucesso.", 'good', FNAME); 
                resolve(event.target.result); 
            }; 
            
            request.onerror = (event) => { 
                logS1(`Erro ao abrir IndexedDB: ${event.target.error}`, 'error', FNAME); 
                errorMsg = `Open error: ${event.target.error}`; 
                reject(event.target.error); 
            }; 
            setTimeout(() => reject(new Error("Timeout abrindo DB (5s)")), 5000);
        });
        
        if (db) { 
            logS1("Testando adicionar registro simples...", 'info', FNAME); 
            const simpleId = "simple_" + Date.now();
            const addData = { id: simpleId, name: "TestDataS1", value: Math.random() }; 
            const addResult = await new Promise((resolve, reject) => { 
                try { 
                    const transaction = db.transaction([storeName], "readwrite"); 
                    const store = transaction.objectStore(storeName); 
                    const request = store.add(addData); 
                    request.onsuccess = (event) => { addOK = true; resolve(addData.id); }; 
                    request.onerror = (event) => reject(event.target.error); 
                    transaction.onerror = (event) => reject(event.target.error); 
                    transaction.onabort = (event) => reject(new Error(`Transação abortada (Add Simples): ${event.target.error ? event.target.error.name : 'N/A'}`));
                    setTimeout(() => reject(new Error("Timeout add simples (3s)")), 3000);
                } catch (e) { reject(e); } 
            }); 
            logS1(`Adicionar registro simples ${addOK ? 'OK' : 'FALHOU'}. ID: ${addResult}`, addOK ? 'good' : 'error', FNAME);
            
            if (addOK && addResult) { 
                logS1("Testando ler registro simples...", 'info', FNAME); 
                const getResult = await new Promise((resolve, reject) => { 
                    try { 
                        const transaction = db.transaction([storeName], "readonly"); 
                        const store = transaction.objectStore(storeName); 
                        const request = store.get(addResult); 
                        request.onsuccess = (event) => { getOK = (event.target.result != null); resolve(event.target.result); }; 
                        request.onerror = (event) => reject(event.target.error); 
                        transaction.onerror = (event) => reject(event.target.error); 
                        transaction.onabort = (event) => reject(new Error(`Transação abortada (Get Simples): ${event.target.error ? event.target.error.name : 'N/A'}`));
                        setTimeout(() => reject(new Error("Timeout get simples (3s)")), 3000);
                    } catch (e) { reject(e); } 
                }); 
                logS1(`Ler registro simples ${getOK ? 'OK' : 'FALHOU'}. Conteúdo: ${getResult ? JSON.stringify(getResult).substring(0,50)+'...' : 'N/A'}`, getOK ? 'good' : 'error', FNAME);
                
                if (getOK) { 
                    logS1("Testando deletar registro simples...", 'info', FNAME); 
                    await new Promise((resolve, reject) => { 
                        try { 
                            const transaction = db.transaction([storeName], "readwrite"); 
                            const store = transaction.objectStore(storeName); 
                            const request = store.delete(addResult); 
                            request.onsuccess = () => { deleteOK = true; }; 
                            transaction.oncomplete = resolve; // Resolve quando a transação completar
                            request.onerror = (event) => reject(event.target.error); 
                            transaction.onerror = (event) => reject(event.target.error); 
                            transaction.onabort = (event) => reject(new Error(`Transação abortada (Delete Simples): ${event.target.error ? event.target.error.name : 'N/A'}`));
                            setTimeout(() => reject(new Error("Timeout delete simples (3s)")), 3000);
                        } catch (e) { reject(e); } 
                    }); 
                    logS1(`Deletar registro simples ${deleteOK ? 'OK' : 'FALHOU'}.`, deleteOK ? 'good' : 'error', FNAME); 
                } 
            }
            
            logS1("Testando adicionar Blob e ArrayBuffer...", 'info', FNAME); 
            const blobData = new Blob(['Test Blob Data S1 - ' + Date.now()], {type: 'text/plain'}); 
            const bufferData = new Uint8Array([10, 20, 30, 40, Date.now() % 256]).buffer; 
            
            try { 
                await new Promise(async (resolve, reject) => { 
                    const transaction = db.transaction([storeName], "readwrite"); 
                    transaction.onerror = (event) => reject(event.target.error); 
                    transaction.onabort = (event) => reject(new Error(`Transação abortada (Add Complex): ${event.target.error ? event.target.error.name : 'N/A'}`)); 
                    transaction.oncomplete = resolve; 
                    const store = transaction.objectStore(storeName); 
                    store.put({ id: 'blob_test_s1', data: blobData }); 
                    store.put({ id: 'buffer_test_s1', data: bufferData }); 
                    setTimeout(() => reject(new Error("Timeout add complex (4s)")), 4000);
                }); 
                addComplexOK = true; 
                logS1("Adicionar/Put Blob e ArrayBuffer parece OK.", 'good', FNAME); 
            } catch(e) { 
                logS1(`Erro ao adicionar/put Blob/ArrayBuffer: ${e?.message || String(e)}`, 'error', FNAME); 
                errorMsg = errorMsg || `Add complex failed: ${e?.message || String(e)}`; 
            } 
        } else {
            logS1("Instância do DB não foi criada, pulando testes de CRUD.", "warn", FNAME);
        }
    } catch (e) { 
        logS1(`Erro GERAL no teste IndexedDB S1: ${e?.message || String(e)}`, 'error', FNAME); 
        if (!errorMsg) errorMsg = e?.message || String(e); 
        console.error("IndexedDB Error S1:", e); 
    } finally { 
        logS1("Fechando conexão IndexedDB (se aberta)...", 'info', FNAME); 
        try { if (db) db.close(); } catch (e) { /* ignore erros no close */ } 
        db = null; 
        logS1(`--- Teste 9 Concluído (Add Simples: ${addOK}, Get: ${getOK}, Del: ${deleteOK}, Add Complex: ${addComplexOK}, Erro Geral: ${!!errorMsg}) ---`, 'test', FNAME); 
    }
}
