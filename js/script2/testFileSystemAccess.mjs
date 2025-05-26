// js/script2/testFileSystemAccess.mjs
import { logS2, PAUSE_S2, MEDIUM_PAUSE_S2 } from './s2_utils.mjs';

export async function testFileSystemAccessS2() {
    const FNAME = 'testFileSystemAccessS2'; 
    logS2("--- Teste: File System Access API Check (S2) ---", 'test', FNAME); 
    let apiAvailable = false; 
    let openFilePickerCalled = false; 
    let saveFilePickerCalled = false; 
    let dirPickerCalled = false; 
    let errorMsg = null; 
    
    if (typeof window.showOpenFilePicker === 'function') { 
        logS2("API showOpenFilePicker disponível.", 'good', FNAME); 
        apiAvailable = true; 
        try { 
            // A chamada real abrirá um seletor de arquivos, que o usuário provavelmente cancelará.
            // O teste é para ver se a API existe e pode ser chamada sem erro síncrono.
            window.showOpenFilePicker().then(handles => { 
                logS2("showOpenFilePicker resolvido (provavelmente cancelado pelo usuário ou arquivo selecionado).", 'vuln', FNAME); 
            }).catch(err => { 
                logS2(`showOpenFilePicker rejeitado: ${err.name} - ${err.message}`, err.name === 'AbortError' ? 'good' : 'warn', FNAME); 
            }); 
            openFilePickerCalled = true; 
            await PAUSE_S2(100); // Pausa para permitir que o seletor apareça/seja cancelado
        } catch (e) { 
            logS2(`Erro síncrono ao chamar showOpenFilePicker: ${e.message}`, 'error', FNAME); 
            errorMsg = e.message; 
        } 
    } else { 
        logS2("API showOpenFilePicker NÃO disponível.", 'good', FNAME); 
    } 
    
    await PAUSE_S2(MEDIUM_PAUSE_S2); // Pausa entre as verificações de API
    
    if (typeof window.showSaveFilePicker === 'function') { 
        logS2("API showSaveFilePicker disponível.", 'good', FNAME); 
        apiAvailable = true; 
        try { 
            window.showSaveFilePicker().then(handle => { 
                logS2("showSaveFilePicker resolvido (provavelmente cancelado pelo usuário ou arquivo salvo).", 'vuln', FNAME); 
            }).catch(err => { 
                logS2(`showSaveFilePicker rejeitado: ${err.name} - ${err.message}`, err.name === 'AbortError' ? 'good' : 'warn', FNAME); 
            }); 
            saveFilePickerCalled = true; 
            await PAUSE_S2(100); 
        } catch (e) { 
            logS2(`Erro síncrono ao chamar showSaveFilePicker: ${e.message}`, 'error', FNAME); 
            if (!errorMsg) errorMsg = e.message; 
        } 
    } else { 
        logS2("API showSaveFilePicker NÃO disponível.", 'good', FNAME); 
    } 
    
    await PAUSE_S2(MEDIUM_PAUSE_S2); 
    
    if (typeof window.showDirectoryPicker === 'function') { 
        logS2("API showDirectoryPicker disponível.", 'good', FNAME); 
        apiAvailable = true; 
        try { 
            window.showDirectoryPicker().then(handle => { 
                logS2("showDirectoryPicker resolvido (provavelmente cancelado pelo usuário ou diretório selecionado).", 'vuln', FNAME); 
            }).catch(err => { 
                logS2(`showDirectoryPicker rejeitado: ${err.name} - ${err.message}`, err.name === 'AbortError' ? 'good' : 'warn', FNAME); 
            }); 
            dirPickerCalled = true; 
            await PAUSE_S2(100); 
        } catch (e) { 
            logS2(`Erro síncrono ao chamar showDirectoryPicker: ${e.message}`, 'error', FNAME); 
            if (!errorMsg) errorMsg = e.message; 
        } 
    } else { 
        logS2("API showDirectoryPicker NÃO disponível.", 'good', FNAME); 
    } 
    
    if (!apiAvailable) { 
        logS2("Nenhuma API File System Access principal disponível.", 'good', FNAME); 
    } else if (errorMsg) { 
        logS2(`Erro encontrado ao chamar APIs File System Access: ${errorMsg}`, 'error', FNAME); 
    } else if (openFilePickerCalled || saveFilePickerCalled || dirPickerCalled) {
        logS2("Chamadas às APIs File System Access realizadas (rejeições são normais se o usuário cancelar os seletores).", 'good', FNAME); 
    } else {
        logS2("APIs File System Access parecem disponíveis, mas nenhuma chamada foi executada com sucesso.", 'warn', FNAME);
    }
    
    logS2(`--- Teste File System Access S2 Concluído (Disponível: ${apiAvailable}, Chamadas: Open-${openFilePickerCalled}/Save-${saveFilePickerCalled}/Dir-${dirPickerCalled}) ---`, 'test', FNAME); 
    await PAUSE_S2();
}
