// js/script2/testWebGPUCheck.mjs
import { logS2, PAUSE_S2 } from './s2_utils.mjs';
import { setGpuAdapterS2, setGpuDeviceS2, getGpuDeviceS2 as getStateGpuDevice } from '../state.mjs'; // Para armazenar o adaptador e dispositivo

export async function testWebGPUCheckS2() {
    const FNAME = 'testWebGPUCheckS2'; 
    logS2("--- Teste: WebGPU Check (S2) ---", 'test', FNAME); 
    let adapterOK = false; 
    let deviceOK = false; 
    let errorMsg = null; 
    
    // Limpa o estado anterior
    setGpuAdapterS2(null);
    setGpuDeviceS2(null);

    if (!navigator.gpu) { 
        logS2("WebGPU API (navigator.gpu) NÃO disponível.", 'good', FNAME); 
        logS2(`--- Teste WebGPU S2 Concluído (API Não Disponível) ---`, 'test', FNAME); 
        await PAUSE_S2(); 
        return; 
    } 
    logS2("WebGPU API (navigator.gpu) disponível.", 'good', FNAME); 
    
    try { 
        const adapter = await navigator.gpu.requestAdapter(); 
        setGpuAdapterS2(adapter); // Armazena no estado

        if (adapter) { 
            logS2(`Adaptador GPU obtido: ${adapter.name || 'Nome N/A (Pode ser normal em alguns navegadores/SO)'}`, 'good', FNAME); 
            // Informações adicionais sobre o adaptador (opcional)
            // if (adapter.features && adapter.features.size > 0) {
            //     logS2(`  Features: ${Array.from(adapter.features).join(', ')}`, 'info', FNAME);
            // }
            // if (adapter.limits) {
            //     logS2(`  Max Texture Dimension 2D: ${adapter.limits.maxTextureDimension2D}`, 'info', FNAME);
            // }
            adapterOK = true; 
            
            try { 
                const device = await adapter.requestDevice(); 
                setGpuDeviceS2(device); // Armazena no estado

                if (device) { 
                    logS2("Dispositivo GPU obtido.", 'good', FNAME); 
                    deviceOK = true; 
                    
                    // Listener para erros não capturados no dispositivo
                    device.addEventListener('uncapturederror', (event) => { 
                        logS2(`--> ERRO WebGPU não capturado: ${event.error.message}`, 'critical', FNAME); 
                        console.error("WebGPU Uncaptured Error:", event.error); 
                    }); 
                    
                    // Listener para quando o dispositivo é perdido
                    device.lost.then((info) => { 
                        logS2(`--> Dispositivo WebGPU PERDIDO! Razão: ${info.reason}. Mensagem: ${info.message}`, info.reason === 'destroyed' ? 'warn' : 'critical', FNAME); 
                        setGpuDeviceS2(null); // Limpa do estado
                    }).catch(err => {
                        logS2(`Erro ao processar 'device.lost': ${err.message}`, 'error', FNAME);
                    });
                    
                    // Tenta criar um buffer simples para verificar a funcionalidade básica
                    try { 
                        const buffer = device.createBuffer({ 
                            size: 16, 
                            usage: GPUBufferUsage.MAP_READ | GPUBufferUsage.COPY_DST 
                        }); 
                        logS2("Buffer WebGPU (16 bytes) criado com sucesso.", 'good', FNAME); 
                        buffer.destroy(); // Limpa o buffer
                        logS2("Buffer WebGPU destruído.", 'info', FNAME);
                    } catch(bufferError) { 
                        logS2(`Erro ao criar/destruir buffer WebGPU: ${bufferError.message}`, 'error', FNAME); 
                    } 
                    
                } else { 
                    logS2("Falha ao obter dispositivo GPU (requestDevice retornou null).", 'error', FNAME); 
                    errorMsg = "requestDevice retornou null"; 
                } 
            } catch (deviceError) { 
                logS2(`Erro ao requisitar dispositivo GPU: ${deviceError.message}`, 'error', FNAME); 
                errorMsg = deviceError.message; 
                console.error(deviceError); 
            } 
        } else { 
            logS2("Falha ao obter adaptador GPU (requestAdapter retornou null).", 'warn', FNAME); 
            errorMsg = "requestAdapter retornou null"; 
        } 
    } catch (adapterError) { 
        logS2(`Erro ao requisitar adaptador GPU: ${adapterError.message}`, 'error', FNAME); 
        errorMsg = adapterError.message; 
        console.error(adapterError); 
    } 
    
    logS2(`--- Teste WebGPU S2 Concluído (Adaptador: ${adapterOK}, Dispositivo: ${deviceOK}, Erro: ${!!errorMsg}) ---`, 'test', FNAME); 
    await PAUSE_S2();
}
