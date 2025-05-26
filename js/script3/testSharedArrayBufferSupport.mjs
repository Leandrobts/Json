// js/script3/testSharedArrayBufferSupport.mjs
import { logS3 } from './s3_utils.mjs';

export async function testSharedArrayBufferSupport() {
    const FNAME = "testSharedArrayBufferSupport";
    logS3("--- Iniciando Teste de SharedArrayBuffer (S3) ---", "test", FNAME);
    if (typeof SharedArrayBuffer === 'undefined') {
        logS3("SharedArrayBuffer não suportado ou desabilitado (requer COOP/COEP).", "warn", FNAME);
        logS3("Verifique os cabeçalhos Cross-Origin-Opener-Policy (COOP) e Cross-Origin-Embedder-Policy (COEP).", "info", FNAME);
    } else {
        logS3("SharedArrayBuffer suportado.", "good", FNAME);
        try {
            const sab = new SharedArrayBuffer(16); // Cria um SAB de 16 bytes
            logS3(`SharedArrayBuffer de ${sab.byteLength} bytes criado com sucesso.`, "good", FNAME);
            const i32a = new Int32Array(sab);
            Atomics.store(i32a, 0, 123); // Escreve atomicamente
            const loadedVal = Atomics.load(i32a, 0); // Lê atomicamente
            if (loadedVal === 123) {
                logS3(`Atomics.store/load em SharedArrayBuffer OK. (Valor: ${loadedVal})`, "good", FNAME);
            } else {
                logS3(`Atomics.store/load em SharedArrayBuffer falhou. Esperado: 123, Lido: ${loadedVal}`, "error", FNAME);
            }
        } catch (e) {
            logS3(`Erro ao usar SharedArrayBuffer/Atomics (S3): ${e.message}`, "error", FNAME);
             if (e.name === 'ReferenceError' && e.message.includes("Atomics")) {
                logS3("Atomics API parece não estar disponível, mesmo com SharedArrayBuffer presente.", "warn", FNAME);
            }
        }
    }
    logS3("--- Teste SharedArrayBuffer (S3) Concluído ---", "test", FNAME);
}
