// js/script3/testWebAssembly.mjs
import { logS3 } from './s3_utils.mjs';

export async function testWebAssemblyInterface() {
    const FNAME = "testWebAssemblyInterface";
    logS3("--- Iniciando Teste de Interface WebAssembly ---", "test", FNAME);
    if (typeof WebAssembly !== 'object') {
        logS3("WebAssembly API não suportada.", "warn", FNAME);
        logS3("--- Teste WebAssembly Concluído (Não Suportado) ---", "test", FNAME);
        return;
    }
    logS3("WebAssembly API disponível.", "good", FNAME);
    try {
        // Um módulo Wasm mínimo (faz um add)
        const wasmBytes = new Uint8Array([
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x07, 0x01, 0x60,
            0x02, 0x7f, 0x7f, 0x01, 0x7f, 0x03, 0x02, 0x01, 0x00, 0x07, 0x07, 0x01,
            0x03, 0x61, 0x64, 0x64, 0x00, 0x00, 0x0a, 0x09, 0x01, 0x07, 0x00, 0x20,
            0x00, 0x20, 0x01, 0x6a, 0x0b
        ]);
        const module = await WebAssembly.compile(wasmBytes);
        const instance = await WebAssembly.instantiate(module);
        const result = instance.exports.add(5, 3);
        if (result === 8) {
            logS3(`Instanciação e chamada de Wasm OK. add(5,3) = ${result}`, "good", FNAME);
        } else {
            logS3(`Chamada Wasm retornou valor inesperado: ${result}`, "warn", FNAME);
        }
    } catch (e) {
        logS3(`Erro durante teste WebAssembly: ${e.message}`, "error", FNAME);
        console.error("Wasm Error:", e);
    }
    logS3("--- Teste WebAssembly Concluído ---", "test", FNAME);
}
