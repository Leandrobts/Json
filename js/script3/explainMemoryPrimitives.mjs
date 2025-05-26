// js/script3/explainMemoryPrimitives.mjs
import { logS3 } from './s3_utils.mjs';
import { jscOffsets, AdvancedInt64, readWriteUtils } from '../utils.mjs'; // Para referenciar na explicação

export function explainMemoryPrimitives() {
    const FNAME = "explainMemoryPrimitives";
    logS3("--- Explicação: Primitivas de Memória (addrof, fakeobj) (S3) ---", "tool", FNAME);
    logS3("Estas são primitivas comuns em exploração de navegadores, tipicamente obtidas após explorar uma vulnerabilidade inicial (ex: OOB R/W).", "info", FNAME);
    logS3("`addrof(object)`: Retornaria o endereço de memória do objeto JavaScript fornecido.", "info", FNAME);
    logS3("`fakeobj(address)`: Criaria um objeto JavaScript 'falso' que aponta para o endereço de memória fornecido, permitindo tratar dados arbitrários na memória como se fossem um objeto JS.", "info", FNAME);
    logS3("Para implementar `addrof` real, você precisaria de uma forma de ler a memória onde as estruturas de objetos JS são armazenadas. Frequentemente, isso envolve corromper um ArrayBuffer ou DataView para apontar seu buffer interno para o objeto desejado e então ler seus metadados/ponteiros.", "info", FNAME);
    logS3("Para `fakeobj` real, seria o inverso: corromper um objeto JS (ou o buffer de um ArrayBuffer que depois é tratado como objeto) para que seus ponteiros internos apontem para um endereço arbitrário.", "info", FNAME);
    logS3(`Offsets úteis (JSC - exemplo de jscOffsets importado): js_butterfly (0x${jscOffsets.js_butterfly.toString(16)}), view_m_vector (0x${jscOffsets.view_m_vector.toString(16)} de um JSArrayBufferView).`, "info", FNAME);
    logS3("Esta suíte usa AdvancedInt64 para manipulação de endereços de 64 bits: new AdvancedInt64('0xHIGH_0xLOW') ou new AdvancedInt64(byteArray).", "info", FNAME);
    logS3(`Funções de Leitura/Escrita (simuladas aqui, mas mostram a ideia): readWriteUtils.read64(view, offset), readWriteUtils.write64(view, offset, int64Value). Ex: read32 disponível como readWriteUtils.read32.`, "info", FNAME);
    logS3("--- Fim da Explicação (S3) ---", "tool", FNAME);
}
