// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Importa a nova função de teste
import { executeRevisitForInRangeErrorTest } from './testInvestigateForInRCE.mjs'; // Mantém o nome do arquivo, mas a função interna mudou

async function runRevisitRangeErrorStrategy() {
    const FNAME_RUNNER = "runRevisitRangeErrorStrategy";
    logS3(`==== INICIANDO Estratégia de Reinvestigação do RangeError com for...in (Instrumentado) ====`, 'test', FNAME_RUNNER);

    const result = await executeRevisitForInRangeErrorTest();

    if (result && result.setupError) {
        logS3(`   Falha na configuração do teste: ${result.setupError.message}.`, "error", FNAME_RUNNER);
    } else if (result && result.stringifyError && result.stringifyError.name === 'RangeError') {
        logS3(`   !!!!!! RangeError REPRODUZIDO no objeto ${result.targetObjectId} !!!!!!`, "critical", FNAME_RUNNER);
    } else if (result && result.stringifyError) {
        logS3(`   Outro erro (${result.stringifyError.name}) ocorreu no objeto ${result.targetObjectId}.`, "error", FNAME_RUNNER);
    } else if (result && result.toJSONReturn && result.toJSONReturn.internal_error){
        logS3(`   Erro interno capturado pela toJSON no objeto ${result.targetObjectId}: ${result.toJSONReturn.internal_error}`, "warn", FNAME_RUNNER);
    } else {
        logS3(`   Teste completou sem RangeError ou erro interno óbvio no objeto ${result.targetObjectId}.`, "good", FNAME_RUNNER);
    }

    logS3(`==== Estratégia de Reinvestigação do RangeError CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_RevisitForInRangeError';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Reinvestigação do RangeError com for...in (Instrumentado) ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - Revisit ForIn RangeError";

    await runRevisitRangeErrorStrategy();

    logS3(`\n==== Script 3 CONCLUÍDO (Revisit ForIn RangeError) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes("CONGELOU?")) {
        // Manter
    } else if (document.title.includes("RangeError") || document.title.includes("ERRO") || document.title.includes("CRASH")) {
        // Manter títulos que indicam resultados específicos
    }
    else {
        document.title = "Script 3 Concluído - Revisit ForIn RangeError";
    }
}
