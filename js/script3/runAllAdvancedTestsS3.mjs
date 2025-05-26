// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';

import { testWebAssemblyInterface } from './testWebAssemblyInterface.mjs';
import { testSharedArrayBufferSupport } from './testSharedArrayBufferSupport.mjs';
import { explainMemoryPrimitives } from './explainMemoryPrimitives.mjs';
import { testJsonTypeConfusionUAFSpeculative } from './testJsonTypeConfusionUAFSpeculative.mjs';
import { testCoreExploitModule } from '../core_exploit.mjs'; // Teste do próprio core_exploit
import { testCorruptArrayBufferStructure } from './testCorruptArrayBufferStructure.mjs'; // << ADICIONADO NA RESPOSTA ANTERIOR


export async function runAllAdvancedTestsS3() { // << ESTA É A LINHA 13 (contando comentários e linhas em branco no topo)
    const FNAME = 'runAllAdvancedTestsS3_Modular';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3("==== INICIANDO Script 3: Testes Avançados Automatizados (v19.0 - Modular) ====", 'test', FNAME);

    await testWebAssemblyInterface();
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    await testSharedArrayBufferSupport();
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    explainMemoryPrimitives();
    await PAUSE_S3(SHORT_PAUSE_S3);

    await testJsonTypeConfusionUAFSpeculative();
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    await testCorruptArrayBufferStructure(); // Adicionado
    await PAUSE_S3(MEDIUM_PAUSE_S3);

    await testCoreExploitModule(logS3); // Passa logS3 como função de log
    await PAUSE_S3(MEDIUM_PAUSE_S3);


    logS3("\n==== Script 3 CONCLUÍDO (Testes Automáticos - Modular) ====", 'test', FNAME);
    if (runBtn) runBtn.disabled = false;
}
