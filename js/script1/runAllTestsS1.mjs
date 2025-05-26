// js/script1/runAllTestsS1.mjs
import { logS1, PAUSE_S1, MEDIUM_PAUSE_S1 } from './s1_utils.mjs';
import { getOutputDivS1, getRunBtnS1 } from '../dom_elements.mjs';

// Importar todas as funções de teste do Script 1
import { testCSPBypassS1 } from './testCSPBypass.mjs';
import { testOOBReadInfoLeakEnhancedStoreS1 } from './testOOBReadInfoLeak.mjs';
// Substitua os caminhos abaixo pelos nomes corretos dos arquivos se você os criou
import { testOOBUAFPatternS1 } from './testOOBUAFPattern.mjs'; // Exemplo, crie este arquivo
import { testOOBOtherTypesS1 } from './testOOBOtherTypes.mjs'; // Exemplo
import { testBasicPPS1 } from './testBasicPP.mjs'; // Exemplo
import { testPPJsonHijackS1 } from './testPPJsonHijack.mjs'; // Exemplo
import { testWebSocketsS1 } from './testWebSockets.mjs'; // Exemplo
import { testWebWorkersS1 } from './testWebWorkers.mjs'; // Exemplo
import { testIndexedDBS1 } from './testIndexedDB.mjs'; // Exemplo
import { testDOMStressS1 } from './testDOMStress.mjs'; // Exemplo


export async function runAllTestsS1() {
    const FNAME = 'runAllTestsS1';
    const runBtn = getRunBtnS1();
    const outputDiv = getOutputDivS1();

    if (runBtn) runBtn.disabled = true;
    if (outputDiv) outputDiv.innerHTML = '';
    
    logS1("==== INICIANDO Script 1 (v19.0 - Arsenal Expandido - Modular) ====", 'test', FNAME);
    
    await testCSPBypassS1(); await PAUSE_S1(MEDIUM_PAUSE_S1);
    await testOOBReadInfoLeakEnhancedStoreS1(); await PAUSE_S1(MEDIUM_PAUSE_S1);
    
    // Para os testes abaixo, você precisará criar os arquivos .mjs correspondentes
    // e portar a lógica original para eles, similar aos exemplos acima.
    if (typeof testOOBUAFPatternS1 === 'function') await testOOBUAFPatternS1(); else logS1("testOOBUAFPatternS1 não importado", "warn", FNAME); 
    await PAUSE_S1(MEDIUM_PAUSE_S1);
    
    if (typeof testOOBOtherTypesS1 === 'function') await testOOBOtherTypesS1(); else logS1("testOOBOtherTypesS1 não importado", "warn", FNAME);
    await PAUSE_S1(MEDIUM_PAUSE_S1);
    
    if (typeof testBasicPPS1 === 'function') await testBasicPPS1(); else logS1("testBasicPPS1 não importado", "warn", FNAME);
    await PAUSE_S1(MEDIUM_PAUSE_S1);
    
    if (typeof testPPJsonHijackS1 === 'function') await testPPJsonHijackS1(); else logS1("testPPJsonHijackS1 não importado", "warn", FNAME);
    await PAUSE_S1(MEDIUM_PAUSE_S1);
    
    if (typeof testWebSocketsS1 === 'function') await testWebSocketsS1(); else logS1("testWebSocketsS1 não importado", "warn", FNAME);
    await PAUSE_S1(MEDIUM_PAUSE_S1);
    
    if (typeof testWebWorkersS1 === 'function') await testWebWorkersS1(); else logS1("testWebWorkersS1 não importado", "warn", FNAME);
    await PAUSE_S1(MEDIUM_PAUSE_S1);
    
    if (typeof testIndexedDBS1 === 'function') await testIndexedDBS1(); else logS1("testIndexedDBS1 não importado", "warn", FNAME);
    await PAUSE_S1(MEDIUM_PAUSE_S1);
    
    if (typeof testDOMStressS1 === 'function') await testDOMStressS1(); else logS1("testDOMStressS1 não importado", "warn", FNAME);
    await PAUSE_S1(MEDIUM_PAUSE_S1);

    logS1("\n==== Script 1 CONCLUÍDO (v19.0 - Modular) ====", 'test', FNAME);
    if (runBtn) runBtn.disabled = false;
}
