// js/config.mjs
console.log("[CONSOLE_LOG][CONFIG] Módulo config.mjs carregado.");

// Firmware: PS4 (Ex: 11.00, 9.00 - ajuste conforme seu alvo)
export const JSC_OFFSETS = {
    JSCell: {
        STRUCTURE_POINTER_OFFSET: 0x8,
    },
    Structure: {
        CLASS_INFO_OFFSET: 0x18, // EXEMPLO! VALIDE ESTE OFFSET PARA SEU ALVO! Se não tiver, comente ou remova.
                                 // Se comentado/removido, o teste usará o próprio Structure*
    },
    JSObject: {
        // BUTTERFLY_OFFSET: 0x10, // Exemplo
    },
    ArrayBuffer: {
        DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START: 0x20, // VALIDE!
        SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START: 0x18,   // VALIDE!
    },
    KnownStructureIDs: {
        ArrayBuffer_STRUCTURE_ID: 2, // VALIDE!
    },
    KnownOffsetsInLibs: {
        // !! IMPORTANTE PARA O TESTE DE VAZAMENTO DO BASE DO WEBKIT !!
        // Este é o offset do ponteiro que você está tentando vazar (ex: ClassInfo* ou Structure*)
        // DENTRO da biblioteca WebKit. Você PRECISA encontrar isso via engenharia reversa.
        LEAKED_POINTER_OFFSET_IN_WEBKIT: 0xDEADBEEFDEADBEEF, // <<< SUBSTITUA PELO VALOR REAL! (Número ou {low, high})
    },
    // Adicione outros offsets conforme sua validação
};

// Configuração para a primitiva Out-Of-Bounds
export let OOB_CONFIG = {
    ALLOCATION_SIZE: 32768,
    BASE_OFFSET_IN_DV: 128,
    INITIAL_BUFFER_SIZE: 32, // Pode não ser mais usado diretamente
    HEISENBUG_TRIGGER_OFFSET: 0x70, // Defina explicitamente aqui (112 decimal)
    HEISENBUG_TRIGGER_VALUE: 0xFFFFFFFF,
};
console.log(`[CONSOLE_LOG][CONFIG] OOB_CONFIG inicial: HEISENBUG_TRIGGER_OFFSET = 0x${OOB_CONFIG.HEISENBUG_TRIGGER_OFFSET.toString(16)}`);

export function updateOOBConfigFromUI(docInstance) {
    if (typeof docInstance === 'undefined' || !docInstance || typeof docInstance.getElementById !== 'function') {
        // console.warn("[CONSOLE_LOG][CONFIG_UI] updateOOBConfigFromUI chamada sem docInstance válido ou em ambiente não-navegador.");
        return;
    }
    // console.log("[CONSOLE_LOG][CONFIG_UI] updateOOBConfigFromUI chamada.");

    const oobAllocSizeEl = docInstance.getElementById('oobAllocSize');
    const baseOffsetEl = docInstance.getElementById('baseOffset');

    if (oobAllocSizeEl && oobAllocSizeEl.value !== undefined && oobAllocSizeEl.value !== null && oobAllocSizeEl.value !== '') {
        const val = parseInt(oobAllocSizeEl.value, 10);
        if (!isNaN(val) && val > 0) {
            OOB_CONFIG.ALLOCATION_SIZE = val;
            // console.log(`[CONSOLE_LOG][CONFIG_UI] OOB_CONFIG.ALLOCATION_SIZE atualizado para: ${OOB_CONFIG.ALLOCATION_SIZE}`);
        }
    }
    if (baseOffsetEl && baseOffsetEl.value !== undefined && baseOffsetEl.value !== null && baseOffsetEl.value !== '') {
        const val = parseInt(baseOffsetEl.value, 10);
        if (!isNaN(val) && val >= 0) {
            OOB_CONFIG.BASE_OFFSET_IN_DV = val;
            // Recalcula o trigger offset com base no novo base offset da UI
            OOB_CONFIG.HEISENBUG_TRIGGER_OFFSET = (OOB_CONFIG.BASE_OFFSET_IN_DV) - 16;
            console.log(`[CONSOLE_LOG][CONFIG_UI] OOB_CONFIG.BASE_OFFSET_IN_DV atualizado para: ${OOB_CONFIG.BASE_OFFSET_IN_DV}`);
            console.log(`[CONSOLE_LOG][CONFIG_UI] OOB_CONFIG.HEISENBUG_TRIGGER_OFFSET recalculado para: 0x${OOB_CONFIG.HEISENBUG_TRIGGER_OFFSET.toString(16)}`);
        }
    }
}
