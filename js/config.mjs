// js/config.mjs

// Firmware: PS4 12.02 (Com base na análise dos TXT fornecidos)
// !! OFFSETS VALIDADOS E ATUALIZADOS COM BASE NOS ARQUIVOS DE DISASSEMBLY FORNECIDOS !!
//    É crucial continuar validando no contexto do seu exploit específico.
export const JSC_OFFSETS = {
    JSCell: {
        STRUCTURE_POINTER_OFFSET: 0x8, 
        STRUCTURE_ID_OFFSET: 0x00, 
        FLAGS_OFFSET: 0x04       
    },
    Structure: { 
        GLOBAL_OBJECT_OFFSET: 0x00,        
        PROTOTYPE_OFFSET: 0x08,            
        TYPE_INFO_FLAGS_OFFSET: 0x10,      
        INDEXING_TYPE_AND_MISC_OFFSET: 0x18, 
        CLASS_INFO_OFFSET: 0x1C, // Ponteiro para ClassInfo
        // Outros offsets de Structure que podem ser úteis:
        // DUMP_OFFSETS_IF_NEEDED
    },
    JSObject: {
        BUTTERFLY_OFFSET: 0x10, 
    },
    ArrayBuffer: {  
        CONTENTS_IMPL_POINTER_OFFSET: 0x10, 
        SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START: 0x18, 
        DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START: 0x20, 
        SHARING_MODE_OFFSET: 0x28,
        IS_RESIZABLE_FLAGS_OFFSET: 0x30,
        KnownStructureIDs: { 
            JSString_STRUCTURE_ID: null, 
            ArrayBuffer_STRUCTURE_ID: 2, 
            JSArray_STRUCTURE_ID: null, 
            JSObject_Simple_STRUCTURE_ID: null, 
            JSFunction_STRUCTURE_ID: null // PREENCHA SE SOUBER O ID DE UMA FUNÇÃO JS
        }
    },
    ArrayBufferView: { 
        CONTENTS_IMPL_POINTER_OFFSET: 0x10,         
        STRUCTURE_ID_OFFSET: 0x00,           
        FLAGS_OFFSET: 0x04,                  
        ASSOCIATED_ARRAYBUFFER_OFFSET: 0x08, 
        M_VECTOR_OFFSET: 0x10,               
        M_LENGTH_OFFSET: 0x18,               
        M_MODE_OFFSET: 0x1C                  
    },
    ArrayBufferContents: { 
        SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START: 0x8, 
        DATA_POINTER_OFFSET_FROM_CONTENTS_START: 0x10, 
    },
    JSFunction: {
        // Estes são críticos para vazar a base da lib
        EXECUTABLE_OFFSET: 0x18, // Ponteiro para JSExecutable (ou subclass como FunctionExecutable)
        SCOPE_OFFSET: 0x20,      // Ponteiro para JSScope
        // Adicionar mais se conhecido, ex: m_jsCallEntrypoint, m_nativeCallEntrypoint
    },
    JSExecutable: { // Ou FunctionExecutable, NativeExecutable etc.
        // Offsets DENTRO da estrutura Executable
        // Precisamos de um que aponte para código JITted ou um stub na libWebkit
        JIT_CODE_START_OFFSET: null, // Ex: offset para m_jitCode->start() ou similar
        NATIVE_ENTRYPOINT_OFFSET: null, // Ex: offset para m_nativeEntryPoint (se aplicável)
    }
};

export const WEBKIT_LIBRARY_INFO = {
    LIBRARY_NAME: "libSceNKWebkit.sprx", 
    FUNCTION_OFFSETS: { 
        // Estes são offsets de FUNÇÕES (ou stubs) RELATIVOS AO INÍCIO DA BIBLIOTECA WEBKIT
        // Precisamos de um que corresponda ao que EXECUTABLE_OFFSET aponta.
        "JSC::JSFunction::create": "0x58A1D0", // Este é o offset da função create, não de um entrypoint de uma função criada.
        "some_known_function_call_entrypoint_stub_offset": null, // PREENCHA COM O OFFSET DE UM STUB CONHECIDO
        // Ex: Se JSFunction->Executable->JITCodeStart aponta para um stub JIT, e sabemos o offset desse tipo de stub.
        "WTF::fastMalloc": "0x1271810", // Útil para outros propósitos, mas não diretamente para vazar a base de uma JSFunction
    },
    GOT_ENTRIES: {
        "mprotect": "0x3CBD820", 
    }
};

export let OOB_CONFIG = {
    ALLOCATION_SIZE: 32768, 
    BASE_OFFSET_IN_DV: 128,  
    INITIAL_BUFFER_SIZE: 32 
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
