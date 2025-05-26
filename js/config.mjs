
// js/config.mjs

// Firmware: PS4 12.02 (inferido)
// !! VOCÊ DEVE VALIDAR E REFINAR ESTES OFFSETS CUIDADOSAMENTE NO SEU DISASSEMBLER !!
export const JSC_OFFSETS = {
    JSCell: {
        // Análise de JSC::JSObject::put (download 33) sugere [rsi+8h] (rsi=JSCell*) é o Structure*.
        // Se StructureID é um uint32_t antes disso, poderia ser 0x4.
        // Se a célula começa com vtable (8 bytes), então Structure* pode ser 0x8.
        // O mais comum é o StructureID (ou um ponteiro para Structure que contém o ID)
        // estar bem no início da célula.
        // VÁLIDE: Se [obj_ptr+0] ou [obj_ptr+4] é o StructureID numérico,
        // ou se [obj_ptr+X] é o ponteiro para a Structure.
        // Vamos assumir um ponteiro para Structure no offset 0x8 por enquanto,
        // e o StructureID está dentro da Structure.
        STRUCTURE_POINTER_OFFSET: 0x8, // CANDIDATO: Ponteiro para a estrutura Structure
        // Se o ID estivesse direto na célula: STRUCTURE_ID_OFFSET: 0x0 (ou 0x4), FLAGS_OFFSET: 0x4 (ou 0x0)
        // Vamos manter seu original por enquanto, mas o STRUCTURE_POINTER_OFFSET acima é uma forte hipótese.
        STRUCTURE_ID_OFFSET: 0x00, // Seu valor original, VERIFIQUE se é ID direto ou se deve usar o ponteiro acima.
        FLAGS_OFFSET: 0x04       // Seu valor original
    },

    Structure: {
        // De download (36).txt (Construtor de Structure, rdi = this Structure*)
        GLOBAL_OBJECT_OFFSET: 0x00,        // mov [rdi], r8 (r8 = JSGlobalObject*)
        PROTOTYPE_OFFSET: 0x08,            // mov [rdi+8h], r9 (r9 = JSValue do protótipo)
        TYPE_INFO_FLAGS_OFFSET: 0x10,      // mov [rdi+10h], eax (TypeInfo.m_flags e .m_type)
                                           // Este campo provavelmente contém o StructureID real e flags de tipo.
        INDEXING_TYPE_AND_MISC_OFFSET: 0x18, // mov [rdi+18h], r10d (indexingType)
        CLASS_INFO_OFFSET: 0x1C,           // mov [rdi+1Ch], rcx (rcx = ClassInfo*)

        // De download (33).txt (JSC::JSObject::put), se rdx é Structure*:
        VIRTUAL_PUT_OFFSET: 0x18,          // call qword ptr [rdx+18h] (Pode ser um offset dentro de ClassInfo ou vtable inline)
                                           // Nota: Este 0x18 é diferente do INDEXING_TYPE_AND_MISC_OFFSET acima. Contexto é chave.
    },

    JSObject: {
        // Precisa ser confirmado. Se JSCell tem 8 ou 16 bytes, e Structure* está ali,
        // o Butterfly viria depois.
        BUTTERFLY_OFFSET: 0x10, // CANDIDATO: (Se JSCell base + Structure* ocupam 0x10 bytes)
                               // Seu config original tinha 0x08. Verifique!
    },

    ArrayBuffer: {
        // De download (37).txt (JSC::ArrayBuffer::create, rdi = this JSArrayBuffer*)
        // Assumindo Structure* em JSC_OFFSETS.JSCell.STRUCTURE_POINTER_OFFSET (ex: 0x8)
        CONTENTS_IMPL_POINTER_OFFSET: 0x10, // mov [rdi+10h], rbx (rbx = m_impl / ArrayBufferContents*)
                                            // Este offset é relativo ao início do objeto JSArrayBuffer.

        // O tamanho está DENTRO da estrutura ArrayBufferContents (ou m_impl).
        // Se m_impl está em CONTENTS_IMPL_POINTER_OFFSET (0x10),
        // e o tamanho está no offset 0x08 DENTRO de m_impl (ArrayBufferContents),
        // então o offset do tamanho, relativo ao JSArrayBuffer, é 0x10 + 0x08 = 0x18.
        SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START: 0x18, // Consistente com sua análise anterior.

        // Seu config original (especulativos, precisam ser verificados se relevantes)
        SHARING_MODE_OFFSET: 0x28,
        IS_RESIZABLE_FLAGS_OFFSET: 0x30
    },

    ArrayBufferView: { // Como DataView, Uint32Array
        // Se herda de JSCell, considerar os offsets de JSCell primeiro.
        // Estes são relativos ao início do objeto JSArrayBufferView.
        STRUCTURE_ID_OFFSET: 0x00,           // Seu original.
        FLAGS_OFFSET: 0x04,                  // Seu original.
        ASSOCIATED_ARRAYBUFFER_OFFSET: 0x08, // Ponteiro para o JSArrayBuffer.
        M_VECTOR_OFFSET: 0x10,               // Ponteiro para os dados (dentro do ArrayBuffer.m_impl->data()).
        M_LENGTH_OFFSET: 0x18,               // Comprimento da view.
        M_MODE_OFFSET: 0x1C                  // Modo (ex: WastefulWriting).
    },

    JSFunction: {
        // Se herda de JSCell...
        M_EXECUTABLE_OFFSET: "0x20", // Seu original (Ponteiro para FunctionExecutable).
        M_SCOPE_OFFSET: "0x28",      // Seu original (Ponteiro para JSScope).
    },

    SymbolObject: {
        // Se herda de JSCell...
        PRIVATE_SYMBOL_POINTER_OFFSET: 0x10, // De download (31).txt (Ponteiro para JSC::Symbol*).
    }
};

// VALORES NUMÉRICOS REAIS (HEX) PRECISAM SER EXTRAÍDOS DA SUA ANÁLISE!
export const KNOWN_STRUCTURE_IDS = {
    TYPE_ARRAY_BUFFER: "0xFILL_ME_IN_ARRAYBUFFER_ID",
    TYPE_JS_FUNCTION: "0xFILL_ME_IN_JSFUNCTION_ID",
    TYPE_JS_OBJECT_GENERIC: "0xFILL_ME_IN_JSOBJECT_ID",
    TYPE_FAKE_TARGET_FOR_CONFUSION: "0xFILL_ME_IN_INTERESTING_TYPE_ID", // Ex: Um tipo com vtable ou ponteiros de função.
    TYPE_DATAVIEW: "0xFILL_ME_IN_DATAVIEW_ID",
    // Adicione outros StructureIDs que você identificar.
};

// Endereços de GOT e funções (OFFSETS RELATIVOS AO BASE DO MÓDULO)
export const WEBKIT_LIBRARY_INFO = {
    MODULE_NAME: "libSceNKWebkit.sprx", // Ou o nome do módulo principal que contém JSC e WebCore
    // BASE_ADDRESS: "0x0", // VOCÊ PRECISARÁ DE UM INFO LEAK PARA OBTER ISSO EM TEMPO DE EXECUÇÃO
    KNOWN_OFFSETS: {
        // VTable_Possible_Offsets: [...] // Se você tiver offsets para vtables específicas
    },
    GOT_ENTRIES: {
         "mprotect": "0x3CBD820", // Do seu download (38).txt. Relativo ao base do módulo da GOT (SCE_RELRO?)
         // Adicione outros (free, memcpy, system, etc.)
    },
    FUNCTION_OFFSETS: { // Offsets relativos ao base do módulo principal (libSceNKWebkit.sprx)
        "JSC::JSFunction::create": "0x58A1D0",                 // download (4), (26), (28)
        "JSC::InternalFunction::createSubclassStructure": "0xA86580", // download (5), (6)
        "WTF::StringImpl::destroy": "0x10AA800",               // download (7), (10)
        "bmalloc::Scavenger::schedule": "0x2EBDB0",             // download (7)
        "WebCore::JSLocation::createPrototype": "0xD2E30",       // download (34)
        "WebCore::cacheDOMStructure": "0x740F30",              // download (11), (21), (20)
        "mprotect_plt_stub": "0x1A08",                         // download (22) (PLT stub, jmps para GOT)
        "JSC::JSWithScope::create": "0x9D6990",                // download (23)
        "JSC::JSObject::putByIndex": "0x1EB3B00",             // download (24)
        "JSC::JSInternalPromise::create": "0x112BB00",        // download (25)
        "JSC::JSInternalPromise::then": "0x1BC2D70",          // download (16)
        "JSC::loadAndEvaluateModule": "0xFC2900",              // download (27)
        "JSC::ArrayBuffer::create_from_arraybuffer_ref": "0x170A490", // download (29), (30) (create(ArrayBuffer&))
        "JSC::ArrayBuffer::create_from_contents": "0x10E5320", // download (37) (create(ArrayBufferContents&&))
        "JSC::SymbolObject::finishCreation": "0x102C8F0",       // download (31)
        "JSC::StructureCache::emptyStructureForPrototypeFromBaseStructure": "0xCCF870", // download (32)
        "JSC::JSObject::put": "0xBD68B0",                     // download (33)
        "JSC::Structure::Structure_constructor": "0x1638A50",    // download (36)
        "WTF::fastMalloc": "0x1271810",                        // download (10) - verifique se é o mais comum
        "WTF::fastFree": "0x230C7D0",                          // download (14) - verifique se é o mais comum
        "JSValueIsSymbol": "0x126D940",                         // download (17)
        "JSC::JSArray::getOwnPropertySlot": "0x2322630",       // download (18)
        "JSC::JSGlobalObject::visitChildren_JSCell": "0x1A5F740", // download (19)
        "JSC::JSCallee::JSCallee_constructor": "0x2038D50",      // download (20)

        // Gadgets ROP/JOP que você encontrar:
        "gadget_lea_rax_rdi_plus_20_ret": "0x58B860",         // download (3)
        // Adicione mais gadgets aqui
    }
};

export let OOB_CONFIG = {ALLOCATION_SIZE: 32768, BASE_OFFSET_IN_DV: 128, INITIAL_BUFFER_SIZE: 32};

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
