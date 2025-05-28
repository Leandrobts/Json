// js/utils.mjs

export const KB = 1024;
export const MB = KB * KB;
export const GB = KB * KB * KB;

export class AdvancedInt64 { // Certifique-se que a classe está exportada
    constructor(low, high) {
        this._isAdvancedInt64 = true; // Propriedade para identificação
        let buffer = new Uint32Array(2);
        // let bytes = new Uint8Array(buffer.buffer); // Não usado diretamente no construtor original

        if (arguments.length > 2) { throw TypeError('AdvancedInt64 takes at most 2 args'); }
        
        let is_one_arg = false;
        if (arguments.length === 1) { is_one_arg = true; }
        if (arguments.length === 0) { // Adicionado para evitar erro com 0 args
            low = 0; high = 0; is_one_arg = false; 
        }


        if (!is_one_arg) {
            if (typeof (low) !== 'number' || typeof (high) !== 'number') {
                // Permitir que AdvancedInt64 seja construído a partir de outro AdvancedInt64
                if (low instanceof AdvancedInt64 && high === undefined) {
                    buffer[0] = low.low();
                    buffer[1] = low.high();
                    this.buffer = buffer;
                    return;
                }
                throw TypeError('low/high must be numbers or single AdvancedInt64 argument');
            }
        }
        
        const check_range = (x) => Number.isInteger(x) && x >= -0x80000000 && x <= 0xffffffff; // Permite inteiros dentro do range de u32/i32

        if (typeof low === 'number') {
            if (!check_range(low)) { throw TypeError('low not a valid 32-bit integer value: ' + low); }
            if (is_one_arg) {
                high = 0;
                if (low < 0) { high = -1; } // Extensão de sinal para um único argumento numérico
            } else {
                if (!check_range(high)) { throw TypeError('high not a valid 32-bit integer value: ' + high); }
            }
            buffer[0] = low;
            buffer[1] = high;
        } else if (typeof low === 'string') { // Construir a partir de string hexadecimal
            let str = low;
            if (high !== undefined) { throw TypeError('Cannot supply high with hex string'); }
            if (!str.startsWith('0x')) { throw TypeError('Hex string must start with 0x'); }
            str = str.substring(2);
            if (str.length > 16) { throw TypeError('Hex string too long (max 16 chars for 64-bit)'); }
            str = str.padStart(16, '0'); // Pad para 16 caracteres (64 bits)
            
            const high_str = str.substring(0, 8);
            const low_str = str.substring(8, 16);

            buffer[1] = parseInt(high_str, 16);
            buffer[0] = parseInt(low_str, 16);

        } else if (low instanceof AdvancedInt64 && is_one_arg) { // Construir a partir de outro AdvancedInt64
             buffer[0] = low.low();
             buffer[1] = low.high();
        } else {
            throw TypeError('Invalid constructor arguments for AdvancedInt64');
        }
        this.buffer = buffer;
    }

    low() { return this.buffer[0]; }
    high() { return this.buffer[1]; }

    // toString(show_0x = false, pad_to_16_chars = false) { // Assinatura original
    toString(show_0x = true, pad_to_16_chars = true) { // Modificado para corresponder ao uso nos logs
        const high_hex = (this.buffer[1] >>> 0).toString(16).padStart(8, '0');
        const low_hex = (this.buffer[0] >>> 0).toString(16).padStart(8, '0');
        let result = `${high_hex}_${low_hex}`;
        if (pad_to_16_chars && result.length < 17) { // 8 + 1 underscore + 8
             // O padStart já faz isso, esta lógica pode ser redundante se o objetivo for sempre 8_8
        }
        return (show_0x ? '0x' : '') + result;
    }
    
    toNumber() { // CUIDADO: Perda de precisão para números grandes
        return this.buffer[1] * 0x100000000 + (this.buffer[0] >>> 0);
    }

    equals(other) {
        if (!(other instanceof AdvancedInt64)) return false;
        return this.low() === other.low() && this.high() === other.high();
    }

    static fromNumber(num) {
        if (typeof num !== 'number' || !Number.isFinite(num)) {
            throw new TypeError("Input must be a finite number.");
        }
        const high = Math.floor(num / 0x100000000);
        const low = num % 0x100000000;
        return new AdvancedInt64(low >>> 0, high >>> 0); // Garante que sejam tratados como unsigned na conversão
    }

    add(other) {
        if (!(other instanceof AdvancedInt64)) {
            other = AdvancedInt64.fromNumber(Number(other));
        }
        let low = (this.low() >>> 0) + (other.low() >>> 0);
        let high = (this.high() >>> 0) + (other.high() >>> 0) + Math.floor(low / 0x100000000);
        return new AdvancedInt64(low >>> 0, high >>> 0);
    }

    sub(other) {
        if (!(other instanceof AdvancedInt64)) {
            other = AdvancedInt64.fromNumber(Number(other));
        }
        // Realizar subtração em 64 bits simulados
        let new_low = (this.low() >>> 0) - (other.low() >>> 0);
        let borrow = 0;
        if (new_low < 0) {
            new_low += 0x100000000; // Adiciona 2^32 para torná-lo positivo, simulando o "empréstimo"
            borrow = 1;
        }
        let new_high = (this.high() >>> 0) - (other.high() >>> 0) - borrow;
        return new AdvancedInt64(new_low >>> 0, new_high >>> 0);
    }
    
    neg() {
        const low = ~this.low();
        const high = ~this.high();
        return new AdvancedInt64(low, high).add(AdvancedInt64.One);
    }

    static get Zero() { return new AdvancedInt64(0, 0); }
    static get One() { return new AdvancedInt64(1, 0); }
}

export function isAdvancedInt64Object(obj) {
    return obj && obj._isAdvancedInt64 === true;
}

export const PAUSE = (ms = 50) => new Promise(r => setTimeout(r, ms));

export const toHex = (val, bits = 32) => {
    if (val === null || val === undefined) return 'null/undef';
    if (isAdvancedInt64Object(val) && bits === 64) return val.toString(true, true);
    if (typeof val === 'string') return val;
    if (typeof val !== 'number' || !isFinite(val)) return 'NaN/Invalid';
    
    let num = Number(val);
    let hexStr;

    if (bits === 64) { // Se for para 64 bits, mas não é AdvancedInt64, use fromNumber
        return AdvancedInt64.fromNumber(num).toString(true, true);
    }

    // Para 32 bits ou menos
    if (num < 0) {
        // Para números negativos, obtenha a representação de complemento de dois
        if (bits === 32) hexStr = (num >>> 0).toString(16).padStart(8, '0');
        else if (bits === 16) hexStr = ((num & 0xFFFF) >>> 0).toString(16).padStart(4, '0');
        else if (bits === 8) hexStr = ((num & 0xFF) >>> 0).toString(16).padStart(2, '0');
        else hexStr = (num >>> 0).toString(16).padStart(8, '0'); // Padrão para 32 bits
    } else {
        hexStr = num.toString(16).padStart(bits / 4, '0');
    }
    return '0x' + hexStr;
};

/**
 * Converte uma string em um array de objetos AdvancedInt64.
 * Cada AdvancedInt64 armazena até 4 caracteres UTF-16 (8 bytes).
 * @param {string} str A string a ser convertida.
 * @param {boolean} nullTerminate Se true, adiciona um AdvancedInt64(0,0) no final.
 * @returns {AdvancedInt64[]} Array de AdvancedInt64.
 */
export function stringToAdvancedInt64Array(str, nullTerminate = false) {
    let result = [];
    for (let i = 0; i < str.length; i += 4) {
        let char1 = (i < str.length) ? str.charCodeAt(i) : 0;
        let char2 = (i + 1 < str.length) ? str.charCodeAt(i + 1) : 0;
        let char3 = (i + 2 < str.length) ? str.charCodeAt(i + 2) : 0;
        let char4 = (i + 3 < str.length) ? str.charCodeAt(i + 3) : 0;

        // Little-endian: char1 e char2 na parte baixa, char3 e char4 na parte alta.
        // Char1 nos bytes 0-1, Char2 nos bytes 2-3 (da parte baixa de 32 bits)
        // Char3 nos bytes 0-1, Char4 nos bytes 2-3 (da parte alta de 32 bits)
        let low_u32 = (char2 << 16) | char1;
        let high_u32 = (char4 << 16) | char3;
        
        result.push(new AdvancedInt64(low_u32 >>> 0, high_u32 >>> 0));
    }

    if (nullTerminate) {
        // Se o último AdvancedInt64 já for parcialmente zero por causa do padding,
        // um terminador nulo de 16 bits (0x0000) já pode estar lá.
        // Para garantir um terminador de 64 bits completo se a escrita for sempre de 8 bytes:
        result.push(AdvancedInt64.Zero);
    }
    return result;
}

/**
 * Converte um array de AdvancedInt64 de volta para uma string.
 * Assume que cada AdvancedInt64 representa 4 caracteres UTF-16.
 * Para ao encontrar o primeiro caractere nulo (0x0000).
 * @param {AdvancedInt64[]} arr O array de AdvancedInt64.
 * @returns {string} A string resultante.
 */
export function advancedInt64ArrayToString(arr) {
    let str = "";
    if (!Array.isArray(arr)) return "InputIsNotArray";

    for (const adv64 of arr) {
        if (!isAdvancedInt64Object(adv64)) continue;

        const low = adv64.low();
        const high = adv64.high();

        const char1_code = low & 0xFFFF;
        const char2_code = (low >>> 16) & 0xFFFF;
        const char3_code = high & 0xFFFF;
        const char4_code = (high >>> 16) & 0xFFFF;

        if (char1_code === 0) break;
        str += String.fromCharCode(char1_code);
        if (char2_code === 0) break;
        str += String.fromCharCode(char2_code);
        if (char3_code === 0) break;
        str += String.fromCharCode(char3_code);
        if (char4_code === 0) break;
        str += String.fromCharCode(char4_code);
    }
    return str;
}

// Remover jscOffsets duplicado daqui, pois deve estar em config.mjs
// export const jscOffsets = { ... };

// Remover placeholders de utils não implementadas, a menos que você as queira
// export const readWriteUtils = { ... };
// export const generalUtils = { ... };
