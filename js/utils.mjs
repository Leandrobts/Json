// js/utils.mjs
console.log("[CONSOLE_LOG][UTILS] Módulo utils.mjs carregado.");

export const KB = 1024;
export const MB = KB * KB;
export const GB = KB * KB * KB;

export class AdvancedInt64 {
    constructor(low, high) {
        this._isAdvancedInt64 = true;
        let buffer = new Uint32Array(2);
        // let bytes = new Uint8Array(buffer.buffer); // Não usado diretamente no construtor

        if (arguments.length > 2) { throw TypeError('AdvancedInt64 takes at most 2 args'); }
        if (arguments.length === 0) { throw TypeError('AdvancedInt64 takes at min 1 args'); }

        let is_one_arg = false;
        if (arguments.length === 1) {
            if (typeof low === 'object' && low !== null && low.low !== undefined && low.high !== undefined) {
                // Construtor de cópia de objeto {low, high}
                high = low.high;
                low = low.low;
            } else if (typeof low === 'number') {
                is_one_arg = true;
            } else if (typeof low === 'string') { // Suporte para string hexadecimal
                 if (!low.startsWith("0x")) throw TypeError("Hex string for AdvancedInt64 must start with 0x");
                 const hex = low.substring(2);
                 if (hex.length > 16) throw TypeError("Hex string too long for 64-bit");
                 if (!/^[0-9a-fA-F]+$/.test(hex)) throw TypeError("Invalid hex string for AdvancedInt64");

                 const fullHex = hex.padStart(16, '0');
                 high = parseInt(fullHex.substring(0, 8), 16);
                 low = parseInt(fullHex.substring(8, 16), 16);
                 // Corrigir sinal para high se o bit mais significativo do low original for 1 (para números > 2^63-1)
                 // ou se a string for > 8 caracteres e o primeiro caractere indicar um valor grande
                 if (parseInt(hex[0], 16) >= 8 && hex.length > 8) {
                    //  Esta lógica de sinal pode ser complexa para strings;
                    //  assumir unsigned por padrão para strings hexadecimais.
                    //  Se precisar de números negativos via string hex, é melhor usar {low,high}
                 }

            } else {
                 throw TypeError("Single argument must be number, {low,high} object, or hex string");
            }
        }

        if (typeof low !== 'number' || typeof high !== 'number') {
            throw TypeError('low/high must be numbers or parseable from single arg');
        }

        const check_range = (x) => (-0x80000000 <= x) && (x <= 0xffffffff);

        if (!check_range(low)) { throw TypeError('low not a valid value: ' + low); }
        if (is_one_arg) {
            high = 0;
            if (low < 0) { high = -1; }
        } else {
            if (!check_range(high)) { throw TypeError('high not a valid value: ' + high); }
        }
        buffer[0] = low;
        buffer[1] = high;
        this.low = buffer[0];
        this.high = buffer[1];
    }
    static fromBytes(bytes, littleEndian = true) {
        if (!bytes || bytes.length < 8) throw new Error("Need at least 8 bytes for AdvancedInt64.fromBytes");
        const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        const low = view.getUint32(littleEndian ? 0 : 4, littleEndian);
        const high = view.getUint32(littleEndian ? 4 : 0, littleEndian);
        return new AdvancedInt64(low, high);
    }
    getBytes(littleEndian = true) {
        const buffer = new ArrayBuffer(8);
        const view = new DataView(buffer);
        view.setUint32(littleEndian ? 0 : 4, this.low, littleEndian);
        view.setUint32(littleEndian ? 4 : 0, this.high, littleEndian);
        return new Uint8Array(buffer);
    }
    toNumber() { // CUIDADO: Perda de precisão para números grandes
        return this.high * Math.pow(2, 32) + (this.low >>> 0);
    }
    isZero() { return this.low === 0 && this.high === 0; }
    isNegative() { return this.high < 0; }
    equals(other) {
        if (!isAdvancedInt64Object(other)) return false;
        return this.low === other.low && this.high === other.high;
    }
    add(other) {
        if (!isAdvancedInt64Object(other)) other = new AdvancedInt64(other);
        let low = (this.low + other.low) | 0;
        let carry = (((this.low & 0xffffffff) + (other.low & 0xffffffff)) > 0xffffffff) ? 1 : 0;
        let high = (this.high + other.high + carry) | 0;
        return new AdvancedInt64(low, high);
    }
    sub(other) {
        if (!isAdvancedInt64Object(other)) other = new AdvancedInt64(other);
        let low = (this.low - other.low) | 0;
        let borrow = (((this.low & 0xffffffff) - (other.low & 0xffffffff)) < 0) ? 1 : 0;
        let high = (this.high - other.high - borrow) | 0;
        return new AdvancedInt64(low, high);
    }
    toString(hex = false) {
        if (hex) {
            const highHex = (this.high >>> 0).toString(16).padStart(8, '0');
            const lowHex = (this.low >>> 0).toString(16).padStart(8, '0');
            return `0x${highHex}${lowHex}`;
        }
        // Para decimal, é mais complexo e pode exigir uma biblioteca BigInt
        // ou uma conversão aproximada para número se não for muito grande.
        if (this.high === 0 && this.low >= 0) return (this.low >>> 0).toString();
        if (this.high === -1 && this.low < 0) return this.low.toString();
        return `(High: 0x${(this.high >>> 0).toString(16)}, Low: 0x${(this.low >>> 0).toString(16)})`; // Fallback
    }
}
export function isAdvancedInt64Object(obj) {
    return typeof obj === 'object' && obj !== null && obj._isAdvancedInt64 === true;
}
export const PAUSE = (ms = 50) => new Promise(r => setTimeout(r, ms));

export const toHex = (val, bits = 32) => {
    if (val === null || val === undefined) return 'null/undef';
    if (typeof val === 'string') return val;
    if (isAdvancedInt64Object(val)) return val.toString(true);
    if (val instanceof Uint8Array || val instanceof Uint16Array || val instanceof Uint32Array) {
        let hexString = "0x";
        for (let i = 0; i < val.length; i++) {
            hexString += val[i].toString(16).padStart(val.BYTES_PER_ELEMENT * 2, '0');
        }
        return hexString;
    }
    if (typeof val !== 'number' || !isFinite(val)) return `NaN/Invalid (${typeof val})`;

    let num = Number(val);
    if (num < 0) { // Para números negativos, representação em complemento de dois
        if (bits === 64) return new AdvancedInt64(num).toString(true); // Aproximação se não for inteiro
        if (bits === 32) num = (num | 0); // Converte para inteiro de 32 bits com sinal
        else if (bits === 16) num = (num & 0xFFFF) | 0; // Tenta manter o sinal para 16 bits
        else if (bits === 8) num = (num & 0xFF) | 0;   // Tenta manter o sinal para 8 bits
    }

    let hexStr = (num >>> 0).toString(16); // Use unsigned right shift para garantir que o resultado seja positivo para toHexString
    if (bits === 64) return "0x" + hexStr.padStart(16, '0'); // Impreciso para JS numbers > 2^53
    if (bits === 32) return "0x" + hexStr.padStart(8, '0');
    if (bits === 16) return "0x" + (num & 0xFFFF).toString(16).padStart(4, '0');
    if (bits === 8) return "0x" + (num & 0xFF).toString(16).padStart(2, '0');
    return "0x" + hexStr; // Default
};
