// js/utils.mjs

export const KB = 1024;
export const MB = KB * KB;
export const GB = KB * KB * KB;

export class AdvancedInt64 {
    constructor(low, high) {
        // ... (construtor existente permanece o mesmo) ...
        // Adicionado para consistência com o debug do core_exploit.mjs
        this._isAdvancedInt64 = true; // Propriedade simples para verificação interna, se desejado

        let buffer = new Uint32Array(2);
        let bytes = new Uint8Array(buffer.buffer);

        if (arguments.length > 2) { throw TypeError('AdvancedInt64 takes at most 2 args'); }
        if (arguments.length === 0) { throw TypeError('AdvancedInt64 takes at min 1 args'); }
        let is_one = false;
        if (arguments.length === 1) { is_one = true; }

        if (!is_one) {
            if (typeof (low) !== 'number' && typeof (high) !== 'number') {
                throw TypeError('low/high must be numbers');
            }
        }
        const check_range = (x) => (-0x80000000 <= x) && (x <= 0xffffffff);

        if (typeof low === 'number') {
            if (!check_range(low)) { throw TypeError('low not a valid value: ' + low); }
            if (is_one) {
                high = 0;
                if (low < 0) { high = -1; }
            } else {
                if (!check_range(high)) { throw TypeError('high not a valid value: ' + high); }
            }
            buffer[0] = low;
            buffer[1] = high;
        } else if (typeof low === 'string') { // Hex string
            let hexstr = low;
            if (hexstr.substring(0, 2) === "0x") { hexstr = hexstr.substring(2); }
            if (hexstr.length % 2 === 1) { hexstr = '0' + hexstr; }
            if (hexstr.length > 16) { hexstr = hexstr.substring(hexstr.length - 16); }
            else { hexstr = hexstr.padStart(16, '0');}

            for (let i = 0; i < 8; i++) {
                bytes[i] = parseInt(hexstr.slice(14 - i*2, 16 - i*2), 16);
            }
        } else if (typeof low === 'object') {
            if (low instanceof AdvancedInt64 || (low && low._isAdvancedInt64 === true)) { // Verifica a propriedade também
                bytes.set(low.bytes);
            } else if (low.length === 8) { // Assuming byte array
                bytes.set(low);
            } else { throw TypeError("Array must have exactly 8 elements."); }
        } else {
            throw TypeError('AdvancedInt64 does not support your object for conversion');
        }

        this.buffer = buffer;
        this.bytes = bytes;
    }

    low() { return this.buffer[0]; }
    high() { return this.buffer[1]; }

    toString(is_pretty) {
        // ... (toString existente permanece o mesmo) ...
        let lowStr = (this.low() >>> 0).toString(16).padStart(8, '0');
        let highStr = (this.high() >>> 0).toString(16).padStart(8, '0');
        if (is_pretty) {
            highStr = highStr.substring(0, 4) + '_' + highStr.substring(4);
            lowStr = lowStr.substring(0, 4) + '_' + lowStr.substring(4);
            return '0x' + highStr + '_' + lowStr;
        }
        return '0x' + highStr + lowStr;
    }

    add(other) {
        // ... (add existente permanece o mesmo) ...
        if (!isAdvancedInt64Object(other)) { other = new AdvancedInt64(other); }
        let newLow = (this.low() + other.low()) >>> 0;
        let carry = (this.low() & 0xFFFFFFFF) + (other.low() & 0xFFFFFFFF) > 0xFFFFFFFF ? 1 : 0;
        let newHigh = (this.high() + other.high() + carry) >>> 0;
        return new AdvancedInt64(newLow, newHigh);
    }
    sub(other) {
        // ... (sub existente permanece o mesmo) ...
        if (!isAdvancedInt64Object(other)) { other = new AdvancedInt64(other); }
        const negOther = other.neg();
        return this.add(negOther);
    }
    neg() {
        // ... (neg existente permanece o mesmo) ...
        const low = ~this.low();
        const high = ~this.high();
        const one = new AdvancedInt64(1,0); // Ou AdvancedInt64.One se preferir
        const res = new AdvancedInt64(low, high);
        return res.add(one);
    }
    equals(other) { // Renomeado de eq para melhor semântica
        if (!isAdvancedInt64Object(other)) {
             try { other = new AdvancedInt64(other); } catch (e) { return false; }
        }
        return this.low() === other.low() && this.high() === other.high();
    }

    static Zero = new AdvancedInt64(0,0);
    static One = new AdvancedInt64(1,0);

    // Novo método estático para converter de número JS (apenas os 53 bits seguros)
    static fromNumber(num) {
        if (typeof num !== 'number' || !Number.isFinite(num)) {
            throw new TypeError("AdvancedInt64.fromNumber espera um número finito.");
        }
        const high = Math.floor(num / Math.pow(2, 32));
        const low = num % Math.pow(2, 32);
        return new AdvancedInt64(low, high);
    }
}

// Nova função helper
export function isAdvancedInt64Object(obj) {
    return obj instanceof AdvancedInt64 || (obj && obj._isAdvancedInt64 === true);
}

export const readWriteUtils = {
    // ... (readWriteUtils existente permanece o mesmo) ...
    readBytes: (u8_view, offset, size) => {
        let res = 0;
        for (let i = 0; i < size; i++) {
            res += u8_view[offset + i] << (i * 8);
        }
        return res >>> 0;
    },
    read16: (u8_view, offset) => readWriteUtils.readBytes(u8_view, offset, 2),
    read32: (u8_view, offset) => readWriteUtils.readBytes(u8_view, offset, 4),
    read64: (u8_view, offset) => {
        let resBytes = [];
        for (let i = 0; i < 8; i++) {
            resBytes.push(u8_view[offset + i]);
        }
        return new AdvancedInt64(resBytes);
    },
    writeBytes: (u8_view, offset, value, size) => {
        for (let i = 0; i < size; i++) {
            u8_view[offset + i] = (value >>> (i * 8)) & 0xff;
        }
    },
    write16: (u8_view, offset, value) => readWriteUtils.writeBytes(u8_view, offset, value, 2),
    write32: (u8_view, offset, value) => readWriteUtils.writeBytes(u8_view, offset, value, 4),
    write64: (u8_view, offset, value) => {
        if (!isAdvancedInt64Object(value)) { throw TypeError('write64 value must be an AdvancedInt64 object'); }
        let low = value.low();
        let high = value.high();
        for (let i = 0; i < 4; i++) { u8_view[offset + i] = (low >>> (i * 8)) & 0xff; }
        for (let i = 0; i < 4; i++) { u8_view[offset + 4 + i] = (high >>> (i * 8)) & 0xff; }
    }
};

export const generalUtils = {
    // ... (generalUtils existente permanece o mesmo) ...
    align: (addrOrInt, alignment) => {
        let a = (isAdvancedInt64Object(addrOrInt)) ? addrOrInt : new AdvancedInt64(addrOrInt);
        let low = a.low();
        let high = a.high();
        low = (low + alignment -1) & (~(alignment-1));
        return new AdvancedInt64(low, high);
    },
    str2array: (str, length, offset = 0) => {
        let a = new Array(length);
        for (let i = 0; i < length; i++) {
            a[i] = str.charCodeAt(i + offset);
        }
        return a;
    }
};

export const jscOffsets = {
    // ... (jscOffsets existente permanece o mesmo) ...
    js_butterfly: 0x8,
    view_m_vector: 0x10,
    view_m_length: 0x18,
    view_m_mode: 0x1c,
    size_view: 0x20,
};

export const PAUSE = (ms = 50) => new Promise(r => setTimeout(r, ms));

export const toHex = (val, bits = 32) => {
    // ... (toHex existente permanece o mesmo) ...
    if (typeof val !== 'number' || !isFinite(val)) return 'NaN/Invalid';
    let num = Number(val);
    if (bits <= 32) { num = num >>> 0; }
    const pad = Math.ceil(bits / 4);
    return '0x' + num.toString(16).toUpperCase().padStart(pad, '0');
};
