// js/utils.mjs

export const KB = 1024;
export const MB = KB * KB;
export const GB = KB * KB * KB;

export class AdvancedInt64 {
    constructor(low, high) {
        this._isAdvancedInt64 = true;
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
                if (!check_range(high)) { throw TypeError('high not a valid value'); }
            }
            buffer[0] = low;
            buffer[1] = high;
        } else if (typeof low === 'string') {
            if (low.length > 18 || !low.startsWith('0x')) { throw TypeError('string arg must be hex & <= 18 chars'); }
            low = low.substring(2);
            while (low.length < 16) { low = '0' + low; }
            let high_str = low.substring(0, 8);
            let low_str = low.substring(8);
            buffer[0] = parseInt(low_str, 16);
            buffer[1] = parseInt(high_str, 16);
        } else {
            throw TypeError('low must be number or string');
        }

        this.low = () => buffer[0];
        this.high = () => buffer[1];
        this.bytes = () => bytes;

        this.toString = (asHex = true) => {
            if (asHex) {
                let h = buffer[1].toString(16).padStart(8, '0');
                let l = buffer[0].toString(16).padStart(8, '0');
                return `0x${h}${l}`;
            }
            return `h:<span class="math-inline">\{buffer\[1\]\} l\:</span>{buffer[0]}`;
        };

        this.equals = (other) => {
            if (!isAdvancedInt64Object(other)) return false;
            return this.low() === other.low() && this.high() === other.high();
        };

        this.add = (otherNumOrAdvInt64) => {
            let otherLow, otherHigh;
            if (isAdvancedInt64Object(otherNumOrAdvInt64)) {
                otherLow = otherNumOrAdvInt64.low();
                otherHigh = otherNumOrAdvInt64.high();
            } else if (typeof otherNumOrAdvInt64 === 'number') {
                otherLow = otherNumOrAdvInt64;
                otherHigh = (otherNumOrAdvInt64 < 0) ? -1 : 0; 
            } else {
                throw TypeError("Can only add number or AdvancedInt64");
            }

            let currentLow = this.low();
            let currentHigh = this.high();
            let newLow = currentLow + otherLow;
            let newHigh = currentHigh + otherHigh;
            if ((currentLow >>> 0) + (otherLow >>> 0) > 0xFFFFFFFF) {
                newHigh += 1;
            }
            const low32 = newLow & 0xFFFFFFFF;
            const highCarry = (newLow - low32) / (0xFFFFFFFF + 1);
            newHigh += highCarry;
            return new AdvancedInt64(low32, newHigh & 0xFFFFFFFF);
        };
    }
}

export function isAdvancedInt64Object(obj) {
    return obj && obj._isAdvancedInt64 === true;
}

export function PAUSE(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

export function toHex(value, bits = 32) {
    if (isAdvancedInt64Object(value)) {
        return value.toString(true);
    }
    if (typeof value !== 'number') return String(value);

    let hexStr;
    if (value < 0) {
        if (bits === 32) {
            hexStr = (value >>> 0).toString(16);
        } else if (bits === 16) {
            hexStr = ((value & 0xFFFF) >>> 0).toString(16);
        } else if (bits === 8) {
            hexStr = ((value & 0xFF) >>> 0).toString(16);
        } else {
            hexStr = (BigInt(value) & BigInt("0xFFFFFFFFFFFFFFFF")).toString(16);
            return "0x" + hexStr.padStart(16, '0');
        }
    } else {
        hexStr = value.toString(16);
    }
    let padding = Math.ceil(bits / 4);
    return "0x" + hexStr.padStart(padding, '0');
}

export const DataViewUtils = { // <--- ESTA É A EXPORTAÇÃO
    readUint64: (dv, offset) => {
        const low = dv.getUint32(offset, true);
        const high = dv.getUint32(offset + 4, true);
        return new AdvancedInt64(low, high);
    },
    writeUint64: (dv, offset, value) => { 
        if (!isAdvancedInt64Object(value)) { throw new TypeError('Value must be an AdvancedInt64 object'); }
        dv.setUint32(offset, value.low(), true);
        dv.setUint32(offset + 4, value.high(), true);
    },
    readUint64FromArrayBuffer: (arrayBuffer, offset) => {
        const u8_view = new Uint8Array(arrayBuffer, offset, 8);
        const low = u8_view[0] | (u8_view[1] << 8) | (u8_view[2] << 16) | (u8_view[3] << 24);
        const high = u8_view[4] | (u8_view[5] << 8) | (u8_view[6] << 16) | (u8_view[7] << 24);
        return new AdvancedInt64(low, high);
    },
    writeUint64ToArrayBuffer: (arrayBuffer, offset, value) => {
        const u8_view = new Uint8Array(arrayBuffer);
        if (!isAdvancedInt64Object(value)) { throw new TypeError('Value must be an AdvancedInt64 object'); }
        let low = value.low();
        let high = value.high();
        for (let i = 0; i < 4; i++) { u8_view[offset + i] = (low >>> (i * 8)) & 0xff; }
        for (let i = 0; i < 4; i++) { u8_view[offset + 4 + i] = (high >>> (i * 8)) & 0xff; }
    }
};

export const generalUtils = {
    align: (addrOrInt, alignment) => {
        let a = (isAdvancedInt64Object(addrOrInt)) ? addrOrInt : new AdvancedInt64(addrOrInt);
        let low = a.low();
        low = (low + alignment -1) & (~(alignment-1));
        return new AdvancedInt64(low, a.high());
    },
    str2array: (str, length, offset = 0) => {
        let a = new Array(length);
        for (let i = 0; i < length; i++) {
            a[i] = str.charCodeAt(i + offset);
             if (isNaN(a[i])) a[i] = 0;
        }
        return a;
    }
};
