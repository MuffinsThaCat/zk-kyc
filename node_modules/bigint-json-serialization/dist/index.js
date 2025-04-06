"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parse = exports.stringify = void 0;
function stringify(value) {
    if (value == undefined || value == null) {
        throw new Error("Cannot stringify null or undefined");
    }
    return JSON.stringify(value, (_, v) => (typeof v === "bigint" ? `${v}n` : v));
}
exports.stringify = stringify;
function parse(text) {
    return JSON.parse(text, (_, value) => {
        if (typeof value === "string") {
            const m = value.match(/(-?\d+)n/);
            if (m && m[0] === value) {
                value = BigInt(m[1]);
            }
        }
        return value;
    });
}
exports.parse = parse;
//# sourceMappingURL=index.js.map