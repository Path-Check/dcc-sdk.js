const baseSize = 45;
const baseSizeSquared = 2025;
const chunkSize = 2;
const encodedChunkSize = 3;
const smallEncodedChunkSize = 2;
const byteSize = 256;

const encoding = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
    "A", "B", "C", "D", "E", "F", "G", "H", "I", "J",
    "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T",
    "U", "V", "W", "X", "Y", "Z", " ", "$", "%", "*",
    "+", "-", ".", "/", ":"];

var decoding;

export function encode(byteArrayArg) {

    if (byteArrayArg === null || byteArrayArg === undefined)
        throw new Error("byteArrayArg is null or undefined.");

    //TODO check is array-like?

    const wholeChunkCount = Math.trunc(byteArrayArg.length / chunkSize);
    const resultSize = wholeChunkCount * encodedChunkSize + (byteArrayArg.length % chunkSize === 1 ? smallEncodedChunkSize : 0);

    if (resultSize === 0)
        return "";

    const result = new Array(resultSize);
    var resultIndex = 0;
    const wholeChunkLength = wholeChunkCount * chunkSize;
    for (let i = 0; i < wholeChunkLength;) {
        const value = byteArrayArg[i++] * byteSize + byteArrayArg[i++];
        result[resultIndex++] = encoding[value % baseSize];
        result[resultIndex++] = encoding[Math.trunc(value / baseSize) % baseSize];
        result[resultIndex++] = encoding[Math.trunc(value / baseSizeSquared) % baseSize];
    }

    if (byteArrayArg.length % chunkSize === 0)
        return result.join("");

    result[result.length - 2] = encoding[byteArrayArg[byteArrayArg.length - 1] % baseSize];
    result[result.length - 1] = byteArrayArg[byteArrayArg.length - 1] < baseSize ? encoding[0] : encoding[Math.trunc(byteArrayArg[byteArrayArg.length - 1] / baseSize) % baseSize];

    return result.join("");
};

export function decode(utf8StringArg) {

    if (utf8StringArg === null || utf8StringArg === undefined)
        throw new Error("utf8StringArg is null or undefined.");

    if (utf8StringArg.length === 0)
        return [];

    var remainderSize = utf8StringArg.length % encodedChunkSize;
    if (remainderSize === 1)
        throw new Error("utf8StringArg has incorrect length.");

    if (decoding === undefined) {
        decoding = {};
        for (let i = 0; i < encoding.length; ++i)
            decoding[encoding[i]] = i;
    }

    const buffer = new Array(utf8StringArg.length);
    for (let i = 0; i < utf8StringArg.length; ++i) {
        const found = decoding[utf8StringArg[i]];
        if (found === undefined)
            throw new Error("Invalid character at position ".concat(i).concat("."));
        buffer[i] = found;
    }

    const wholeChunkCount = Math.trunc(buffer.length / encodedChunkSize);
    var result = new Array(wholeChunkCount * chunkSize + (remainderSize === chunkSize ? 1 : 0));
    var resultIndex = 0;
    const wholeChunkLength = wholeChunkCount * encodedChunkSize;
    for (let i = 0; i < wholeChunkLength;) {
        const val = buffer[i++] + baseSize * buffer[i++] + baseSizeSquared * buffer[i++];
        result[resultIndex++] = Math.trunc(val / byteSize); //result is always in the range 0-255 - % ByteSize omitted.
        result[resultIndex++] = val % byteSize;
    }

    if (remainderSize === 0)
        return result;

    result[result.length - 1] = buffer[buffer.length - 2] + baseSize * buffer[buffer.length - 1]; //result is always in the range 0-255 - % ByteSize omitted.
    return result;
}

export function decodeToUtf8String(utf8StringArg) {

    var data = decode(utf8StringArg);

    var str = "";
    var count = data.length;
    for (let i= 0; i < count; ++i)
        str += String.fromCharCode(data[i]);

    return str;
}