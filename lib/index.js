'use strict'

// Needs to import only the sign and verify functions, not the encrypt and decrypt due to additional dependencies. 
const cose = require('cose-js/lib/sign.js')
const rawHash = require("sha256-uint8array").createHash;
const { Certificate, PrivateKey } = require('@fidm/x509');
const zlib = require('pako');
const cbor = require('cbor');
const base45 = require('base45-js');
const base32 = require('hi-base32');

const URI_SCHEMA = 'HC1';

function getParamsFromPEM(publicKeyPem) {
  const cert = Certificate.fromPEM(publicKeyPem);
  const fingerprint = rawHash().update(cert.raw).digest();
  const keyID = fingerprint.slice(0,8);
  
  let pk = cert.publicKey.keyRaw
  const keyB = Buffer.from(pk.slice(0, 1));
  const keyX = Buffer.from(pk.slice(1, 1+32));
  const keyY = Buffer.from(pk.slice(33,33+32));

  return {keyID: keyID, keyB: keyB, keyX: keyX, keyY: keyY};
}

function getPrivateKeyFromP8(privateKeyP8) {
  // Highly ES256 specific - extract the 'D' (private key) for signing.
  const pk = PrivateKey.fromPEM(privateKeyP8)
  return Buffer.from(pk.keyRaw.slice(7,7+32))
}

function isBase32(payload) {
  let b32_regex = /^[A-Z2-7]+=*$/;
  return b32_regex.exec(payload);
}

function isBase45(payload) {
  let b45_regex = /^[A-Z0-9 $%*+./:-]+$/;
  return b45_regex.exec(payload);
}

function pad(base32Str) {
    switch (base32Str.length % 8) {
        case 2: return base32Str + "======"; 
        case 4: return base32Str + "===="; 
        case 5: return base32Str + "==="; 
        case 7: return base32Str + "="; 
    }
    return base32Str;
}

function rmPad(base32Str) {
    return base32Str.replaceAll("=", "");
}   

function b32URLencode(data) {
  return rmPad(base32.encode(data));
}

function b32URLdecode(data) {
  return base32.decode.asBytes(pad(data));
}

async function sign(payload, publicKeyPem, privateKeyP8) {
  const headers = {
    'p': { 
      'alg': 'ES256', 
      'kid': getParamsFromPEM(publicKeyPem).keyID 
    }, 
    'u': {}
  };

  const signer = {
    'key': {
      'd': getPrivateKeyFromP8(privateKeyP8) 
    }
  };

  const cborPayload = cbor.encode(payload);
  return cose.create(headers, cborPayload, signer);
}

async function verifyAndReturnPayload(coseContent, publicKeyPem) {
  const keyParams = getParamsFromPEM(publicKeyPem);
  const verifier = { 
    'key': { 
      'x': keyParams.keyX, 
      'y': keyParams.keyY,  
      'kid': keyParams.keyID,
    } 
  };

  const verified = await cose.verify(coseContent,verifier);
  const jsonPayload = cbor.decode(verified);
  return jsonPayload; 
}

async function verify(coseContent, publicKeyPem) {
  try {
    await verifyAndReturnPayload(coseContent, publicKeyPem);
    return true;
  } catch (err) {
    console.log(err);
    return false;
  }
}

async function unpack(uri) {
  let data = uri;

  // Backwards compatibility.
  if (data.startsWith(URI_SCHEMA)) {
    data = data.substring(3)
    if (data.startsWith(':')) {
      data = data.substring(1)
    } else {
      console.log("Warning: unsafe HC1: header - update to v0.0.4");
    };
  } else {
      console.log("Warning: no HC1: header - update to v0.0.4");
  };

  if (isBase32(data)) {
    data = Buffer.from(b32URLdecode(data));
  } else if (isBase45(data)) {
    data = base45.decode(data);
  } else {
    console.log("Warning: Payload was not encoded correctly", data);
  }

  // Check if it was zipped (Backwards compatibility.)
  if (data[0] == 0x78) {
    data = zlib.inflate(data)
  }

  return data;
}

async function unpackAndVerify(uri, publicKeyPem) {
  try {
    return await verifyAndReturnPayload(await unpack(uri), publicKeyPem);
  } catch (err) {
    console.log(err);
    return undefined;
  }
}

async function pack32(payload) {
  const zipped = zlib.deflate(payload);
  return URI_SCHEMA + ':' + b32URLencode(zipped);
}

async function pack45(payload) {
  const zipped = zlib.deflate(payload);
  return URI_SCHEMA + ':' + base45.encode(zipped);
}

async function pack(payload) {
  return await pack45(payload);
}

async function signAndPack32(payload, publicKeyPem, privateKeyP8) {
  return await pack32(await sign(payload, publicKeyPem, privateKeyP8));
}

async function signAndPack45(payload, publicKeyPem, privateKeyP8) {
  return await pack45(await sign(payload, publicKeyPem, privateKeyP8));
}

async function signAndPack(payload, publicKeyPem, privateKeyP8) {
  return await pack45(await sign(payload, publicKeyPem, privateKeyP8));
}

module.exports = {
  sign, verify, pack, unpack, signAndPack, unpackAndVerify, signAndPack32, signAndPack45
};
