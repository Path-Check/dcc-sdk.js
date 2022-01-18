// Needs to import only the sign and verify functions, not the encrypt and decrypt due to additional dependencies. 
import * as cose from './cose-js/sign.js'
import {createHash as rawHash} from "sha256-uint8array";

import zlib from 'pako';
import * as cbor from 'cbor';

import * as base64 from 'base64-js';

import base45 from 'base45';

import { resolveKey, addCachedCerts, addCachedKeys } from './resolver'; 
import { getJWTFromPEM, getDERFromPEM } from './key-parser';

const URI_SCHEMA = 'HC1';

const CWT_ISSUER = 1;
const CWT_SUBJECT = 2;
const CWT_AUDIENCE = 3;
const CWT_EXPIRATION = 4;
const CWT_NOT_BEFORE = 5;
const CWT_ISSUED_AT = 6;
const CWT_ID = 7;
const CWT_HCERT = -260;
const CWT_HCERT_V1 = 1;

const CWT_STRING_PAYLOAD = 99;

const COSE_ALG_TAG = 1;
const COSE_KID_TAG = 4;

const NOT_SUPPORTED = "not_supported";                  // QR Standard not supported by this algorithm
const INVALID_ENCODING = "invalid_encoding";            // could not decode Base45 for DCC, Base10 for SHC
const INVALID_COMPRESSION = "invalid_compression";      // could not decompress the byte array
const INVALID_SIGNING_FORMAT = "invalid_signing_format";// invalid COSE, JOSE, W3C VC Payload
const KID_NOT_INCLUDED = "kid_not_included";            // unable to resolve the issuer ID
const ISSUER_NOT_TRUSTED = "issuer_not_trusted";        // issuer is not found in the registry
const TERMINATED_KEYS = "terminated_keys";              // issuer was terminated by the registry
const EXPIRED_KEYS = "expired_keys";                    // keys expired
const REVOKED_KEYS = "revoked_keys";                    // keys were revoked by the issuer
const INVALID_SIGNATURE = "invalid_signature";          // signature doesn't match
const VERIFIED = "verified";                            // Verified content.

function getKeyIDFromPEM(pem) {
  return rawHash().update(getDERFromPEM(pem)).digest().slice(0,8);
}

export async function sign(payload, publicKeyPem, privateKeyP8) {
  const jwt = getJWTFromPEM(publicKeyPem);
  const keyId = getKeyIDFromPEM(publicKeyPem);

  const headers = {
    'p': { 
      'alg': jwt.alg, 
      'kid': keyId 
    }, 
    'u': {}
  };

  const signer = {
    'key': {
      'pkcs8': getDERFromPEM(privateKeyP8) 
    }
  };

  const cborPayload = cbor.encode(payload);
  return cose.create(headers, cborPayload, signer);
}

/*
 * I am not sure if I should build this by hand. 
 */
export async function makeCWT(payload, monthsToExpire, issuer) {
  let cwt = new Map();

  let iss = new Date();
  cwt.set(CWT_ISSUED_AT, Math.round(iss.getTime()/1000));

  if (monthsToExpire) {
    let exp = new Date(iss);
    exp.setMonth(exp.getMonth()+monthsToExpire);
    cwt.set(CWT_EXPIRATION, Math.round(exp.getTime()/1000));
  }
  
  if (issuer) {
    cwt.set(CWT_ISSUER, issuer);
  }

  cwt.set(CWT_HCERT, new Map()); 
  cwt.get(CWT_HCERT).set(CWT_HCERT_V1, payload);  
  return cwt;
}

export async function parseCWT(cwt) {
  if (cwt.get(CWT_HCERT))
    return cwt.get(CWT_HCERT).get(CWT_HCERT_V1);
  else 
    return JSON.parse(cwt.get(CWT_STRING_PAYLOAD))
}

function toBase64(bytes) {
  return base64.fromByteArray(bytes);
}

function toBase64URL(bytes) {
  return toBase64(bytes).replace(/\+/g,'-').replace(/\//g,'_').replace(/\=+$/m,'');
}

function getCOSEHeaderParams(header) {
  let headerObj;
  // Sometimes the header has to be decoded. 
  if (header instanceof Buffer || header  instanceof Uint8Array) {
    if (header.length == 0) {
      return {};
    }
    headerObj = cbor.decode(header);
  } 

  // Sometimes the header is already decoded. 
  if (header instanceof Map) {
    headerObj = header;
  }

  if (headerObj) {
    let algorithm;
    let kid; 

    if (headerObj.get(COSE_ALG_TAG))
      algorithm = headerObj.get(COSE_ALG_TAG);
    if (headerObj.get(COSE_KID_TAG))
      kid = new Uint8Array(headerObj.get(COSE_KID_TAG));

    return {alg: algorithm, kid: kid};
  }
  return {};
} 

async function getIssuerKeyId(coseContent) {
  let cborObj = cbor.decode(new Uint8Array(coseContent));

  if (!cborObj) { 
    console.log("Not a readable COSE");
    return undefined;
  }

  let cborObjValue = cborObj.value;

  if (!cborObjValue) { 
    if (Array.isArray(cborObj)) {
      console.warn("COSE object with no Value field", cborObj);
      cborObjValue = cborObj;
    } else { 
      console.log("COSE object with no Value field and no array", cborObj);
      return undefined;
    }
  }  

  let [protec, unprotec, payload, signature] = cborObjValue;

  let cwtIssuer;

  try {
    let decodedPayload = cbor.decode(payload); 
    if (decodedPayload instanceof Map) {
      cwtIssuer = decodedPayload.get(CWT_ISSUER);
    }
  } catch (err) {
    console.log(payload, err);
  }

  let protectedData = getCOSEHeaderParams(protec);
  let unProtectedData = getCOSEHeaderParams(unprotec);

  return {
    alg: protectedData.alg ? protectedData.alg : unProtectedData.alg, 
    kid: protectedData.kid ? protectedData.kid : unProtectedData.kid, 
    iss: cwtIssuer
  };
}

export async function verify(coseContent, addPublicKeyPem) {
  let rawContents
  let plainObj
  try {
    rawContents = await decodeCbor(coseContent);
    let obj = await cbor.decodeFirst(coseContent)
    if (obj.tag) { obj = obj.value; }
    let [p, u, plaintext, signers] = obj;
    plainObj = cbor.decode(plaintext)
    
    if (!rawContents || !plaintext) {
      return { status: INVALID_SIGNING_FORMAT, raw: rawContents }
    }
  } catch (err) {
    console.log(err)
    return { status: INVALID_SIGNING_FORMAT, raw: rawContents }
  }

  const keyID = await getIssuerKeyId(coseContent);

  if (!keyID || !keyID.kid) return { status: KID_NOT_INCLUDED, contents: plainObj, raw: rawContents }

  // Tries B64URL First
  let issuer = await resolveKey(toBase64(keyID.kid));
  
  // if not then use the key passed on the parameter. 
  if (!issuer && addPublicKeyPem) {
    issuer = { didDocument: addPublicKeyPem, status: "current" }
  }

  if (!issuer) {
    return { status: ISSUER_NOT_TRUSTED, contents: plainObj, raw: rawContents };
  }

  let jwk = getJWTFromPEM(issuer.didDocument);

  switch (issuer.status) {
    case "revoked": return    { status: REVOKED_KEYS, contents: plainObj, issuer: issuer, raw: rawContents }
    case "terminated": return { status: TERMINATED_KEYS, contents: plainObj, issuer: issuer, raw: rawContents }
    case "expired": return    { status: EXPIRED_KEYS, contents: plainObj, issuer: issuer, raw: rawContents }
  }

  try {
    jwk.kid = toBase64(keyID.kid);

    const verified = await cose.verify(coseContent, { 'jwk': jwk });
    return { status: VERIFIED, contents: cbor.decode(verified), issuer: issuer, raw: rawContents }
  } catch (err) {
     return { status: INVALID_SIGNATURE, contents: plainObj, issuer: issuer, raw: rawContents }
  }
}

function removePrefix(uri) {
  let data = uri;

  // Backwards compatibility.
  if (data.startsWith(URI_SCHEMA)) {
    data = data.substring(3)
    if (data.startsWith(':')) {
      data = data.substring(1)
    } else {
      console.warn("Warning: unsafe HC1: header from older versions");
    };
  } else {
      console.warn("Warning: no HC1: header from older versions");
  };
  return data;
}

export async function unpack(uri) {
  const data = removePrefix(uri);

  try {
    let unencodedData = base45.decode(data);

    // Check if it was zipped (Backwards compatibility.)
    if (unencodedData[0] == 0x78) {
      unencodedData = zlib.inflate(unencodedData);
    }

    return unencodedData;
  } catch (err) {
    console.log(err)
    return
  }
}

async function decodeCbor(cborObj) {
  if (cborObj instanceof Buffer || cborObj instanceof Uint8Array) {
    try {  
      cborObj = cbor.decode(cborObj);
      for (var key in cborObj) {
        cborObj[key] = await decodeCbor(cborObj[key]);
      }
    } catch {
      cborObj = cborObj.toString('base64');
    }
  } 

  if (Array.isArray(cborObj)) {
    for (let i=0; i<cborObj.length; i++) {
      cborObj[i] = await decodeCbor(cborObj[i])
    }
  }

  if (cborObj instanceof Map) {
    for (const [key, value] of cborObj.entries()) {
      cborObj.set(key, await decodeCbor(cborObj.get(key)));
    }
  }

  return cborObj;
}

export async function debug(uri) {
  return await decodeCbor(await unpack(uri));
}

export async function unpackAndVerify(uri, publicKeyPem) {
  const data = removePrefix(uri);

  try { // Checks if the data is Base45
    base45.decode(data);
  } catch (err) {
    console.log(err)
    return { status: INVALID_ENCODING, qr: uri };
  }

  const cbor = await unpack(uri);

  if (!cbor) { 
    return { status: INVALID_COMPRESSION, qr: uri };
  }

  const verified = await verify(cbor, publicKeyPem);
  return {...verified, qr: uri} ;
}

export async function pack(payload) {
  const zipped = zlib.deflate(payload);
  return URI_SCHEMA + ':' + base45.encode(zipped);
}

export async function signAndPack(payload, publicKeyPem, privateKeyP8) {
  return await pack(await sign(payload, publicKeyPem, privateKeyP8));
}

export {addCachedCerts, addCachedKeys};

