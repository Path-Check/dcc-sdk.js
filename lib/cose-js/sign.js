/**
 * Modified version of @cose-js with added support for RSASSA-PSS
 */

import * as cbor from 'cbor';
import webcrypto from 'isomorphic-webcrypto';
import * as common from './common';

const EMPTY_BUFFER = common.EMPTY_BUFFER;
const Tagged = cbor.Tagged;

const SignTag = 98;
const Sign1Tag = 18;

function subtle() {
  return webcrypto.subtle ? webcrypto.subtle : window.crypto.subtle;
}

const AlgFromTags = {};
AlgFromTags[-7] = { 'sign': 'ES256', 'digest': 'SHA-256' };  
AlgFromTags[-35] = { 'sign': 'ES384', 'digest': 'SHA-384' };
AlgFromTags[-36] = { 'sign': 'ES512', 'digest': 'SHA-512' };
AlgFromTags[-37] = { 'sign': 'PS256', 'digest': 'SHA-256' };
AlgFromTags[-38] = { 'sign': 'PS384', 'digest': 'SHA-384' };
AlgFromTags[-39] = { 'sign': 'PS512', 'digest': 'SHA-512' };

const COSEAlgToNodeAlg = {
  'ES256': { 'sign': 'ECDSA', kty: 'EC', 'curve': 'P-256', 'digest': 'SHA-256' },
  'ES384': { 'sign': 'ECDSA', kty: 'EC', 'curve': 'P-384', 'digest': 'SHA-384' },
  'ES512': { 'sign': 'ECDSA', kty: 'EC', 'curve': 'P-521', 'digest': 'SHA-512' },
  'PS256': { 'sign': 'RSA-PSS', kty: 'RSA', 'digest': 'SHA-256', saltLength: 32  },
  'PS384': { 'sign': 'RSA-PSS', kty: 'RSA', 'digest': 'SHA-384', saltLength: 48  },
  'PS512': { 'sign': 'RSA-PSS', kty: 'RSA', 'digest': 'SHA-512', saltLength: 64  }
};

async function doSign (SigStructure, signer, alg) {
  if (!AlgFromTags[alg]) {
    throw new Error('Unknown algorithm, ' + alg);
  }
  if (!COSEAlgToNodeAlg[AlgFromTags[alg].sign]) {
    throw new Error('Unsupported algorithm, ' + AlgFromTags[alg].sign);
  }

  let toBeSigned = cbor.encode(SigStructure);
  let algo = {
      name: COSEAlgToNodeAlg[AlgFromTags[alg].sign].sign,
      namedCurve: COSEAlgToNodeAlg[AlgFromTags[alg].sign].curve,
      hash: COSEAlgToNodeAlg[AlgFromTags[alg].sign].digest, 
      saltLength: COSEAlgToNodeAlg[AlgFromTags[alg].sign].saltLength
  };

  const importedKey = await subtle().importKey('pkcs8', signer.key.pkcs8, algo, false, ['sign']); 
  return await subtle().sign(algo, importedKey, toBeSigned);
}

export function create(headers, payload, signers, options) {
  options = options || {};
  let u = headers.u || {};
  let p = headers.p || {};

  p = common.TranslateHeaders(p);
  u = common.TranslateHeaders(u);
  let bodyP = p || {};
  bodyP = (bodyP.size === 0) ? EMPTY_BUFFER : cbor.encode(bodyP);
  if (Array.isArray(signers)) {
    if (signers.length === 0) {
      throw new Error('There has to be at least one signer');
    }
    if (signers.length > 1) {
      throw new Error('Only one signer is supported');
    }
    // TODO handle multiple signers
    const signer = signers[0];
    const externalAAD = signer.externalAAD || EMPTY_BUFFER;
    let signerP = signer.p || {};
    let signerU = signer.u || {};

    signerP = common.TranslateHeaders(signerP);
    signerU = common.TranslateHeaders(signerU);
    const alg = signerP.get(common.HeaderParameters.alg);
    signerP = (signerP.size === 0) ? EMPTY_BUFFER : cbor.encode(signerP);

    const SigStructure = [
      'Signature',
      bodyP,
      signerP,
      externalAAD,
      payload
    ];
    return doSign(SigStructure, signer, alg).then((sig) => {
      if (p.size === 0 && options.encodep === 'empty') {
        p = EMPTY_BUFFER;
      } else {
        p = cbor.encode(p);
      }
      const signed = [p, u, payload, [[signerP, signerU, sig]]];
      return cbor.encode(options.excludetag ? signed : new Tagged(SignTag, signed));
    });
  } else {
    const signer = signers;
    const externalAAD = signer.externalAAD || EMPTY_BUFFER;
    const alg = p.get(common.HeaderParameters.alg) || u.get(common.HeaderParameters.alg);
    const SigStructure = [
      'Signature1',
      bodyP,
      externalAAD,
      payload
    ];
    return doSign(SigStructure, signer, alg).then((sig) => {
      if (p.size === 0 && options.encodep === 'empty') {
        p = EMPTY_BUFFER;
      } else {
        p = cbor.encode(p);
      }
      const signed = [p, u, payload, sig];
      return cbor.encodeCanonical(options.excludetag ? signed : new Tagged(Sign1Tag, signed));
    });
  }
};

async function doVerify (SigStructure, verifier, alg, sig) {
  if (!AlgFromTags[alg]) {
    throw new Error('Unknown algorithm, ' + alg);
  }
  if (!COSEAlgToNodeAlg[AlgFromTags[alg].sign]) {
    throw new Error('Unsupported algorithm, ' + AlgFromTags[alg].sign);
  }
  const ToBeSigned = cbor.encode(SigStructure);

  let algo = {
      name: COSEAlgToNodeAlg[AlgFromTags[alg].sign].sign,
      namedCurve: COSEAlgToNodeAlg[AlgFromTags[alg].sign].curve,
      hash: COSEAlgToNodeAlg[AlgFromTags[alg].sign].digest, 
      saltLength: COSEAlgToNodeAlg[AlgFromTags[alg].sign].saltLength
  };

  let jwkData = {
    kty: COSEAlgToNodeAlg[AlgFromTags[alg].sign].kty,
    crv: COSEAlgToNodeAlg[AlgFromTags[alg].sign].curve,
    e: verifier.jwk.e,
    n: verifier.jwk.n,
    x: verifier.jwk.x,
    y: verifier.jwk.y
  };

  const importedKey = await subtle().importKey('jwk', jwkData, algo, false, ['verify']);
  return await subtle().verify(algo, importedKey, sig, ToBeSigned); 
}

function getSigner (signers, verifier) {
  for (let i = 0; i < signers.length; i++) {
    const kid = signers[i][1].get(common.HeaderParameters.kid); // TODO create constant for header locations
    if (kid.equals(Buffer.from(verifier.jwk.kid, 'utf8'))) {
      return signers[i];
    }
  }
}

function getCommonParameter (first, second, parameter) {
  let result;
  if (first.get) {
    result = first.get(parameter);
  }
  if (!result && second.get) {
    result = second.get(parameter);
  }
  return result;
}

export function verify(payload, verifier, publicKeyPem, options) {
  options = options || {};
  return cbor.decodeFirst(payload)
    .then((obj) => {
      let type = options.defaultType ? options.defaultType : SignTag;
      if (obj instanceof Tagged) {
        if (obj.tag !== SignTag && obj.tag !== Sign1Tag) {
          throw new Error('Unexpected cbor tag, \'' + obj.tag + '\'');
        }
        type = obj.tag;
        obj = obj.value;
      }

      if (!Array.isArray(obj)) {
        throw new Error('Expecting Array');
      }

      if (obj.length !== 4) {
        throw new Error('Expecting Array of lenght 4');
      }

      let [p, u, plaintext, signers] = obj;

      if (type === SignTag && !Array.isArray(signers)) {
        throw new Error('Expecting signature Array');
      }

      p = (!p.length) ? EMPTY_BUFFER : cbor.decodeFirstSync(p);
      u = (!u.size) ? EMPTY_BUFFER : u;

      let signer = (type === SignTag ? getSigner(signers, verifier) : signers);

      if (!signer) {
        throw new Error('Failed to find signer with kid' + verifier.key.kid);
      }

      if (type === SignTag) {
        const externalAAD = verifier.externalAAD || EMPTY_BUFFER;
        let [signerP, , sig] = signer;
        signerP = (!signerP.length) ? EMPTY_BUFFER : signerP;
        p = (!p.size) ? EMPTY_BUFFER : cbor.encode(p);
        const signerPMap = cbor.decode(signerP);
        const alg = signerPMap.get(common.HeaderParameters.alg);
        const SigStructure = [
          'Signature',
          p,
          signerP,
          externalAAD,
          plaintext
        ];
        return doVerify(SigStructure, verifier, alg, sig)
          .then(() => {
            return plaintext;
          });
      } else {
        const externalAAD = verifier.externalAAD || EMPTY_BUFFER;

        const alg = getCommonParameter(p, u, common.HeaderParameters.alg);
        p = (!p.size) ? EMPTY_BUFFER : cbor.encode(p);
        const SigStructure = [
          'Signature1',
          p,
          externalAAD,
          plaintext
        ];
        return doVerify(SigStructure, verifier, alg, signer, publicKeyPem)
          .then((verified) => {
            if (verified) 
              return plaintext;
            else
              return undefined;
          });
      }
    });
};
