/**
 * Unchanged copy from @cose-js
 */
const AlgToTags = {
  'RS512': -259,
  'RS384': -258,
  'RS256': -257,
  'PS256': -37,
  'PS384': -38,
  'PS512': -39,
  'ECDH-SS-512': -28,
  'ECDH-SS': -27,
  'ECDH-ES-512': -26,
  'ECDH-ES': -25,
  'ES256': -7,
  'ES512': -36,
  'direct': -6,
  'A128GCM': 1,
  'A192GCM': 2,
  'A256GCM': 3,
  'SHA-256_64': 4,
  'SHA-256-64': 4,
  'HS256/64': 4,
  'SHA-256': 5,
  'HS256': 5,
  'SHA-384': 6,
  'HS384': 6,
  'SHA-512': 7,
  'HS512': 7,
  'AES-CCM-16-64-128': 10,
  'AES-CCM-16-128/64': 10,
  'AES-CCM-16-64-256': 11,
  'AES-CCM-16-256/64': 11,
  'AES-CCM-64-64-128': 12,
  'AES-CCM-64-128/64': 12,
  'AES-CCM-64-64-256': 13,
  'AES-CCM-64-256/64': 13,
  'AES-MAC-128/64': 14,
  'AES-MAC-256/64': 15,
  'AES-MAC-128/128': 25,
  'AES-MAC-256/128': 26,
  'AES-CCM-16-128-128': 30,
  'AES-CCM-16-128/128': 30,
  'AES-CCM-16-128-256': 31,
  'AES-CCM-16-256/128': 31,
  'AES-CCM-64-128-128': 32,
  'AES-CCM-64-128/128': 32,
  'AES-CCM-64-128-256': 33,
  'AES-CCM-64-256/128': 33
};

const Translators = {
  'kid': (value) => {
    return Buffer.from(value, 'utf8');
  },
  'alg': (value) => {
    if (!(AlgToTags[value])) {
      throw new Error('Unknown \'alg\' parameter, ' + value);
    }
    return AlgToTags[value];
  }
};

const HeaderParameters = {
  'partyUNonce': -22,
  'static_key_id': -3,
  'static_key': -2,
  'ephemeral_key': -1,
  'alg': 1,
  'crit': 2,
  'content_type': 3,
  'ctyp': 3, // one could question this but it makes testing easier
  'kid': 4,
  'IV': 5,
  'Partial_IV': 6,
  'counter_signature': 7
};

var EMPTY_BUFFER = Buffer.alloc(0);

function TranslateHeaders(header) {
  const result = new Map();
  for (const param in header) {
    if (!HeaderParameters[param]) {
      throw new Error('Unknown parameter, \'' + param + '\'');
    }
    let value = header[param];
    if (Translators[param]) {
      value = Translators[param](header[param]);
    }
    if (value !== undefined && value !== null) {
      result.set(HeaderParameters[param], value);
    }
  }
  return result;
};

export {HeaderParameters, TranslateHeaders, EMPTY_BUFFER};