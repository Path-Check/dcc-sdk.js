import fetch from 'cross-fetch'

let TRUST_REGISTRY = {}

let LAST_FETCH = undefined;
const ONE_DAY_IN_MSECONDS = 86400000;

/** add kid, public cert PEM pairs  */
export function addCachedCerts(array) {
  for (const [key, value] of Object.entries(array)) {
    TRUST_REGISTRY[key] = {
      "displayName": {  "en": "" },
      "entityType": "issuer",
      "status": "current",
      "credentialType": ["v","t","r"],
      "validFromDT":  "2021-01-01T01:00:00.000Z",
      "didDocument": '-----BEGIN CERTIFICATE-----\n' + value + '\n-----END CERTIFICATE-----'
    }
  }
}

/** add kid, public key PEM pairs  */
export function addCachedKeys(array) {
  for (const [key, value] of Object.entries(array)) {
    TRUST_REGISTRY[key] = {
      "displayName": {  "en": "" },
      "entityType": "issuer",
      "status": "current",
      "credentialType": ["v","t","r"],
      "validFromDT":  "2021-01-01T01:00:00.000Z",
      "didDocument": '-----BEGIN PUBLIC KEY-----\n' + value + '\n-----END PUBLIC KEY-----'
    }
  }
}

export async function resolveKey(kID) {
  if (!TRUST_REGISTRY[kID] && (!LAST_FETCH || new Date().getTime() > LAST_FETCH.getTime() + ONE_DAY_IN_MSECONDS )) {
    // Loading PathCheck Registry
    console.log('KeyID not found: ', kID, ' fetching certificates from PathCheck\'s Trust Registry')

    try {
      const res = await fetch('https://raw.githubusercontent.com/Path-Check/trust-registry/main/registry.json', {method: 'GET', mode: 'no-cors'})
      const data = await res.text()
      TRUST_REGISTRY = JSON.parse(data)["EUDCC"];
    } catch (e) {
      console.log(e);
    }

    LAST_FETCH = new Date();
  }

  if (TRUST_REGISTRY[kID]) {
    return TRUST_REGISTRY[kID];
  }

  return undefined
}
