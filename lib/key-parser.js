import * as ASN from '@fidm/asn1';

const RSA_IOD = "1.2.840.113549.1.1.1";

/**
 * ASN.1 Template for PKCS#8 Public Key.
 */
const PublicKeyValidator = {
    name: 'PublicKeyInfo',
    class: ASN.Class.UNIVERSAL,
    tag: ASN.Tag.SEQUENCE,
    capture: 'publicKeyInfo',
    value: [{
            name: 'PublicKeyInfo.AlgorithmIdentifier',
            class: ASN.Class.UNIVERSAL,
            tag: ASN.Tag.SEQUENCE,
            value: [{
                    name: 'PublicKeyAlgorithmIdentifier.algorithm',
                    class: ASN.Class.UNIVERSAL,
                    tag: ASN.Tag.OID,
                    capture: 'publicKeyOID',
                }],
        }, {
            name: 'PublicKeyInfo.PublicKey',
            class: ASN.Class.UNIVERSAL,
            tag: ASN.Tag.BITSTRING,
            capture: 'publicKey',
        }],
};

// validator for an X.509v3 certificate
const x509CertificateValidator = {
    name: 'Certificate',
    class: ASN.Class.UNIVERSAL,
    tag: ASN.Tag.SEQUENCE,
    value: [{
            name: 'Certificate.TBSCertificate',
            class: ASN.Class.UNIVERSAL,
            tag: ASN.Tag.SEQUENCE,
            capture: 'tbsCertificate',
            value: [{
                    name: 'Certificate.TBSCertificate.version',
                    class: ASN.Class.CONTEXT_SPECIFIC,
                    tag: ASN.Tag.NONE,
                    optional: true,
                    value: [{
                            name: 'Certificate.TBSCertificate.version.integer',
                            class: ASN.Class.UNIVERSAL,
                            tag: ASN.Tag.INTEGER,
                            capture: 'certVersion',
                        }],
                }, {
                    name: 'Certificate.TBSCertificate.serialNumber',
                    class: ASN.Class.UNIVERSAL,
                    tag: ASN.Tag.INTEGER,
                    capture: 'certSerialNumber',
                }, {
                    name: 'Certificate.TBSCertificate.signature',
                    class: ASN.Class.UNIVERSAL,
                    tag: ASN.Tag.SEQUENCE,
                    value: [{
                            name: 'Certificate.TBSCertificate.signature.algorithm',
                            class: ASN.Class.UNIVERSAL,
                            tag: ASN.Tag.OID,
                            capture: 'certinfoSignatureOID',
                        }, {
                            name: 'Certificate.TBSCertificate.signature.parameters',
                            class: ASN.Class.UNIVERSAL,
                            tag: ASN.Tag.OCTETSTRING,
                            optional: true,
                            capture: 'certinfoSignatureParams',
                        }],
                }, {
                    name: 'Certificate.TBSCertificate.issuer',
                    class: ASN.Class.UNIVERSAL,
                    tag: ASN.Tag.SEQUENCE,
                    capture: 'certIssuer',
                }, {
                    name: 'Certificate.TBSCertificate.validity',
                    class: ASN.Class.UNIVERSAL,
                    tag: ASN.Tag.SEQUENCE,
                    value: [{
                            name: 'Certificate.TBSCertificate.validity.notBefore',
                            class: ASN.Class.UNIVERSAL,
                            tag: [ASN.Tag.UTCTIME, ASN.Tag.GENERALIZEDTIME],
                            capture: 'certValidityNotBefore',
                        }, {
                            name: 'Certificate.TBSCertificate.validity.notAfter',
                            class: ASN.Class.UNIVERSAL,
                            tag: [ASN.Tag.UTCTIME, ASN.Tag.GENERALIZEDTIME],
                            capture: 'certValidityNotAfter',
                        }],
                }, {
                    // Name (subject) (RDNSequence)
                    name: 'Certificate.TBSCertificate.subject',
                    class: ASN.Class.UNIVERSAL,
                    tag: ASN.Tag.SEQUENCE,
                    capture: 'certSubject',
                },
                // SubjectPublicKeyInfo
                PublicKeyValidator,
                {
                    // issuerUniqueID (optional)
                    name: 'Certificate.TBSCertificate.issuerUniqueID',
                    class: ASN.Class.CONTEXT_SPECIFIC,
                    tag: ASN.Tag.BOOLEAN,
                    optional: true,
                    value: [{
                            name: 'Certificate.TBSCertificate.issuerUniqueID.id',
                            class: ASN.Class.UNIVERSAL,
                            tag: ASN.Tag.BITSTRING,
                            capture: 'certIssuerUniqueId',
                        }],
                }, {
                    // subjectUniqueID (optional)
                    name: 'Certificate.TBSCertificate.subjectUniqueID',
                    class: ASN.Class.CONTEXT_SPECIFIC,
                    tag: ASN.Tag.INTEGER,
                    optional: true,
                    value: [{
                            name: 'Certificate.TBSCertificate.subjectUniqueID.id',
                            class: ASN.Class.UNIVERSAL,
                            tag: ASN.Tag.BITSTRING,
                            capture: 'certSubjectUniqueId',
                        }],
                }, {
                    // Extensions (optional)
                    name: 'Certificate.TBSCertificate.extensions',
                    class: ASN.Class.CONTEXT_SPECIFIC,
                    tag: ASN.Tag.BITSTRING,
                    capture: 'certExtensions',
                    optional: true,
                }],
        }, {
            // AlgorithmIdentifier (signature algorithm)
            name: 'Certificate.signatureAlgorithm',
            class: ASN.Class.UNIVERSAL,
            tag: ASN.Tag.SEQUENCE,
            value: [{
                    // algorithm
                    name: 'Certificate.signatureAlgorithm.algorithm',
                    class: ASN.Class.UNIVERSAL,
                    tag: ASN.Tag.OID,
                    capture: 'certSignatureOID',
                }, {
                    name: 'Certificate.TBSCertificate.signature.parameters',
                    class: ASN.Class.UNIVERSAL,
                    tag: ASN.Tag.OCTETSTRING,
                    optional: true,
                    capture: 'certSignatureParams',
                }],
        }, {
            name: 'Certificate.signatureValue',
            class: ASN.Class.UNIVERSAL,
            tag: ASN.Tag.BITSTRING,
            capture: 'certSignature',
        }],
};

export function getDERFromPEM(pem) {
  return ASN.PEM.parse(pem)[0].body;
}

function toBase64URL(buffer) {
    return buffer.toString('base64').replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_")
}

export function getJWTFromPEM(pem) {
  const obj = ASN.ASN1.fromDER(getDERFromPEM(pem), true);

  let publicKey = { oid: undefined, keyRaw: undefined};
  if (pem.includes("CERTIFICATE")) {
    const certCaptures = {};
    obj.validate(x509CertificateValidator, certCaptures);

    const publicKeyCaptures = {};
    certCaptures.publicKeyInfo.validate(PublicKeyValidator, publicKeyCaptures);

    publicKey.oid = ASN.ASN1.parseOID(publicKeyCaptures.publicKeyOID.bytes)
    publicKey.keyRaw = ASN.ASN1.parseBitString(publicKeyCaptures.publicKey.bytes).buf;
  } else {
    const captures = {};
    obj.validate(PublicKeyValidator, captures);
    
    publicKey.oid = ASN.ASN1.parseOID(captures.publicKeyOID.bytes)
    publicKey.keyRaw = ASN.ASN1.parseBitString(captures.publicKey.bytes).buf;
  }

  // if RSA
  // Find better ways to parse key parameters. 
  if (publicKey.oid === RSA_IOD) {
    let pk = publicKey.keyRaw
    const keyMod = toBase64URL(pk.slice(9, pk.length - 5));
    const keyExp = toBase64URL(pk.slice(pk.length - 3,pk.length));
    return {alg: 'PS256', kid: undefined, n: keyMod, e: keyExp};
  } else {
    let pk = publicKey.keyRaw
    const keyX = toBase64URL(pk.slice(1, 1+32));
    const keyY = toBase64URL(pk.slice(33,33+32));
    return {alg: 'ES256', kid: undefined, x: keyX, y: keyY};
  }
}