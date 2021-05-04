const {sign, verify, pack, unpack, signAndPack, unpackAndVerify, signAndPack32, signAndPack45, makeCWT} = require('../lib/index');

const PUBLIC_KEY_PEM = '-----BEGIN CERTIFICATE-----\nMIIBYDCCAQYCEQCAG8uscdLb0ppaneNN5sB7MAoGCCqGSM49BAMCMDIxIzAhBgNV\nBAMMGk5hdGlvbmFsIENTQ0Egb2YgRnJpZXNsYW5kMQswCQYDVQQGEwJGUjAeFw0y\nMTA0MjcyMDQ3MDVaFw0yNjAzMTIyMDQ3MDVaMDYxJzAlBgNVBAMMHkRTQyBudW1i\nZXIgd29ya2VyIG9mIEZyaWVzbGFuZDELMAkGA1UEBhMCRlIwWTATBgcqhkjOPQIB\nBggqhkjOPQMBBwNCAARkJeqyO85dyR+UrQ5Ey8EdgLyf9NtsCrwORAj6T68/elL1\n9aoISQDbzaNYJjdD77XdHtd+nFGTQVpB88wPTwgbMAoGCCqGSM49BAMCA0gAMEUC\nIQDvDacGFQO3tuATpoqf40CBv09nfglL3wh5wBwA1uA7lAIgZ4sOK2iaaTsFNqEN\nAF7zi+d862ePRQ9Lwymr7XfwVm0=\n-----END CERTIFICATE-----';
const ATPUBKEY       = '-----BEGIN CERTIFICATE-----\nMIIBIzCByqADAgECAgRi5XwLMAoGCCqGSM49BAMCMBAxDjAMBgNVBAMMBUVDLU1l\nMB4XDTIxMDQyMzEwMzc1NVoXDTIxMDUyMzEwMzc1NVowEDEOMAwGA1UEAwwFRUMt\nTWUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT4pyqh0AMFtrN/rLF4tKBB+Rhp\n6ttuC6JTQ4c4fIy9f6H/Hjko8v6fYWkz3WrhKV7e0ScI4RLbT6nrv/F/6sJQoxIw\nEDAOBgNVHQ8BAf8EBAMCBaAwCgYIKoZIzj0EAwIDSAAwRQIhAMQjFFnmgFx1scLH\n6+iY9Vyu3EYkHEzNXUv7Zr/H6gJDAiAw7Sry/U7h/X+Hk1MncAqln7dpK2MDKABc\n46ByFwZ+Bw==\n-----END CERTIFICATE-----'
  

const PRIVATE_KEY_P8 = '-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgZgp3uylFeCIIXozb\nZkCkSNr4DcLDxplZ1ax/u7ndXqahRANCAARkJeqyO85dyR+UrQ5Ey8EdgLyf9Nts\nCrwORAj6T68/elL19aoISQDbzaNYJjdD77XdHtd+nFGTQVpB88wPTwgb\n-----END PRIVATE KEY-----';

const TEST_PAYLOAD = {
  "ver": "1.0.0",
  "nam": {
    "fn": "d'Arsøns - van Halen",
    "gn": "François-Joan",
    "fnt": "DARSONS<VAN<HALEN",
    "gnt": "FRANCOIS<JOAN"
  },
  "dob": "2009-02-28",
  "v": [
    {
      "tg": "840539006",
      "vp": "1119349007",
      "mp": "EU/1/20/1528",
      "ma": "ORG-100030215",
      "dn": 2,
      "sd": 2,
      "dt": "2021-04-21",
      "co": "NL",
      "is": "Ministry of Public Health, Welfare and Sport",
      "ci": "urn:uvci:01:NL:PlA8UWS60Z4RZXVALl6GAZ"
    }
  ]
};

const TEST_PAYLOAD_AT = {
  "dob": "1998-02-26", 
  "nam": {
    "fn": "Musterfrau-Gößinger", 
    "fnt": "MUSTERFRAU<GOESSINGER", 
    "gn": "Gabriele", 
    "gnt": "GABRIELE"
  }, 
  "v": [
    {
      "ci": "ATOZQWGY3IOJUXGYTBOVWWC3TO", 
      "co": "AT", 
      "dn": 1, 
      "dt": "2021-02-18", 
      "is": "BMGSPK Austria", 
      "ma": "ORG-100030215", 
      "mp": "EU/1/20/1528", 
      "sd": 2, 
      "tg": "840539006", 
      "vp": "1119305005"
      }
  ], 
  "ver": "1.0.0"
}

test('Sign the json', async () => {
  const signed = await sign(TEST_PAYLOAD, PUBLIC_KEY_PEM, PRIVATE_KEY_P8);
  expect(signed).not.toBe(null);
});

test('Verify the json', async () => {
  // Signed by the original EU source.  They encoded the JSON as a String
  const signed = 'HC1:6BFOXN%TSMAHN-H+XO5XF7:UY%FJ.GDB2SW2/-QJI93RV+H9R/GOD1Z-98Y8/*AIIGN*QCP2KV45W0 T8:QM6$JVSA4U3PS09/KY$NL-QJVA+D2$J48N0-F13+ME 1ZAOL9ML7S6CO-8TH03UZQTM34.D4+78LO5UI2AQ*%VZ7A4GOA053Y6K3P0PAJKIV0J4E93T2YW5P$9 M1TVC%6GP:5TBRB2VGDBB85DVIJG7';
  const result = await unpackAndVerify(signed, PUBLIC_KEY_PEM);
  expect(result).toStrictEqual('{ "Foo":1, "Bar":{ "Field1": "a value",   "integer":1212112121 }}');
});

test('Verify the json from dgc.a-sit.at/', async () => {
  // Signed by the original EU source.  They encoded the JSON as a String
  const signed = 'HC1:NCFOXN%TS3DHZN4HAF*PQFKKGTNA.Q/R8WRU2FCGJ9P+V%%H4G5NOK5F3ZMIN9HNO4*J8OX4W$C2VL*LA 43/IE%TE6UG+ZEAT1HQ13W1:O1YUI%F1PN1/T1J$HTR9/O14SI.J9DYHZROVZ05QNZ 20OP748$NI4L6RXKYQ8FRKBYOBM4T$7U-N0O4RK43%JTXO$WOS%H*-VZIEQKERQ8IY1I$HH%U8 9PS5OH6*ZUFZFEPG:YN/P3JRH8LHGL2-LH/CJTK96L6SR9MU9DV5 R1:PI/E2$4J6AL.+I9UV6$0+BNPHNBC7CTR3$VDY0DUFRLN/Y0Y/K9/IIF0%:K6*K$X4FUTD14//E3:FL.B$JDBLEH-BL1H6TK-CI:ULOPD6LF20HFJC3DAYJDPKDUDBQEAJJKHHGEC8ZI9$JAQJKZ%K.CPM+8172JB0Q/BSRMQ%LBI1IZ72UVMPVNQND%GA.Q4AF- EH5NTTS$*1DK1D.1WB3I4WA+FUC4HLBKHUZNLBV7.XCI:PJ7RY:0K RB3Q0BT AA:40V19G3';
  const cwtPayload = await unpackAndVerify(signed, ATPUBKEY);
  expect(cwtPayload.get(-260).get(1)).toStrictEqual(TEST_PAYLOAD_AT);
});

test('Sign and Verify a Payload (JSON->COSE->JSON)', async () => {
  const signed = await sign(TEST_PAYLOAD, PUBLIC_KEY_PEM, PRIVATE_KEY_P8);
  const result = await verify(signed, PUBLIC_KEY_PEM);
  expect(result).toBe(true);
});

test('Pack And Unpack', async () => {
  const binaryData = new Uint8Array([123, 34, 118, 101, 114, 34, 58, 34, 49, 46, 48, 46, 48, 34]);
  const packed = await pack(binaryData);
  const unpacked = await unpack(packed);
  expect(unpacked.toString()).toStrictEqual(binaryData.toString());
});

test('Sign Pack And Unpack Verify JSON', async () => {
  const signed = await signAndPack(TEST_PAYLOAD, PUBLIC_KEY_PEM, PRIVATE_KEY_P8);
  const resultJSON = await unpackAndVerify(signed, PUBLIC_KEY_PEM);
  expect(resultJSON).toStrictEqual(TEST_PAYLOAD);
});

test('Sign Pack and Unpack Verify a json using Base32', async () => {
  const signed = await signAndPack32(TEST_PAYLOAD, PUBLIC_KEY_PEM, PRIVATE_KEY_P8);
  const result = await unpackAndVerify(signed, PUBLIC_KEY_PEM);
  expect(result).toStrictEqual(TEST_PAYLOAD);
  expect(signed.length).toBe(635);
});

test('Sign Pack and Unpack Verify a json using Base45', async () => {
  const signed = await signAndPack45(TEST_PAYLOAD, PUBLIC_KEY_PEM, PRIVATE_KEY_P8);
  const result = await unpackAndVerify(signed, PUBLIC_KEY_PEM);
  expect(result).toStrictEqual(TEST_PAYLOAD);
  expect(signed.length).toBe(595);
});

test('Make CWT', async () => {
  const cwtPayload = await makeCWT(TEST_PAYLOAD);
  expect(cwtPayload.get(-260).get(1)).toStrictEqual(TEST_PAYLOAD);
});