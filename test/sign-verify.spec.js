const {sign, verify, pack, unpack, signAndPack, unpackAndVerify, signAndPack32, signAndPack45, makeCWT, parseCWT, debug, addCachedCerts, addCachedKeys} = require('../lib/index');
const expect = require('chai').expect; 

const {CERT_TEST_LIST, PUBKEY_TEST_LIST} = require('./resolver.test.js');

addCachedCerts(CERT_TEST_LIST);
addCachedKeys(PUBKEY_TEST_LIST);

const PUBLIC_KEY_PEM = '-----BEGIN CERTIFICATE-----\nMIIBYDCCAQYCEQCAG8uscdLb0ppaneNN5sB7MAoGCCqGSM49BAMCMDIxIzAhBgNV\nBAMMGk5hdGlvbmFsIENTQ0Egb2YgRnJpZXNsYW5kMQswCQYDVQQGEwJGUjAeFw0y\nMTA0MjcyMDQ3MDVaFw0yNjAzMTIyMDQ3MDVaMDYxJzAlBgNVBAMMHkRTQyBudW1i\nZXIgd29ya2VyIG9mIEZyaWVzbGFuZDELMAkGA1UEBhMCRlIwWTATBgcqhkjOPQIB\nBggqhkjOPQMBBwNCAARkJeqyO85dyR+UrQ5Ey8EdgLyf9NtsCrwORAj6T68/elL1\n9aoISQDbzaNYJjdD77XdHtd+nFGTQVpB88wPTwgbMAoGCCqGSM49BAMCA0gAMEUC\nIQDvDacGFQO3tuATpoqf40CBv09nfglL3wh5wBwA1uA7lAIgZ4sOK2iaaTsFNqEN\nAF7zi+d862ePRQ9Lwymr7XfwVm0=\n-----END CERTIFICATE-----';
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

const TEST_PAYLOAD_SE = {
    "v": [
      {
        "ci": "urn:uvci:01:SE:EHM/100000024GI5HMGZKSMS",
        "co": "SE",
        "dn": 2,
        "dt": "2021-03-18",
        "is": "Swedish eHealth Agency",
        "ma": "ORG-100030215",
        "mp": "EU/1/21/1529",
        "sd": 2,
        "tg": "840539006",
        "vp": "J07BX03"
      }
    ],
    "dob": "1958-11-11",
    "nam": {
      "fn": "Lövström",
      "gn": "Oscar",
      "fnt": "LOEVSTROEM",
      "gnt": "OSCAR"
    },
    "ver": "1.0.0"
}

describe('EU DCC', function() {
  it('should Sign the json', async () => {
    const signed = await sign(TEST_PAYLOAD, PUBLIC_KEY_PEM, PRIVATE_KEY_P8);
    expect(signed).to.not.be.null;
  });

  it('should Verify the json', async () => {
    // Signed by the original EU source.  They encoded the JSON as a String
    const signed = 'HC1:6BFOXN%TSMAHN-H+XO5XF7:UY%FJ.GDB2SW2/-QJI93RV+H9R/GOD1Z-98Y8/*AIIGN*QCP2KV45W0 T8:QM6$JVSA4U3PS09/KY$NL-QJVA+D2$J48N0-F13+ME 1ZAOL9ML7S6CO-8TH03UZQTM34.D4+78LO5UI2AQ*%VZ7A4GOA053Y6K3P0PAJKIV0J4E93T2YW5P$9 M1TVC%6GP:5TBRB2VGDBB85DVIJG7';
    const result = await unpackAndVerify(signed);
    expect(result).to.eql('{ "Foo":1, "Bar":{ "Field1": "a value",   "integer":1212112121 }}');
  });

  it('should Verify the json from Austria', async () => {
    // Signed by the original EU source.  They encoded the JSON as a String
    const signed = 'HC1:NCFOXN%TS3DHZN4HAF*PQFKKGTNA.Q/R8WRU2FCGJ9P+V%%H4G5NOK5F3ZMIN9HNO4*J8OX4W$C2VL*LA 43/IE%TE6UG+ZEAT1HQ13W1:O1YUI%F1PN1/T1J$HTR9/O14SI.J9DYHZROVZ05QNZ 20OP748$NI4L6RXKYQ8FRKBYOBM4T$7U-N0O4RK43%JTXO$WOS%H*-VZIEQKERQ8IY1I$HH%U8 9PS5OH6*ZUFZFEPG:YN/P3JRH8LHGL2-LH/CJTK96L6SR9MU9DV5 R1:PI/E2$4J6AL.+I9UV6$0+BNPHNBC7CTR3$VDY0DUFRLN/Y0Y/K9/IIF0%:K6*K$X4FUTD14//E3:FL.B$JDBLEH-BL1H6TK-CI:ULOPD6LF20HFJC3DAYJDPKDUDBQEAJJKHHGEC8ZI9$JAQJKZ%K.CPM+8172JB0Q/BSRMQ%LBI1IZ72UVMPVNQND%GA.Q4AF- EH5NTTS$*1DK1D.1WB3I4WA+FUC4HLBKHUZNLBV7.XCI:PJ7RY:0K RB3Q0BT AA:40V19G3';
    const cwtPayload = await unpackAndVerify(signed);
    expect(await parseCWT(cwtPayload)).to.eql(TEST_PAYLOAD_AT);
  });


  it('should Verify the json from Sweden', async () => {
    // Signed by the original EU source.  They encoded the JSON as a String
    const signed = 'HC1:NCFOXN%TSMAHN-H3O4:PVH AJ2J$9J0II:Q5 43SLG/EBUD2XPO.TM8W42YBJSRQHIZC4.OI1RM8ZA*LPUY29+KCFF-+K*LPH*AA:G$LO5/A+*39UVC 0G8C:USOHDAPSY+3AZ33M3JZIM-1Z.4UX4795L*KDYPWGO+9AAEOXCRFE4IWMIT5NR7LY4357LC4DK4LC6DQ42JO9X7M16GF6:/6N9R%EP3/28MJE9A7EDA.D90I/EL6KKLIIL4OTJLI C3DE0OA0D9E2LBHHGKLO-K%FGLIA-D8+6JDJN XGHFEZI9$JAQJKHJLK3M484SZ4RZ4E%5MK9AZPKD70/LIFN7KTC5NI%KH NVFWJ-SUQK8%MPLI8:31CRNHS*44+4BM.SY$NOXAJ8CTAP1-ST*QGTA4W7.Y7N31D6K-BW/ N NRM1U*HFNHJ9USSK380E%WISO9+%GRTJ GBW0UEFJ42SUTU9I8/MD3N3ARC/03W-RHDMO1VC767.P95G-CFA.7L C02FM8F6UF';
    const cwtPayload = await unpackAndVerify(signed);
    expect(await parseCWT(cwtPayload)).to.eql(TEST_PAYLOAD_SE);
  });

  it('should Sign and Verify a Payload (JSON->COSE->JSON)', async () => {
    const signed = await sign(TEST_PAYLOAD, PUBLIC_KEY_PEM, PRIVATE_KEY_P8);
    const result = await verify(signed, PUBLIC_KEY_PEM);
    expect(result).to.eql(true);
  });

  it('should Pack And Unpack', async () => {
    const binaryData = new Uint8Array([123, 34, 118, 101, 114, 34, 58, 34, 49, 46, 48, 46, 48, 34]);
    const packed = await pack(binaryData);
    const unpacked = await unpack(packed);
    expect(unpacked.toString()).to.eql(binaryData.toString());
  });

  it('should Sign Pack And Unpack Verify JSON', async () => {
    const signed = await signAndPack(TEST_PAYLOAD, PUBLIC_KEY_PEM, PRIVATE_KEY_P8);
    const resultJSON = await unpackAndVerify(signed);
    expect(resultJSON).to.eql(TEST_PAYLOAD);
  });

  it('should Sign Pack and Unpack Verify a json using Base32', async () => {
    const signed = await signAndPack32(TEST_PAYLOAD, PUBLIC_KEY_PEM, PRIVATE_KEY_P8);
    const result = await unpackAndVerify(signed);
    expect(result).to.eql(TEST_PAYLOAD);
    expect(signed.length).to.eql(635);
  });

  it('should Sign Pack and Unpack Verify a json using Base45', async () => {
    const signed = await signAndPack45(TEST_PAYLOAD, PUBLIC_KEY_PEM, PRIVATE_KEY_P8);
    const result = await unpackAndVerify(signed);
    expect(result).to.eql(TEST_PAYLOAD);
    expect(signed.length).to.eql(595);
  });

  it('should Make CWT', async () => {
    const cwtPayload = await makeCWT(TEST_PAYLOAD);
    expect(await parseCWT(cwtPayload)).to.eql(TEST_PAYLOAD);
  });

  function replacer(key, value) {
      if(value instanceof Map) {
          return {
          dataType: 'Map',
          value: Array.from(value.entries()), // or with spread: value: [...value]
          };
      } else {
          return value;
      }
  }
  function reviver(key, value) {
      if(typeof value === 'object' && value !== null) {
          if (value.Map) {
              return new Map(value.Map);
          }
      }
      return value;
  }

  it('should Unpack Everything from Sweden', async () => {
    // Signed by the original EU source.  They encoded the JSON as a String
    const signed = 'HC1:NCFOXN%TSMAHN-H3O4:PVH AJ2J$9J0II:Q5 43SLG/EBUD2XPO.TM8W42YBJSRQHIZC4.OI1RM8ZA*LPUY29+KCFF-+K*LPH*AA:G$LO5/A+*39UVC 0G8C:USOHDAPSY+3AZ33M3JZIM-1Z.4UX4795L*KDYPWGO+9AAEOXCRFE4IWMIT5NR7LY4357LC4DK4LC6DQ42JO9X7M16GF6:/6N9R%EP3/28MJE9A7EDA.D90I/EL6KKLIIL4OTJLI C3DE0OA0D9E2LBHHGKLO-K%FGLIA-D8+6JDJN XGHFEZI9$JAQJKHJLK3M484SZ4RZ4E%5MK9AZPKD70/LIFN7KTC5NI%KH NVFWJ-SUQK8%MPLI8:31CRNHS*44+4BM.SY$NOXAJ8CTAP1-ST*QGTA4W7.Y7N31D6K-BW/ N NRM1U*HFNHJ9USSK380E%WISO9+%GRTJ GBW0UEFJ42SUTU9I8/MD3N3ARC/03W-RHDMO1VC767.P95G-CFA.7L C02FM8F6UF';
    const cbor = await debug(signed);
    
    const ExpectedStringified = "{\"tag\":18,\"value\":[{\"dataType\":\"Map\",\"value\":[[1,-7],[4,\"b0PE1U8EXlw\"]]},{},{\"dataType\":\"Map\",\"value\":[[1,\"SE\"],[4,1627936491],[6,1620160491],[-260,{\"dataType\":\"Map\",\"value\":[[1,{\"v\":[{\"ci\":\"urn:uvci:01:SE:EHM/100000024GI5HMGZKSMS\",\"co\":\"SE\",\"dn\":2,\"dt\":\"2021-03-18\",\"is\":\"Swedish eHealth Agency\",\"ma\":\"ORG-100030215\",\"mp\":\"EU/1/21/1529\",\"sd\":2,\"tg\":\"840539006\",\"vp\":\"J07BX03\"}],\"dob\":\"1958-11-11\",\"nam\":{\"fn\":\"Lövström\",\"gn\":\"Oscar\",\"fnt\":\"LOEVSTROEM\",\"gnt\":\"OSCAR\"},\"ver\":\"1.0.0\"}]]}]]},\"+eX8QOuEtAtIadpDDxj07D0LAWRaOSChNrP6O467gJP3OznoIIdlbuwZxn3QnNiIOAVJ4JeGOm+XV12+OaZ63Q==\"]}";
    expect(JSON.stringify(cbor, replacer)).to.eql(ExpectedStringified);
  });

  /* Not ready for Uruguay yet
  it.only('should Unpack Everything from Uruguay', async () => {
    // Signed by the original EU source.  They encoded the JSON as a String
    const signed = 'HC1:NCFOXNYTSFDHJI8Y0PQ8KGXMDVJ S3U 22ZMC C3.1K P/X9I-LOGID-QOXS-RI3VCD+SL89$66Z-AAKPB-5R$9$J5IHLM69KOMJI6ICM5DMORQ7N1Y.I%*48Z2YU4Z0QMX1$R1$%PDLDEQ5LHP063FGPS-MF4KU885 8AGOZ1LR$BD4CCMR2:Q7OA29N9GS%.64891YIWB3X8QVHNCNDYTKC4A1LEE5RJAOL/I*A1I7O4QMUPA.+3PVS.D6:L7*3U*Q5DKI%JOL8PQDSV4FBZR7+C* 4BBI:HKFPUO0ONWR/.98A7O7P00L*.U0COKJ5JJ5LRJXP9BHU7V38OF4ET6HES MF1EGJMWE4CU5CEJJ%TY15JTV *4NRFOVUOA7XC0WWND1EK3JSCM4:OGY4RVT+ 9J.AZ26:PK.YGO1MUGB.-VZXCVWCECEUTSEEF29TAHIH0QXCNRT6M.SAN1B.61.J*YP47MPAB*WAP2WST6*HTJ*MOK2Y6EYSLQZ9ABMBLPXR25QV%F0NXT2ML%/FA13 5VG9ALJVETPN/MRSG NCW30BYQ14';
    const cbor = await debug(signed);
    
    const ExpectedStringified = '{"tag":18,"value":[{"dataType":"Map","value":[[1,-37],[4,"_itDQezTCKY"]]},{},{"dataType":"Map","value":[[1,"Saluduy"],[4,1630113292],[6,1627521292],[99,"{\\"DocumentType\\":\\"68909\\",\\"DocumentNumber\\":\\"17706166\\"}"],["98","{\\"DocumentType\\":\\"68909\\",\\"DocumentNumber\\":\\"17706166\\"}"]]},"Kr0fDcBs0RJRdoK2ivPqrLvVMrJ2iygR1QYPWSxkumgj52kLcHw/W9uStMGaoP2FOTBgG/sYakNlQuK+CFQ0jsOWz5oBFM9Tesbz377LttGmvpPAGagreOhHcfapCQ6cZMYglsFPL9LqU9UL7PiltA16xTLuTk+I0DV9nWfGthQsBPYDNj6TYNr8Nhwt15PNnGwQjLvVsPZmQK9kMwReevPZKoVI9J5bFhIq1xo6DPsZAbI9IMLR5p6onPwchW7RplVadMvoD4YzuUWmX9ZYOdkkDfximnLkGxvkC0sL1ak0bdf8beJUs9ygGddiZY9OCtBuvOAn0fh6MusdQEpBhg=="]}';
    expect(JSON.stringify(cbor, replacer)).to.eql(ExpectedStringified);

    const result = await unpackAndVerify(signed);
    expect(result).to.eql(TEST_PAYLOAD);
    expect(signed.length).to.eql(635);
  });
  */

  it('should Unpack, Debug and Verify UK Certs', async () => {
    const UK_PAYLOAD = 
      {
        v: [
          {
            ci: 'URN:UVCI:01:GB:1628590888416QZII4I7Q#L',
            co: 'GB',
            dn: 1,
            dt: '2020-12-05',
            is: 'NHS Digital',
            ma: 'ORG-100030215',
            mp: 'EU/1/20/1528',
            sd: 2,
            tg: '840539006',
            vp: '1119349007'
          }
        ],
        dob: '1918-06-28',
        nam: { fn: 'GANTES', gn: 'EVAN', fnt: 'GANTES', gnt: 'EVAN' },
        ver: '1.3.0'
      }; 

    // Signed by the original EU source.  They encoded the JSON as a String
    const signed = 'HC1:6BFOXN TSMAHN-H1.OG:MR8EK*ORX4QF9W*9OJAU/ILCFHXKN*GMW6SA3/-2E%5VR5VVBJZI+EBXZ2G*S2U2V8TQEDK8C23T6VC-8D2VCGKDD8C:DC$JCVZ2.2TGHD0DD:FLPTI WJUQ6395R4I-B5ET42HP9EPXCRH99JDOAC5K87H8Q-9BSV40 7+P4Z.4:/6N9R%EPXCROGO3HOWGOKEQEC5L64HX6IAS3DS2980IQODPUHLO$GAHLW 70SO:GOLIROGO3T59YLLYP-HQLTQ9R0+L69/9-3AKI6$T6LEQY76LZ68999Q9E$BDZI69J59U*03HG3LZI29J1I38IT ZJ::A5V2F/9MM50CH7*KB*KYQTKWT4S86FP8-RV3JVWFOMUICHL26WUNPYRRW0TH59KEBW0PSB%D5PJPV:8GOFIUKS:F1IK5CO $DXF152S4:UFH1XL1YQMKCEEONC5I3DLIC2E$K:6D';
    
    const cbor = await debug(signed);
    
    const ExpectedStringified = '{"tag":18,"value":[{"dataType":"Map","value":[[1,-7],[4,"S2V5MQ=="]]},{},{"dataType":"Map","value":[[1,"GB"],[4,1631182860],[6,1628590888],[-260,{"dataType":"Map","value":[[1,{"v":[{"ci":"URN:UVCI:01:GB:1628590888416QZII4I7Q#L","co":"GB","dn":1,"dt":"2020-12-05","is":"NHS Digital","ma":"ORG-100030215","mp":"EU/1/20/1528","sd":2,"tg":"840539006","vp":"1119349007"}],"dob":"1918-06-28","nam":{"fn":"GANTES","gn":"EVAN","fnt":"GANTES","gnt":"EVAN"},"ver":"1.3.0"}]]}]]},"HSjYKxxJ5jjkEgyOZPc6hrKgunmVCxpTJNBUcfkInChbveJoj08S+vsPPIxxO0eHLsESjxNFBUQJutqeDhKCkg=="]}';
    expect(JSON.stringify(cbor, replacer)).to.eql(ExpectedStringified);

    const result = await unpackAndVerify(signed);
    expect(await parseCWT(result)).to.eql(UK_PAYLOAD);
  });

});



