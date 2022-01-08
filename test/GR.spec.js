const {sign, verify, pack, unpack, signAndPack, unpackAndVerify, makeCWT, parseCWT, debug} = require('../lib/index');const expect = require('chai').expect; 

describe('GR', async () => {
  it('should verify GR_2DCode_raw_1', async () => {
    const HC1 = 'HC1:NCFOXNEG2NBJ5*H:QO-.OMBN+XQ99N*6RFS5$JVTWG4G5I.PKT1WJLMER:GGQF95D8:ZH6I1$4JV7J$%25I3HC3183/9TL4T.B9GYPMA71ETMQJC.H :EVXR 1OCA7G6M01Q9D6YVQM473X7A-160NT%R:64J4FZW5 F6G6M5YOF1R2/Q:ER%47+V4YC5/HQ*$QXCR*888EQYKMXEE5IAXMFU*GSHGRKMXGG6DBYCBMQN:HG5PAHGG.IA.C8KRDL4O54O4IGUJKJGI.IAHLCV5GJM77UK HG4HGBIK6IA*$30JAXD16IASD9M82*882EOPCR:36/973KTN$KKQS7DS2*N.SSBNKA.G.P6A8IM%OVNI2%KYZP6NP.MKLWLVRMES9PI05P5034LOE7/5*OCV.29%CN31:T0.QMF3L1+DKAM$.UH9QB T0TIBMRZB19FWX6GLXHRMQ%NKA3WSJJDQS:/K43W-/VN+FB%602UCWJCZVK/SO901A6/7WAWPO1OB8R8502*FR5';
    const cwtPayload = await unpackAndVerify(HC1);
    expect(cwtPayload).not.to.be.null;
    expect(cwtPayload).not.to.be.undefined;
    expect(await parseCWT(cwtPayload.contents)).to.eql({'ver': '1.0.0', 'nam': {'fn': 'Μάριος', 'fnt': 'MARIOS', 'gn': 'Μενεξές', 'gnt': 'MENEKSES'}, 'dob': '1959-10-12', 'v': [{'tg': '840539006', 'vp': 'J07BX03', 'mp': 'EU/1/20/1528', 'ma': 'ORG-100030215', 'dn': 1, 'sd': 2, 'dt': '2021-01-21', 'co': 'GR', 'is': 'Ministry of Health', 'ci': 'urn:uvci:01:GR:78J239D5#2'}]});
  });

  it('should verify GR_2DCode_raw_2', async () => {
    const HC1 = 'HC1:NCFOXNEG2NBJ5*H:QO-.OMBN+XQ99N*6RFS5DVC0RBM*4GGM+HBSRHAL9.4I92P*AVAN9I6T5XH4PIQJAZGA2:UG%U:PI/E2$4JY/KA1TFTJF0E.PVOPE*CQG38JZIC0JVPIJWTB.S$:3LZI84J  IMLFX.5/AUP6N/55Z0KQPI4$TFETAZ3HG3WZJ$7K+ CVED IL9AD1QD-XIJ6RVH57Q4UYQD*O%+Q.SQBDOBKL/645YPL$R-ROM47Z6NC8P$WA3AA9EPBDSM+QFE4:/6N9RJDPHFLOGO3IRIHPXQ6UX4NC6O67795L*K1UP565%PD5DLCWCJZI-.15/EZ.CGHIG.CZ.C4C96+KA0G6LG9KDG+92+8 KE%%G6EDX0KEEDAMEN+IAJK.RFY-I:*G$IIY-KGJJB82%%53I8YEHPX8*GHREP1EFJUUXF9VZFWTVQ5EAJP-4U7YUS JG*5Y66E-7N6BM 5-B8DRQY*JKBSZO7:M9BO3H7HSVCL*P42693W1+D5JJ9 VM1F*9V6V5A505UIN1';
    const cwtPayload = await unpackAndVerify(HC1);
    expect(cwtPayload).not.to.be.null;
    expect(cwtPayload).not.to.be.undefined;
    expect(await parseCWT(cwtPayload.contents)).to.eql({'ver': '1.0.0', 'nam': {'fn': 'Μάριος', 'fnt': 'MARIOS', 'gn': 'Μενεξές', 'gnt': 'MENEKSES'}, 'dob': '1959-10-12', 'v': [{'tg': '840539006', 'vp': 'J07BX03', 'mp': 'EU/1/20/1528', 'ma': 'ORG-100030215', 'dn': 1, 'sd': 2, 'dt': '2021-01-21', 'co': 'GR', 'is': 'Ministry of Health', 'ci': 'urn:uvci:01:GR:78J239D6#2'}, {'tg': '840539006', 'vp': 'J07BX03', 'mp': 'EU/1/20/1528', 'ma': 'ORG-100030215', 'dn': 2, 'sd': 2, 'dt': '2021-02-21', 'co': 'GR', 'is': 'Ministry of Health', 'ci': 'urn:uvci:01:GR:78J239D6#2'}]});
  });

  it('should verify GR_2DCode_raw_3', async () => {
    const HC1 = 'HC1:NCFOXNEG2NBJ5*H:QO-.OMBN+XQ99N*6RFS5%BFTWG4G5B0Q011WJLMER:GGQF95D8:ZH6I1$4JV7J$%25I3HC3183/9TL4T.B9GYPMA71ETMQJC.H :EVXR 1OCA7G6M01Q9D6YVQM473X7A-160NT%R:64J4FZW5 F6G6M5YOF1R2/Q:ER%47+V4YC5/HQ*$QXCR*888EQUKMOFE5IAXMFU*GSHGRKMXGG6DB IBP1J4HGZJK HG43MRB8-JEMDQVD9B.OD4OYGFO-O%Z8JH1PCDJ*3TFH2V49B95EDF-IG54-B5O42TGKX7BA/C8T8EEA+ZA%DBU2LKHGH+INCIJTH37J$IIR+GCFD8XOC6DJ7WLFB/-R93R5V1Q+C3PF7GFO.GZ4G/0TTIT4ATMPRB.3XF74Y78/IU3MMHJ.8JPPV45M$8TK26RHFXD8JYES$QOMDDBNN/5V5074OYLF';
    const cwtPayload = await unpackAndVerify(HC1);
    expect(cwtPayload).not.to.be.null;
    expect(cwtPayload).not.to.be.undefined;
    expect(await parseCWT(cwtPayload.contents)).to.eql({'ver': '1.0.0', 'nam': {'fn': 'Μάριος', 'fnt': 'MARIOS', 'gn': 'Μενεξές', 'gnt': 'MENEKSES'}, 'dob': '1959-10-12', 'r': [{'tg': '840539006', 'fr': '2021-03-20', 'co': 'GR', 'is': 'Ministry of Health', 'df': '2021-05-20', 'du': '2021-11-20', 'ci': 'urn:uvci:01:GR:D9J4238C5'}]});
  });

  it('should verify GR_2DCode_raw_4', async () => {
    const HC1 = 'HC1:NCFOXNEG2NBJ5*H:QO-.OMBN+XQ99N*6RFS5YUC0RBM*4CCM*DALX8/Z4S:8KQC.RFCV4*XUA2PWKP/HLIJL8JF8JF7LPMIH-O92UQ5NEM.P8BNLZF.KNRET07KWH9 UPVF9*ZE6WU3.1QK9-TPII94 7*/2TDV.MBTXIP8Q NP2-EUTEC$1VU19/9-3AKI6%T6A$QKU6UW6/G9HEDCHJ4OIMEDTJCJKDLEDL9CVTAUPIAK29VC4/D-FD8RDFVAPUB1VCSWC%PDMOLBTC$JCH8CM8C: C4R2ZXIVVG4Z1%T6NF675I%E5EPPQF67460R6646O597E9 BID/9OK5NK9DDAZT5799OL56211W50NPRN9900O5LEV499TM*F.XIKXB8UJ06J9UBSVAXCIF4LEIIPBJ NIJZI2CB CABYIPZA 1JQEDK8CJ/S6VCH93HSTAEC8MS-H3WJS%QFQ*6$*R2*1.ALN28HX75 MVLU*9HKAFSFQB+IMPC1PV$ UR3A: 615ND/BIX2$:MOYF5G968R0FB.CV+F03H5SN6$%MW3OU%VD20$9D$1';
    const cwtPayload = await unpackAndVerify(HC1);
    expect(cwtPayload).not.to.be.null;
    expect(cwtPayload).not.to.be.undefined;
    expect(await parseCWT(cwtPayload.contents)).to.eql({'ver': '1.0.0', 'nam': {'fn': 'Μάριος', 'fnt': 'MARIOS', 'gn': 'Μενεξές', 'gnt': 'MENEKSES'}, 'dob': '1959-10-12', 't': [{'tg': '840539006', 'tt': 'LP217198-3', 'sc': '2021-05-20T10:05:32Z', 'dr': '2021-05-20T15:35:07Z', 'tr': '260415000', 'tc': 'Central Athens Testing Center', 'co': 'GR', 'is': 'Ministry of Health', 'ci': 'urn:uvci:01:GR:9X5D838D5'}]});
  });

});

