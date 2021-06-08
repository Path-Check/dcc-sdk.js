const {sign, verify, pack, unpack, signAndPack, unpackAndVerify, signAndPack32, signAndPack45, makeCWT, parseCWT, debug} = require('../lib/index');const expect = require('chai').expect; 

describe('LV', async () => {
  it('should verify LV_2DCode_raw_1', async () => {
    const HC1 = 'HC1:NCFOX1C9QZPO6R3YEE$DAF6L S8EEGCWEEOVX9LN.PBO2G.ESW113C HE.CV*$BLMV4-D*K7 LQ4323N6*FOKQ9IAK4ILB72D925CUK9HHBL29KW6H$SF4HRZ2L3$F2WLND8C N9%0/.KC1JTNTB1OW2KU1QA3HC8N127-+Q/XI4-QDZAI.C*$0W46:V5AF1.X6$-9+POGLRRJF9Z9W1LDQK1CLM Q*-D9/MYFBU/SUO5+/JVEKHZGZAKH/B0-HUEDOA6QSKW48V:NI 31U807P5I9RILC16N09WT8E21YT2AN9VB56Q9YM07PKM12RIJKFQL 7MUBE A JA.T27HD02CRXP64H7%0 TPGXGG7B%IRW%17L7+7D4EC6HEYY36C8N.QL/MG99VS7GX4AR4616QJ3UMO9AJ%DTFGU$ZK$E56UBX64751WRSGZUB9WV B.%RUANJ1LZB7DDWC-3SO1:+33%TJALG1AK2SJMOC1FV SFJTC$N2GJR1G-7JQ5J*-RM/P49UL$EPN1VS96VM//SD/F';
    const cwtPayload = await unpackAndVerify(HC1);
    expect(cwtPayload).not.to.be.null;
    expect(cwtPayload).not.to.be.undefined;
    expect(await parseCWT(cwtPayload)).to.eql({'ver': '1.0.0', 'nam': {'fn': 'Ogle', 'fnt': 'OGLE', 'gn': 'Gunārs', 'gnt': 'GUNARS'}, 'dob': '2008-11-08', 'v': [{'tg': '840539006', 'vp': '1119349007', 'mp': 'EU/1/20/1528', 'ma': 'ORG-100030215', 'dn': 1, 'sd': 2, 'dt': '2021-05-25', 'co': 'LV', 'is': 'Nacionālais veselības dienests', 'ci': 'urn:uvci:01:lv:9ad7d5486eca5bcbc0b502e97bd81186'}]});
  });

  it('should verify LV_2DCode_raw_2', async () => {
    const HC1 = 'HC1:NCF7%AQ.NBK2PS37DEJRH9+0$YJ-5H-E2/MN1UF*-L6/HQ0NKPQ296E FS2L-CQRLNX.U8-S7DFM+UDMTYF0/JKMIQF*S344JJO3ALAI1LQRT-ESS8Y%V9D0WFTKT0V77Z:F606:8ONQ2USRP7SJ.U0WPQHT9J34/D:1TS0H%VVX41:*D+ZNAWUS65VP93PDZ/LHTM$712-34DO9TD0C6/PK%C246LL-9QT74OLPOJO/JGUL4HR9EA +MCKIA1LMDAKOMDFV18F VS+J87ZDW8H2*6R/RQTAWEA+LOI55IRH+W5+LD53UK0HBSM $JXFNSML76DC1G-34I4G9O5KST$JKE-PK91HFN7 VVRC%$IF5TZ8QXFON:0ZK6L.1S92L%SI7NK VETLXAJUAB7Z27E8HHFA-BZ$3$:PO691*U6WS9:IX.R%L2 1K6HDZJ7MO83TTY21MDJ+R2X9BO9N379EE7WNOWTS2J6SLK-U1K842-9KEAW$2+J12%GR.JK/HK17 8I 4FKZPMLR%3UI7HD3L:QVZBPXUG%1456C:TVJU73$68BC:S7Y8F09BVBFA/74VM-XSFTTOABKFBL4WN:S%SCS-J87Q.4AFPBWAWUQ59-I';
    const cwtPayload = await unpackAndVerify(HC1);
    expect(cwtPayload).not.to.be.null;
    expect(cwtPayload).not.to.be.undefined;
    expect(await parseCWT(cwtPayload)).to.eql({'ver': '1.0.0', 'nam': {'fn': 'Darbiņš', 'fnt': 'DARBINS', 'gn': 'Kalvis', 'gnt': 'KALVIS'}, 'dob': '1974-01-04', 't': [{'tg': '840539006', 'tt': 'LP6464-4', 'nm': '1copy COVID-19 qPCR Kit', 'ma': '1drop Inc', 'sc': '2021-06-02T02:25:00Z', 'dr': '2021-06-02T03:45:00Z', 'tr': '260373001', 'tc': 'NVD', 'co': 'LV', 'is': 'Nacionālais veselības dienests', 'ci': 'urn:uvci:01:lv:39d9da8d15e39b93a68b3e095f4f56d9'}]});
  });

  it('should verify LV_2DCode_raw_3', async () => {
    const HC1 = 'HC1:NCFQ 7WY9$C0%207FC+O4 JOK05/56ZPOG$DA9OSTN0W4LXIQH9:72KL6QK5R-6X3M$I8 *PGNCT.K2J1%T8BRV6A8OH8-T8NFKC2W$41QH4UWEH-10DQLOT7CQ4UV*:Q0CCNS3%4QENMHYB18MQ+0XFNMPE6+3 1SD/OE0ECDTT%OR$19DEY.0$IKX+55DJ1JKMF29.ILS90.ISFF2*KZK6AW8+ZL4*KXJLC*LJA6YBNWZE6SU.*SZ0HFRV$-5  DFF0 ALGCKYUP.11F10KQ2Y453HAZNQU/EJJQ2G4$JHXRT2XC:DA6RN/HR4SOP+H-8VJYE+$5%:LQCAADMFPVMII5HUH*O*0MMSA6.CNS7RI3KE3H9Q684 EGAB9PZ042JHXKUMOIHHTO0$LK2+QB.T6FV1+HKVI:7KF$UTVP:DQ3%6.RL/CR5RHG%H/SEFLL-XRV6Q7LBXZDHM5I46QASAZMSVO$02RM0KJM30S/EUK7NN2GV.7Q:E';
    const cwtPayload = await unpackAndVerify(HC1);
    expect(cwtPayload).not.to.be.null;
    expect(cwtPayload).not.to.be.undefined;
    expect(await parseCWT(cwtPayload)).to.eql({'ver': '1.0.0', 'nam': {'fn': 'Tene', 'fnt': 'TENE', 'gn': 'Sandra', 'gnt': 'SANDRA'}, 'dob': '1961-03-08', 'r': [{'tg': '840539006', 'fr': '2020-12-15', 'co': 'LV', 'is': 'Nacionālais veselības dienests', 'df': '2020-12-26', 'du': '2021-06-13', 'ci': 'urn:uvci:01:lv:71a307447b0055e47c2d9c3a274e6188'}]});
  });

});

