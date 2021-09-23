const {sign, verify, pack, unpack, signAndPack, unpackAndVerify, makeCWT, parseCWT, debug} = require('../lib/index');const expect = require('chai').expect; 

describe('FR', async () => {
  it('should verify FR_2DCode_raw_test_pcr_ok', async () => {
    const HC1 = 'HC1:NCF4$8P8QPO0DO38GUWTJ08OH 16QKB7VZUM:5PWWP-.CPXMQH6U:RUC7ZCV./EC+QDFBI4IB.21LEE.K-S3C-34558C2/24HT30IS8459GE ME0OPXTER$R6X40H0D02 0EK*M$-N:MDAG3XI79HGKOUHWFX9S.0GJJEGMQF+KL+EALAP+2$/0QQORB01MI*+I :ITCJ*46Z+M/KB$PE571/U6IDWVDVNQCQ00YSK9O2F2LMW6VRC.O9RC18*BU0HEGD*LAEZKM7BQ66LJEXSO$$GFYODQO/758:F2TP:JJ8ZMNV8083%*92DHMR5LML5.QL.9$GR:VJC000SSVDWOFII 3+*Q7S9RYDQPV.KUBCBFE1K43QH3%60VG5Q4BZ00LT2R53PN9L3J5E4XD9$UO6A2UETTEPOOR8B7SISYF9UGBP3518E-HD94M00L3AS/98+F0.FFPG0%LJAP87O1RXR*FFVQMNIN0IU1.A%UN$UBHKTJADM%BR:MPMC$HN5.FCR071QH1RI1GFQCIXG/0SIRSVUE51J:KJR+VEWLO0MC9MG+BM2GMY020H';
    const cwtPayload = await unpackAndVerify(HC1);
    expect(cwtPayload).not.to.be.null;
    expect(cwtPayload).not.to.be.undefined;
    expect(await parseCWT(cwtPayload)).to.eql({'ver': '1.0.0', 'nam': {'fn': 'Dupond', 'fnt': 'DUPOND', 'gn': 'Marie', 'gnt': 'MARIE'}, 'dob': '1962-07-01', 't': [{'tg': '840539006', 'tt': 'LP6464-4', 'nm': '2019-nCoV RT-qPCR', 'ma': '1232', 'sc': '2021-05-16T14:34:56Z', 'dr': '2021-05-17T14:45:01Z', 'tr': '260415000', 'tc': 'Testing Centre', 'co': 'FR', 'is': 'Laboratory', 'ci': 'URN:UVCI:V1:FR:P50E914L54CIP5J0K4EHSCXOS:'}]});
  });

  it('should verify FR_2DCode_raw_vaccin_ok', async () => {
    const HC1 = 'HC1:NCF570.90T9WTWGVLKG99.+VKV9NT3RH1X*4%AB3XK4F36:G$MB2F3F*K+UR3JCYHAY50.FK6ZK7:EDOLFVCPD0B$D% D3IA4W5646946%96X476KCN9E%961A69L6QW6B46XJCCWENF6OF63W5Y96B46WJCT3E2+8WJC0FD4:473DSDDF+ANG7ZHAFM89A6A1A71B/M8RY971BS1BAC9$+ADB8ZCAM%6//6.JCP9EJY8L/5M/5546.96D46%JCIQE1C93KC.SC4KCD3DX47B46IL6646I*6..DX%DLPCG/DZ-CFZA71A1T8W.CZ-C4%E-3E4VCI3D7WEMY95IAWY8I3DD CGECQED$PC5$CUZCY$5Y$5JPCT3E5JDLA7KF6D463W5WA6%78%VIKQS*9OE.U37WGJG.1J5PF9WOASFU3UI69PKJEH2F:SY2SCYKFOMVGP OLGW31.J5OVSAFBGON19H+HCSIA7P:65P0F-QR/GS:2';
    const cwtPayload = await unpackAndVerify(HC1);
    expect(cwtPayload).not.to.be.null;
    expect(cwtPayload).not.to.be.undefined;
    expect(await parseCWT(cwtPayload)).to.eql({'ver': '1.0.0', 'nam': {'fn': 'Dupond', 'fnt': 'DUPOND', 'gn': 'Marie', 'gnt': 'MARIE'}, 'dob': '1962-07-01', 'v': [{'tg': '840539006', 'vp': '1119305005', 'mp': 'EU/1/20/1507', 'ma': 'ORG-100031184', 'dn': 2, 'sd': 2, 'dt': '2021-01-05', 'co': 'FR', 'is': 'IN', 'ci': 'dgci:V1:FR:C51AOQW7CQMFW7WLIWVGADQY6:70'}]});
  });

  it('should verify FR_2DCode_raw_recovery_ok', async () => {
    const HC1 = 'HC1:NCFOXN%TS3DHA SA6K85KFI60INA.QXV8.9BXG4O QL+4M*45DMLCDKQC+PBCV4*XUA2P-FHT-H4SI/J9WVHPYH+ZE/T93W1$NICZUBOM*LPUY2JD5*LPI-AA:GA.DL/AG0MX1O20COKI -8H5SR+377SNJG4+2FNS+DGT/A+-CZJJVCB0GH3NV9FH3NVC*IUZ4+FJE 4Y3LL/II 0SC9BX8QRKLHKV8L4D4:PI/E2$4J6ALD-IHKNT*01$VLS4J1TXKNA+2 CTNS4KCTO%K4F7MHF%*4 CT3SVI$290LV7J$%25I3HC31835AL5:4A93TLJ4LT.EJKD3L*86+UZ1JON2XHJMMQSQC0 FFAWB8OV:USD6PBFEV8YYU3JR*2T6L64S7N/U:43BR0QOJ58G8NK:SAODRMTE3C8-3NGMU8*2AN2Q1Q+FVG50G4F94';
    const cwtPayload = await unpackAndVerify(HC1);
    expect(cwtPayload).not.to.be.null;
    expect(cwtPayload).not.to.be.undefined;
    expect(await parseCWT(cwtPayload)).to.eql({'ver': '1.0.0', 'nam': {'fn': 'Dupond', 'fnt': 'DUPOND', 'gn': 'Marie', 'gnt': 'MARIE'}, 'dob': '1962-07-01', 'r': [{'tg': '840539006', 'fr': '2021-05-02', 'co': 'FR', 'is': 'Laboratory', 'df': '2021-05-02', 'du': '2023-05-02', 'ci': 'dgci:V1:FR:ME8M4JGYO2UKFHKKMQO8KW9QP:36'}]});
  });

});

