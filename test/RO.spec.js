const {sign, verify, pack, unpack, signAndPack, unpackAndVerify, signAndPack32, signAndPack45, makeCWT, parseCWT, debug} = require('../lib/index');const expect = require('chai').expect; 

describe('RO', async () => {
  it('should verify RO_2DCode_raw_1', async () => {
    const HC1 = 'HC1:NCFOXN%TSMAHN-HUSC7LDZL18ZT4 E1V8.9B7AJU-SXG4X75MLE:X9LGCG+RK1JZZPQA36S4HZ6SH9X5QN9IFY1OSMNV1L8VNF6AYMZUUGH18VH. 63:U$V6QAASH932Q-RTKK9+OC+G9QJPNF67J6QW6A$QRZM6PP3.5Y0Q$UPR$5:NLOEPNRAE69K P3KP*PP:+P*.1D9R+Q6646-$0AX67PPDFPVX1R270:6NEQ0R6AOMUF5LDCPF5RBQ746B46O1N646RM9AL5CBVW566LH 469/9-3AKI6-$MSR0J9C$ZJ*DJWP42W5SKRK:7R95H/5:P4A:7L7OCA7G6M8ORU9SSA7G6MGZ5V1R5.OU65FT5D75W9AV88G64GHCGW5K/C/:7+PK$NH9QF8-7+/H::21UU4NU/*OBU4.XGV8OO95A2QS7ROSMT*IF/PE9O 3VB%GIVIA8R*XJVNVW.155UY9LY+1R/73H0Y/8WIE';
    const cwtPayload = await unpackAndVerify(HC1);
    expect(cwtPayload).not.to.be.null;
    expect(cwtPayload).not.to.be.undefined;
    expect(await parseCWT(cwtPayload)).to.eql({'ver': '1.0.0', 'nam': {'fn': 'Ion', 'fnt': 'ION', 'gn': 'Teodor', 'gnt': 'TEODOR'}, 'dob': '1989-01-12', 'v': [{'tg': '840539006', 'vp': 'J07BX03', 'mp': 'EU/1/20/1528', 'ma': 'ORG-100030215', 'dn': 1, 'sd': 2, 'dt': '2021-01-18', 'co': 'RO', 'is': 'Ministry of Health', 'ci': 'URN:UVCI:01:RO:SNYM1MMU3P#J'}]});
  });

  it('should verify RO_2DCode_raw_2', async () => {
    const HC1 = 'HC1:NCFOXN%TSMAHN-HUSC7LDZL18ZT4 E/R8E:INDCCH184DCJ91YE0PPP-I.BDAZAF/8X*G3M9CXP3+AZW4%+A63HNNVR*G0C7PHBO33:X0 MBSQJ%F3KD3CU84Z0QPFSZ4NM0%*47%S%*48YIZ73423ZQTX63-E32R4UZ2 NVV5TN%2UP20J5/5LEBFD-48YI+T4D-4HRVUMNMD3323R1370RC-4A+2XEN QT QTHC31M3+E3CP456L X4CZKHKB-43.E3KD3OAJ5%IWZKRA38M7323 PCQP9-JNLBJ09BYY88EK:M2VW5Q41W63OH3TOOHJP7NVDEB$/IL0J99SSZ4RZ4E%5MK96R96+PEN9C9Q9J1:.PNJPWH9 UPYF9Q/UIN9P8QOA9DIEF7F:-1G%5TW5A 6YO67N6D9ESJD2BFHXURIUC%55VTE:4IG9R6GCI69 52NF3TD%/2C4HABTDYVZGT%WMM4UG6M:5CNUR+54HVHAVLELA08MU1KMHFXLPVO4:7W3YB 20H3MW2';
    const cwtPayload = await unpackAndVerify(HC1);
    expect(cwtPayload).not.to.be.null;
    expect(cwtPayload).not.to.be.undefined;
    expect(await parseCWT(cwtPayload)).to.eql({'ver': '1.0.0', 'nam': {'fn': 'Ion', 'fnt': 'ION', 'gn': 'Teodor', 'gnt': 'TEODOR'}, 'dob': '1989-01-12', 'v': [{'tg': '840539006', 'vp': 'J07BX03', 'mp': 'EU/1/20/1528', 'ma': 'ORG-100030215', 'dn': 1, 'sd': 2, 'dt': '2021-01-18', 'co': 'RO', 'is': 'Ministry of Health', 'ci': 'URN:UVCI:01:RO:Q6M0U00Y5S#I'}, {'tg': '840539006', 'vp': 'J07BX03', 'mp': 'EU/1/20/1528', 'ma': 'ORG-100030215', 'dn': 2, 'sd': 2, 'dt': '2021-02-08', 'co': 'RO', 'is': 'Ministry of Health', 'ci': 'URN:UVCI:01:RO:S7MVLVV8YQ#B'}]});
  });

  it('should verify RO_2DCode_raw_3', async () => {
    const HC1 = 'HC1:NCFOXN%TSMAHN-HUSC7LDZL18ZT4 E8S8ELB7AJU-SXG4X75%LE:X9LGCG+RK1JZZPQA3DP4OW631AX5QN9IFY1OSMNV1L8VNF6AYMZUU7C1UF6-:U V6GK6FXA31A32Q-RTRH9/UPNF67J6QW6D90C KUGAACQG40SM92OGIC3LD32R4UZ2 NVV5TN%2UP20J5/5LEBFD-48YI5S4CZKHKB-43.E3KD3OAJ5AL5:4A93NOJ4LTZABMD3E-4RZ4E%5MK91UP6-5 T5$V9C9QQK9HWP C59.P+95XW5I%5B/94O5$01RFUDTUNQUIN9P8Q0LPTB12:UX81QV1G 1G%5TW5A 6YO67N6RBE0BQRLFL-AGNGPCLPLM9O644V5:Q/5N5-PMXJLZIA:QH7DM18*9FPSGJ49ZQO$Z5/M5REJ3SBNKV/7N7020NJEE9:*U11U%ROQBOKS0P%PEFE';
    const cwtPayload = await unpackAndVerify(HC1);
    expect(cwtPayload).not.to.be.null;
    expect(cwtPayload).not.to.be.undefined;
    expect(await parseCWT(cwtPayload)).to.eql({'ver': '1.0.0', 'nam': {'fn': 'Spiridon', 'fnt': 'SPIRIDON', 'gn': 'Dumitrescu', 'gnt': 'DUMITRESCU'}, 'dob': '1956-08-11', 'r': [{'tg': '840539006', 'fr': '2021-02-20', 'co': 'RO', 'is': 'Ministry of Health', 'df': '2021-04-04', 'du': '2021-10-04', 'ci': 'URN:UVCI:01:RO:QR75N55V2Q#O'}]});
  });

  it('should verify RO_2DCode_raw_4', async () => {
    const HC1 = 'HC1:NCFOXN%TSMAHN-HUSC7LDZL18ZT4 E/R8.C1NDCCH184D.H9+/SF%G4G5BEBN9HNO4*J8OX4SX42VLWLICN53O8J.V J8$XJK*L5R17PGA*LLWOA*F8XF3+PVE0D 9:PIQGG4SIWLHWVHWVH+ZE/T9NX1XF8/+H2T9.GGOUKOH6NSHOP6OH6XO9IE5IVU5P2-GA*PEVH6/IEKMAC+HAW1FNH%A2 S9BQN* 9-V9%OKAJ92J1QJAZM93$UWW2QRA H99QHOQ1TK96L6SR9MU9DV5 R1AMI8LHU-H/O1:O1AT1NQ1SH99H6-F0+V9.T9D 9PRAAUICO10W59UE1YHU-H:PI/E2$4JY/KUYCG+S:1JD-4M%I /K .K47TC4T+*431T:SCZIVI1HNK7L$G55LY0UD1VF1VHS9UM97H98$QJEQ8BH2GQHLK0QFNANDDD*HHL/FH%R:Z8- 5%JLEQ3DXU:$8C HWJM029B2WO3A0-PN/R9VNS+GS0O8U52WHI5HI3RBBI/XVH1LQGTR$J+2CX405XQ11';
    const cwtPayload = await unpackAndVerify(HC1);
    expect(cwtPayload).not.to.be.null;
    expect(cwtPayload).not.to.be.undefined;
    expect(await parseCWT(cwtPayload)).to.eql({'ver': '1.0.0', 'nam': {'fn': 'Pluteanu', 'fnt': 'PLUTEANU', 'gn': 'Elena', 'gnt': 'ELENA'}, 'dob': '1998-02-26', 't': [{'tg': '840539006', 'tt': 'LP6464-4', 'ma': '1331', 'sc': '2021-05-15T12:34:56Z', 'dr': '2021-05-16T12:45:01Z', 'tr': '260415000', 'tc': 'Testing center 1', 'co': 'RO', 'is': 'Ministry of Health', 'ci': 'URN:UVCI:01:RO:QW3L2LL66Q#4'}]});
  });

});

