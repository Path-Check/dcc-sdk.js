const {sign, verify, pack, unpack, signAndPack, unpackAndVerify, makeCWT, parseCWT, debug} = require('../lib/index');const expect = require('chai').expect; 

describe('LI', async () => {
  it('should verify LI_2DCode_raw_1', async () => {
    const HC1 = 'HC1:NCFOXN%TSMAHN-HAUKB%DYLGV8I3IOI7245JW-4SBFJ599RT N9-RIKJRV28 NI4EFSYSS%OM6PYE9*FJ5MEQC8$.AIGCY0K5$0S+AY0K3:IZ0J9FA6KK64K.2I:4PSLS0OPG989B9EEDG%89-8CNNM3L5$09B91*KJ2KW80.5J3Q07K66MUWQHXYIDG6IRI H9LZUMN9OP6OH6IRI/GA$UFAYUQJAUVPBUHTK2SH93$U-RI PQVW5/O16%HAT1Z%PPRAAUICO1DZ5 +C HB/9TL4T.B9GYPWRU*V0I8AO.A29BLZIA9JXSJGZI8DJC0JUPI8J3ET3:H3A+2/43:ZJ83BJVTR63+NTJO1HP7W9AW9AG64/D8S*TYT4/UIWPU-%GJ%R XBLETHWVL05WRMO/4Z4TVHFI*39$VFACV+TNORN/V.:C64PYUMF55J8B54586QG4WQ7UD H.YF4 E+57V504UU2VE';
    const cwtPayload = await unpackAndVerify(HC1);
    expect(cwtPayload).not.to.be.null;
    expect(cwtPayload).not.to.be.undefined;
    expect(await parseCWT(cwtPayload.credential)).to.eql({'ver': '1.1.0', 'nam': {'fn': 'Musterfrau', 'fnt': 'MUSTERFRAU', 'gn': 'Maria', 'gnt': 'MARIA'}, 'dob': '1991-04-18', 'r': [{'tg': '840539006', 'fr': '2021-04-01', 'co': 'LI', 'is': 'Liechtensteinische Landesverwaltung', 'df': '2021-05-01', 'du': '2021-10-01', 'ci': 'URN:UVCI:01:LI:9T9FZ3UMIGA73UW'}]});
  });

  it('should verify LI_2DCode_raw_2', async () => {
    const HC1 = 'HC1:NCFOXN%TSMAHN-HOPCB1PZ5H$SD8+JM52UEL1WG+MP RIXF5K3E$E08WA6AVO91:ZH6I1$4JM:IP1MPK9V L*H1VUU8C1VTE5ZM3763WU/$MOCEM/URMHO$6S*EKGUSTEVY932QZJD+G9EPL.Q6846A$QY76QW6:C1:667C07ZD$J4VIJGDB7LKUTIPOJ2EA1NJSVBMOJ06J.ZJUIIQHS3DJQMIWVB*IBA2K0OAKOJW0KQZJ/VC*B4395KKPMB4O-OAMP8EF/HL5B9-NT0 2$$0X4PCY0+-C1W4/GJI+C7*4M:KT44LW4X$79-8J6T$/IORNHJP7NVXCBO/ICFQCNNT+4IGF5JNBPIUUU4WF8EGXC5Q$9NVPQK96R9* 9F69 UP%NPBT17$1FY11-E3YUF/9BL537V2XHJZ0526W9AW9AG648FG.QP5FVW4NV1T3BQVTDR1N1HVM%C %A6PJ8D6U8PLTPR2JC4ROU0V5JK0VHVMXSAIU7UD76HA%:MXCEJTLP*7OCRUV7U8KR F59R*40BQ1E2';
    const cwtPayload = await unpackAndVerify(HC1);
    expect(cwtPayload).not.to.be.null;
    expect(cwtPayload).not.to.be.undefined;
    expect(await parseCWT(cwtPayload.credential)).to.eql({'ver': '1.1.0', 'nam': {'fn': 'Mustermann', 'fnt': 'MUSTERMANN', 'gn': 'Max', 'gnt': 'MAX'}, 'dob': '1984-02-04', 't': [{'tg': '840539006', 'tt': 'LP217198-3', 'sc': '2021-06-01T00:00:00+02:00', 'dr': '2021-06-02T00:00:00+02:00', 'tr': '260415000', 'tc': 'Testcenter', 'co': 'LI', 'is': 'Liechtensteinische Landesverwaltung', 'ci': 'URN:UVCI:01:LI:8BINJZC7UE8J6FM'}]});
  });

  it('should verify LI_2DCode_raw_3', async () => {
    const HC1 = 'HC1:NCFOXN%TSMAHN-H0$SF2D*TNVP3%UQ/R8XRUNDC3WU5WCVK91QB5DOP-I52WHKGNO4*J8OX4W$C2VLWLIVO5HI8J.V J8$XJK*L5R1YVFD.LN.R7*J9L88VFC0WB$99:V$NICZUKSR*LA 436IAXPMHQ1*P1MX19UEWYHOH6-M5A$FKPAZL6+LAXLHSHANXU1TH/L6AW2 H2EIACUHQJAQOP*PEHL9.RQ/IE*ZU%E67QHBO9C*J3YUHDG SI5K1*TB3:U-1VVS1UU15%HTNIPPAAMI PQVW5/O16%HAT1Z%PHOP+MMBT16Y5+Z9XV7G+SB.V Q5FN9JEKE+4 .G7LPMIH-O92UQHPMOO9*0N6*K$X4%*4 CT3SVI$21$46AL**INOV6$0+BNPHNBC7+*4KCTO%K4F7TEFB 4N0SYLDV4DE1DMMS7IEU1PI1VVVJXK6YR9U6W EVL+73YD9KQRZR+%2P%N8X5/WRGV6E8T8EH2AMYKE*ZEMG1-WR4$R0DC5 42CSLXSDR1B0S.JE%U51MV$00Z1KV4';
    const cwtPayload = await unpackAndVerify(HC1);
    expect(cwtPayload).not.to.be.null;
    expect(cwtPayload).not.to.be.undefined;
    expect(await parseCWT(cwtPayload.credential)).to.eql({'ver': '1.1.0', 'nam': {'fn': 'Musterfrau', 'fnt': 'MUSTERFRAU', 'gn': 'Maria', 'gnt': 'MARIA'}, 'dob': '1991-04-18', 'v': [{'tg': '840539006', 'vp': '1119349007', 'mp': 'EU/1/20/1528', 'ma': 'Bharat-Biotech', 'dn': 1, 'sd': 2, 'dt': '2021-06-03', 'co': 'LI', 'is': 'Liechtensteinische Landesverwaltung', 'ci': 'URN:UVCI:01:LI:3F1C9TPLYN95JNN'}]});
  });

});

