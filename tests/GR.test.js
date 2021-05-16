const {sign, verify, pack, unpack, signAndPack, unpackAndVerify, signAndPack32, signAndPack45, makeCWT, parseCWT, debug} = require('../lib/index');

test('Verify GR_2DCode_raw_1', async () => {
  const HC1 = 'HC1:NCFOXNEG2NBJ5*H:QOM-O$6LQ1TWWVD*TFI1V%74FCGJ9G1R4UOO%IUFLWWOX$SGXC/GPWBI$C9UDBQEAJJKHHGEC8.-B97U: KUZN:CS6QKS/V3-SY$N.R6 7P45A/HSC.UAS1A+QD-QIUSYUSC.U%KIH2CF08ZBU4DRG+SB.V Q5NN9XN9AL8PZBTVK1RM8ZAUZ4+FJE 4Y3LL/II 0OC9SX0+*B85T%6213PPHN6D7LLK*2HG%89UV-0LZ 2MKN4NN3F8A78CY0O1P9-8:0L.A53XHS-O:S9395*CB5486YBAN8KN42%K:XFKPAOH6NSHOP6OH6XO9IE5IVU5P2-GA*PEVH6WLIJK5YO9OUUMK9WLIK*L5R1L*R1%L8Z5PYH3X5UU9+$HEP3XTTQ+JWZDXCM825XY9G*D02I4 7C4J 1F-/9A*A-WI9SC2/OYYDK0R6/R*QN9LBVEWSKKRG691U+U84K9P.KM+H9Z7A.53IB:QJ500243Q3';
  const cwtPayload = await unpackAndVerify(HC1);
  expect(cwtPayload).not.toBe(null);
  expect(cwtPayload).not.toBe(undefined);
  expect(await parseCWT(cwtPayload)).toStrictEqual({'ver': '1.0.0', 'nam': {'fn': 'Marios', 'fnt': 'MARIOS', 'gn': 'Menekses', 'gnt': 'MENEKSES'}, 'dob': '1959-10-12', 'v': [{'tg': '840539006', 'vp': 'J07BX03', 'mp': 'EU/1/20/1528', 'ma': 'ORG-100030215', 'dn': 1, 'sd': 2, 'dt': '2021-01-21', 'co': 'GR', 'is': 'Ministry of Health', 'ci': 'urn:uvci:01:GR:78J239D5#2'}]});
});

test('Verify GR_2DCode_raw_2', async () => {
  const HC1 = 'HC1:NCFOXNEG2NBJ5*H:QOM-O$6LQ1TWWVD*TFI11B3B2J5B9+$P4UAOGIMS2F7A+T9D:15VC9:BPCNJINQ+MN/Q19QE8QEA7IB65C94JBPNJEJC3/CHFE4JBWD9Y7M-CI:4G9JAX.B$3E5.B /EOKDBLEH-B91HFVLKULSDMV9EZI9$JAQJK4KLK3MXHGWHKMJC6YQA KZ*U0I1-I0*OC6H0/VMNPM/UESJ0A5L5M0*$K8KG+9RR$F+ F%J00N89M4*$K3$OHBWO5FD%8CJ0%H0%P8C KXU70%KLR2C KPLIUM42CGKHG43MTDC-JE2HQVD9B.OD4OYGFO-O%Z8JH1PCDJ*3TFH2V4YE9*FJBOIAZ8-.A2*CEHJ5$0O:AVB8.3TE-BX4P/%5WPP+R26VGP.QU%8BINTSOZRF8+IJRE$3R80V0OD21EGXV.-MKYN1ES$OO32961MRAM41J2GFRYEAJ4VQDDQC UH7O7H8M%DM-150QJ3N7XN0$.CR-Q5BM0WO*ETQ10GIT05';
  const cwtPayload = await unpackAndVerify(HC1);
  expect(cwtPayload).not.toBe(null);
  expect(cwtPayload).not.toBe(undefined);
  expect(await parseCWT(cwtPayload)).toStrictEqual({'ver': '1.0.0', 'nam': {'fn': 'Marios', 'fnt': 'MARIOS', 'gn': 'Menekses', 'gnt': 'MENEKSES'}, 'dob': '1959-10-12', 'v': [{'tg': '840539006', 'vp': 'J07BX03', 'mp': 'EU/1/20/1528', 'ma': 'ORG-100030215', 'dn': 1, 'sd': 2, 'dt': '2021-01-21', 'co': 'GR', 'is': 'Ministry of Health', 'ci': 'urn:uvci:01:GR:78J239D6#2'}, {'tg': '840539006', 'vp': 'J07BX03', 'mp': 'EU/1/20/1528', 'ma': 'ORG-100030215', 'dn': 2, 'sd': 2, 'dt': '2021-02-21', 'co': 'GR', 'is': 'Ministry of Health', 'ci': 'urn:uvci:01:GR:78J239D6#2'}]});
});

