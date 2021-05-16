const {sign, verify, pack, unpack, signAndPack, unpackAndVerify, signAndPack32, signAndPack45, makeCWT, parseCWT, debug} = require('../lib/index');

test('Verify RO_2DCode_raw_1', async () => {
  const HC1 = 'HC1:NCFOXN%TSMAHN-HUYOZJTZAU2G5B71GBHPPMU96EGP$1TNYSZO0R6UUED$UD$2JNUP%6R3B4:ZH6I1$4JN:IN1MPK9HQ5376CH187NRWUK8VJQ1IOM-.EPK9101EN9UKP0T9WC5PF6846A$QZ76NZ6499FQ5CVU2+PFQ51C5EWAC1A.GUQ$9WC5499Q$95:UENEUW6646936DNLO$9KZ56DE/.QC$Q3J62:6LZ6O59++9-G9+E93ZM$96PZ6+Q6X46+E54A9NF625F646L+9AKPCPP0%MFBM0XRJZII7JSTNB95926OL6D/53X7 V5-W6XY4$35+Y5ST4EZQT/5-Z7 P4Y*O0DSD:7JINQ+MN/Q19QE8QNQOU6M8DAFWO:20JXVF-3EVF$4LO1RQ7QIAFHKQVYRTME%WPYUKO%2I6U//E3BTCFWP%E*Y9JKVNXV$1Q-D4.CTY7P6LNU2N%1UQFWK:90*G72F';
  const cwtPayload = await unpackAndVerify(HC1);
  expect(cwtPayload).not.toBe(null);
  expect(cwtPayload).not.toBe(undefined);
  expect(await parseCWT(cwtPayload)).toStrictEqual({'ver': '1.0.0', 'nam': {'fn': 'Ion', 'fnt': 'ION', 'gn': 'Teodor', 'gnt': 'TEODOR'}, 'dob': '1989-01-12', 'v': [{'tg': '840539006', 'vp': 'J07BX03', 'mp': 'EU/1/20/1528', 'ma': 'ORG-100030215', 'dn': 1, 'sd': 2, 'dt': '2021-01-18', 'co': 'RO', 'is': 'Ministry of Health', 'ci': '01:RO:6LSN9SZ8#D'}]});
});

test('Verify RO_2DCode_raw_2', async () => {
  const HC1 = 'HC1:NCFOXN%TSMAHN-HUYOZJTZAU2G5B71-AHFT91RO%S2:CQA R5-88Y5R$PE$FW3400T28I-XRK1JZZPQA36S4GZ6SH9+2Q646AYMZUUTF6JO1-H11.UX7AEN932Q*RTKK9+OC+G9QJPNF67J6QW6A$QRZM6PP3.5Y0Q$UPR$5:NLOEPNRAE69K P3KP*PP:+P*.1D9R+Q6646-$0AX67PPDFPVX1R270:6NEQ0R6AOMUF5LDCPF5RBQ746B46O1N646RM9AL5CBVW566LHL76*2EIM2Q.F6YB LB08K5OI9YI:8D1CC28VFDA.-B97U: KX N9DQ7%NC.U9$MT-QP$IUQK8%M MIB2ATBOC.UQOI/2203GAEW1-ST*QGTA4W7.Y7N31%SC%I1.MJ917 51+ZFQ2CF2IA-K%X0T5LYS9% N7NI.TUNXRO:4*$2ZA17U5R2VMPVVJJ*YO.UBGW6ZR8U:QJ.T564U:S: BR7JT5UV00$3NC0';
  const cwtPayload = await unpackAndVerify(HC1);
  expect(cwtPayload).not.toBe(null);
  expect(cwtPayload).not.toBe(undefined);
  expect(await parseCWT(cwtPayload)).toStrictEqual({'ver': '1.0.0', 'nam': {'fn': 'Ion', 'fnt': 'ION', 'gn': 'Teodor', 'gnt': 'TEODOR'}, 'dob': '1989-01-12', 'v': [{'tg': '840539006', 'vp': 'J07BX03', 'mp': 'EU/1/20/1528', 'ma': 'ORG-100030215', 'dn': 1, 'sd': 2, 'dt': '2021-01-18', 'co': 'RO', 'is': 'Ministry of Health', 'ci': '01:RO:31Q6WQL8#F'}, {'tg': '840539006', 'vp': 'J07BX03', 'mp': 'EU/1/20/1528', 'ma': 'ORG-100030215', 'dn': 2, 'sd': 2, 'dt': '2021-02-08', 'co': 'RO', 'is': 'Ministry of Health', 'ci': '01:RO:31Q6WQL8#F'}]});
});

