/**
 * Sample React Native App
 * https://github.com/facebook/react-native
 *
 * @format
 * @flow
 */

import React, {Component} from 'react';
import {Platform, StyleSheet, Text, View, NativeModules} from 'react-native';

import secp256k1 from 'react-native-secp256k1';



async function test_encrypt(key1, key2, data, encryped) {
  const pub1 = await secp256k1.computePubkey(key1, true);
  const pub2 = await secp256k1.computePubkey(key2, true);
  
  const encryped1 = await secp256k1.ext.encryptECDH(key1, pub2, data);
  const encryped2 = await secp256k1.ext.encryptECDH(key2, pub1, data);

  let decryped1 = await secp256k1.ext.decryptECDH(key2, pub1, encryped1);
  let decryped2 = await secp256k1.ext.decryptECDH(key1, pub2, encryped2);
  if (decryped1 !== data || decryped2 !== data) {
    console.error("self decryption");
    console.error(decryped1);
    console.error(decryped2);
    console.error(data);
    return false;
  }

  if (encryped !== undefined) {
    decryped1 = await secp256k1.ext.decryptECDH(key2, pub1, encryped);
    decryped2 = await secp256k1.ext.decryptECDH(key1, pub2, encryped);
    if (decryped1 !== data || decryped2 !== data) {
      console.error("public decryption");
      console.error(decryped1);
      console.error(decryped2);
      console.error(data);
      return false;
    }
  }
  return true;
}

async function test_case(check) {
  let data = secp256k1.hex_decode("CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A90");
  let sig = secp256k1.hex_decode("3044022079BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980220294F14E883B3F525B5367756C2A11EF6CF84B730B36C17CB0C56F0AAB2C98589");
  let pub = secp256k1.hex_decode("040A629506E1B65CD9D2E0BA9C75DF9C4FED0DB16DC9625ED14397F0AFC836FAE595DC53F8B0EFE61E703075BD9B143BAC75EC0E19F82A2208CAEB32BE53414C40");
  check(await secp256k1.raw_verify(data, sig, pub), "testVerifyPos");

  data = secp256k1.hex_decode("CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A91");
  sig = secp256k1.hex_decode("3044022079BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980220294F14E883B3F525B5367756C2A11EF6CF84B730B36C17CB0C56F0AAB2C98589");
  pub = secp256k1.hex_decode("040A629506E1B65CD9D2E0BA9C75DF9C4FED0DB16DC9625ED14397F0AFC836FAE595DC53F8B0EFE61E703075BD9B143BAC75EC0E19F82A2208CAEB32BE53414C40");
  check(!await secp256k1.raw_verify(data, sig, pub), "testVerifyNeg");
  
  let priv = secp256k1.hex_decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530");
  check(await secp256k1.raw_secKeyVerify(priv), "testSecKeyVerifyPos");
  
  priv = secp256k1.hex_decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
  check(!await secp256k1.raw_secKeyVerify(priv), "testSecKeyVerifyNeg");

  priv = secp256k1.hex_decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530");
  pub = secp256k1.hex_encode(await secp256k1.raw_computePubkey(priv, false));
  check(pub === "04C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D2103ED494718C697AC9AEBCFD19612E224DB46661011863ED2FC54E71861E2A6", "testPubKeyCreatePos");
  pub = secp256k1.hex_encode(await secp256k1.raw_computePubkey(priv, true));
  check(pub === "02C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D", "testPubKeyCreatePos2");

  priv = secp256k1.hex_decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
  pub = secp256k1.hex_encode(await secp256k1.raw_computePubkey(priv, false));
  check(pub === "", "testPubKeyCreateNeg");

  data = secp256k1.hex_decode("CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A90");
  priv = secp256k1.hex_decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530");
  sig = secp256k1.hex_encode(await secp256k1.raw_sign(data, priv));
  check(sig === "30440220182A108E1448DC8F1FB467D06A0F3BB8EA0533584CB954EF8DA112F1D60E39A202201C66F36DA211C087F3AF88B50EDF4F9BDAA6CF5FD6817E74DCA34DB12390C6E9", "testSignPos");
  
  priv = secp256k1.hex_decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");
  sig = secp256k1.hex_encode(await secp256k1.raw_sign(data, priv));
  check(sig === "", "testSignNeg");
  
  priv = secp256k1.hex_decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530");
  data = secp256k1.hex_decode("3982F19BEF1615BCCFBB05E321C10E1D4CBA3DF0E841C2E41EEB6016347653C3");
  let tweak = secp256k1.hex_encode(await secp256k1.raw_privKeyTweakAdd(priv, data));
  check(tweak === "A168571E189E6F9A7E2D657A4B53AE99B909F7E712D1C23CED28093CD57C88F3", "testPrivKeyAdd");

  tweak = secp256k1.hex_encode(await secp256k1.raw_privKeyTweakMul(priv, data));
  check(tweak === "97F8184235F101550F3C71C927507651BD3F1CDB4A5A33B8986ACF0DEE20FFFC", "testPrivKeyMul");

  pub = secp256k1.hex_decode("040A629506E1B65CD9D2E0BA9C75DF9C4FED0DB16DC9625ED14397F0AFC836FAE595DC53F8B0EFE61E703075BD9B143BAC75EC0E19F82A2208CAEB32BE53414C40");
  tweak = secp256k1.hex_encode(await secp256k1.raw_pubKeyTweakAdd(pub, data));
  check(tweak === "0411C6790F4B663CCE607BAAE08C43557EDC1A4D11D88DFCB3D841D0C6A941AF525A268E2A863C148555C48FB5FBA368E88718A46E205FABC3DBA2CCFFAB0796EF", "testPubKeyAdd");
  
  tweak = secp256k1.hex_encode(await secp256k1.raw_pubKeyTweakMul(pub, data));
  check(tweak === "04E0FE6FE55EBCA626B98A807F6CAF654139E14E5E3698F01A9A658E21DC1D2791EC060D4F412A794D5370F672BC94B722640B5F76914151CFCA6E712CA48CC589", "testPubKeyMul");

  data = secp256k1.hex_encode(await secp256k1.raw_createECDHSecret(priv, pub));
  check(data === "2A2A67007A926E6594AF3EB564FC74005B37A9C8AEF2033C4552051B5C87F043", "testCreateECDHSecret");

  let check_array = [
    "1",
    "我",
    "*)(&Y(Y(FDS",
    "我的你的他的事把八八八八把",
    "00000000",
    "000000001",
    "0000000011111111",
    "00000000111111112",
    "000000001111111122222222",
    "0000000011111111222222223",
    "00000000111111112222222233333333",
    "000000001111111122222222333333334",
    "2018年10月1日，我国进入个税改革过渡期——减除费用标准按5000元/月执行，并执行新的税率表。根据国家税务总局提供的数据，个税改革后，有6000多万纳税人不用再缴纳个税。\
    财政部的数据也证实了这一点：2018年1-10月，财政部累计录得个人所得税收入12287亿元，其中10月份个人所得税增幅比上月回落13.8个百分点。根据财政部公示数据推算，2018年11月，财政部单月录得个人所得税收入700亿元，较2017年同期减少了146亿元。\
    具体到个人，个税改革过渡期即2018年第4季度，扣除险金等项目后月薪8000元及以下的纳税人减税比例在70%以上，扣除险金等项目后月薪2万元以下的纳税人减税比例普遍在50%以上。\
    从这个角度看，个税改革让居民省了不少税费，也算是国家为你我变相加薪了！同时由于税收的强制性特征——我国公民均有依法纳税的义务，个税改革带来的“加薪”也因此具有普惠性质。\
    中国劳动学会副会长苏海南在接受中新经纬客户端采访时表示，居民收入增长建立在经济增长基础上，在经济增长放缓以及中美贸易摩擦冲击的背景下，2018年居民工资增长幅度或许达不到社会预期，但仍将取得比较好的成绩。\
    不管怎样，2018年的工资已成定局，不如看看2019年你的工资或福利待遇还能涨多少？",
  ];
  let pass_array = [
    "YuSFnp71PAqp+NwcFXdwQQ",
    "61zJCqZxl9UBZKBI4Uhqwg",
    "Gnufw1LLme2KAJV50lHtCA",
    "wmYGLU+mX08SONrf0lTP4EM8cM0yyeltBMjEeBar8SUriIx4VxB6gBCpA8L8C79u",
    "CCHPmYLSx96y5RSQWAVhDQ",
    "uid9haHV6wPxJTyi8+iw8A",
    "O48Ahcyy/jTax3pnr4Mp9kYxfqxf4z2s6NRe6rq3M5s",
    "t/PLvjgyzWXgWZhYazRR23KisIbInBBRJ2lnnc3KQ4E",
    "ecp348KozZHzoIjlWmmFZsoXxNK2ZFjswCgxKQCF9po",
    "bvzQQwedulPkDOVQMJcC1R8YDedOqVfnIdVVyQHnWRo",
    "qvexrll4LoEh7JnKtW05fOqcwZsvEldOi4crGiqdq9lLdD3jZ0wsc/PzqMnWvxil",
    "XnFXSZEiqPcNN5yRywQg1Ro9puKJVoq2v8Zp3kakiSsVeTrWAPxaMVA99GqCYRdh",
    "HahPDBUxl8JQ0JEsDy5AjR9qSJ2GegCQKZqcjeCAC3Wuchbwz40dluRSlNF41AH8eC5NhVZ9QJJ/A6q84UUZS/zobnq5oAkqyf3Eoo5fZ01LFXyLM3ChW1HftG/FKwBfQiqFioKiUXI/hBc/YihXTsVoeI1MP0zLq+RyACftX5gf48maW05P7SdBQwBnA5UEzMZSSv+twACI2J4h7P6Sm+br9QV/W8sqTRlOJBohf1jEHKldMgXO+m8XRnANbVbiWm5PK2buFdS7MocxNtqitgw+NZHKXtKbo3gk5BltwUYUwh7RKvj8sCNbpQt8EH77+zY+QnwDwkCiFa+ev7EZazSuCJREafuIG257ONLj56VSz92nzJkNOZoSisa+AsDFsMiJ210pTVPqaIIeroHAb9a5Ir5h4pBxnCNHMbxNipc2y17Rta/62p1baKehz6u3+BixMKDC2Yx6FjqUgA29oirPUOsL8oeOHN8IDsUad74AiOIxaQ0/RgTXHHCl8+1Zc+obfKddMFZasUoluBQGvGcLBZuPuzX3mLLzppom2FicE6rFlSjBRim/nB01GVJ7Md3rKDFRFdZf1riDw9PQ3R+ywNidns162d11oqQXLxcggGB6d11GoDlAk2F9oG8PNiq2PgOvtgdaPfkMvGxlfQTLuGPCFzTN485YGiSz4TPhkxgfyYsoWCEM6r4vl4uECj495eVF0EZ/fKAT6ehm+YLfO/w6SvUwgjHNDfvi8gOmgYUCv3RjVOvXl6xne1H++yxgkrxVDySm83fkcgAS6QRT0OsroHrGzA0MINIgpDPXFOvKr1eO9mtMWNv+ypY1HPtntft9qSybBWSBM/CWbJrz08H7NrJAzw8/Ysk1MUjMXBcOAYRThGKrh8g12TJ24h1R+uJWQDoXZJdiumgaXKaxBL+xpudQ/6la49g7D8AWlsJg/J4Ypze0U6IhT4zQhj1v72ZhPZbRq5ooG0tBgLYwWgan4wUtaaAE8qq5DWkG0+A3yXMB1Mf6NHgt5w64dKERQdGtdCTvycvPsyvlNe3Bmx1C3QsPARm7PUIpgODM4IrtmJsRHdis0iFa9QpznQN0+JyAwNdeDjpdsbupTgv4IhZ6+FJDx2/edtN83Q/Kpi2CvNLtjCRiqYIHuOeb27BYBNWzfONwYXLaS5T3g353sIJXWaTq2a0r7wKsYdT3of5+MlTkuir2tb/T5AVM0i/o/OaU6yWzXFbK1lfTDfm75UmrYD4NgcRwseyntjiqM437y+JPIcONy6RK27ONdBtvvVEKj8ep7TFlAByJzS9KmPm6Vnn1n5Z6wB04ZnLoEKdM7q/r+idvH3kuoFGCb2hDg10cFvWFtDZ6Uctj0b9upPJMSdMH0bQKQtZVFmdc0+RXb/2mjiLOQaq3WthPpNxqcs3B/UOeT7x3bYpE0GmJhCrrSLZRVwsNwmiyAiUBGTxnmvp/p4UC4kPEf8Vk49DVkkOqcxh4vNMn2UroFjFsJ8vyS0lVj8MBqn0d8IWeBc4+Yd2Bdz8sF3nz549t679Hww3NCrb86cIPKeL+dIxHVOw8wMCZkKczjzswybeSazgxbBbt3CJoXOvPmWbTEABayyD63Ly+LN/IF6Ly4LsQRL6tzVzh03o65VG33ZwWNmUMQ28coodty0Ymj8DtLknc2ahOwwLzcHFcXgNlTarcouo3faCxYHrXnOL93cxtHf5L9Y9eXe+eRnqP0E/NX0Es6GaQ9gENEBTZ9YI2CbQ2niLixRpX6ZoOjIyTK6Zcs+de75rkCCpc2h33b1UpT+ixFklRklgzUk+f0iZ/rWtFuc4HkpOfdAcIspcHNsIICPC3VLbUoGEOC1L92sOoAsbLUIHvajAJ+HIJZpoByJ/4Q7OMH6fCXUsZ8HbeGzDS+7HZkAZJ5reO4ONJlBZyS3iyTemUPCF86huT+3t+XMBP1sVVfTNUZ5TZwEJq+K9jidets0vrmZjPkB5JVRBY",
  ];
  
  let key1 = await secp256k1.ext.generateKey();
  let key2 = await secp256k1.ext.generateKey();
  const skey1 = "G6rWYPkY5m6VGkdUBzSFPxB8/lWcKOACBTHTlA4qmXQ";
  const skey2 = "1H1SJuGwoSFTqNI8wvVWEdGRpBvTnzLckoZ1QTF7gI0";
  for (let i = 0; i < check_array.length; i++) {
    const enc = check_array[i];
    const dec = pass_array[i];
    if (dec === undefined) {
      const pub2 = await secp256k1.computePubkey(skey2, true);
      const encryped1 = await secp256k1.ext.encryptECDH(skey1, pub2, enc);
      console.warn(encryped1);
    }
    if (!await test_encrypt(key1, key2, enc)) {
      check(false, enc);
    }
    if (!await test_encrypt(skey1, skey2, enc, dec)) {
      check(false, `${enc} decryption`);
    }
  }
}

type Props = {};
export default class App extends Component<Props> {
  state = {
    message: "",
  }

  async componentDidMount() {
    let message = "";
    let done_all = true;
    try {
      await test_case((result, point) => {
        console.log(`${point}: ${result ? "pass" : "reject"}\n`);
        message += `${point}: ${result ? "pass" : "reject"}\n`;
        this.setState({
          message,
        });
        if (!result) done_all = false;
      });
    } catch (e) {
      console.error(e);
      done_all = false;
    }
    message += `\nall: ${done_all ? "pass" : "reject"}`;
    this.setState({
      message,
    });
    if (!done_all) {
      console.error(message);
    }
  }
  render() {
    return (
      <View style={styles.container}>
        <Text style={styles.welcome}>Welcome to react-native-secp256k1</Text>
        <Text style={styles.instructions}>{this.state.message}</Text>
      </View>
    );
  }
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#F5FCFF',
  },
  welcome: {
    fontSize: 20,
    textAlign: 'center',
    margin: 10,
  },
  instructions: {
    textAlign: 'center',
    color: '#333333',
    marginBottom: 5,
  },
});
