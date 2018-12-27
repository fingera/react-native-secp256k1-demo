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
    message += `standard: ${done_all ? "pass" : "reject"}`;
    this.setState({
      message,
    });
    if (!done_all) {
      console.error(message);
    }

    const key1 = await secp256k1.ext.generateKey();
    const pub1 = await secp256k1.computePubkey(key1, true);
    const key2 = await secp256k1.ext.generateKey();
    const pub2 = await secp256k1.computePubkey(key2, true);

    const pubMessage = "Hello World 你好世界，:>";
    
    const encryped1 = await secp256k1.ext.encryptECDH(key1, pub2, pubMessage);
    const encryped2 = await secp256k1.ext.encryptECDH(key2, pub1, pubMessage);
    const decryped1 = await secp256k1.ext.decryptECDH(key2, pub1, encryped1);

    if (encryped1 !== encryped2 || decryped1 !== pubMessage) {
      message += "\next ECDH encrypt: reject";
    } else {
      message += "\next ECDH encrypt: pass";
    }
    this.setState({
      message,
    });

    const skey1 = "G6rWYPkY5m6VGkdUBzSFPxB8/lWcKOACBTHTlA4qmXQ";
    const skey2 = "1H1SJuGwoSFTqNI8wvVWEdGRpBvTnzLckoZ1QTF7gI0";
    const spub1 = await secp256k1.computePubkey(skey1, true);
    const spub2 = await secp256k1.computePubkey(skey2, true);
    const smessage = "Hello World 你好世界，:>\n据中国天气网消息，寒潮持续影响中，预计今明天（26-27日）北方气温将跌至此次过程最低，南方则在周末降至谷底，超一半国土气温将创今年入冬来的新低。同时，南方的雨雪今天将逐渐展开，甘肃、陕西等地降雪增多。";
    const sencrypt = "pYSjWncbST4liblAqDt9SklBHiXsn3JBPDBr/4Y3/d8cWy+dNMXHe/yHlB6t4I33m7Je4hrlb1RMECdnNk1TYhQb7J+Uw3hLhXmOol5rRKpUZgLl96bb+F4jTs9mLxcza2BbHWJLLF7aJxSR/MrtruXpCTnUSxRpdBe6m+gvF9IpYa1A+256Xnzm214LLvXxitzNYMidGCztOFIQwAccuD65kvsf7F91gym/1yEAHxLC66sw/t4JlvYBdVba7ndSCG12Exyyq+b8qxWIlxj3YGr5BBaql5AYa/4wZfq0NRH5YSWXsrEegyUDidsfew0lxXjTPno6liK+TjvGPJHIvnjJMhhlbCNGM6Ie9GJfy2a06LncliBs3YeKWcHWIlrvvITCRX3ehLwL1qgOlD7AjidV6AhnaHNqxeGSTXX3ZOFMEBdTILbWbogiJ6AeXjwc";
  
    const sencryped1 = await secp256k1.ext.encryptECDH(skey1, spub2, smessage);
    const sencryped2 = await secp256k1.ext.encryptECDH(skey2, spub1, smessage);
    const sdecryped1 = await secp256k1.ext.decryptECDH(skey2, spub1, sencryped1);
    if (sencryped1 !== sencryped2 || sdecryped1 !== smessage || sencrypt !== sencryped1) {
      message += "\next ECDH 2 encrypt: reject";
    } else {
      message += "\next ECDH 2 encrypt: pass";
    }
    this.setState({
      message,
    });
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
