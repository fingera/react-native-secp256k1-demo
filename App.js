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

const private1 = "67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530";
const private2 = "112233445566778899AABBCCDEE112233445566778899AABBCCDEE1122334455";

type Props = {};
export default class App extends Component<Props> {
  state = {
    priv1_verify: false,
    priv2_verify: false,
  }

  async componentDidMount() {
    const p1 = secp256k1.hex_decode(private1);
    const base64_p2 = secp256k1.base64_encode(secp256k1.hex_decode(private2));
    const base64_p1 = secp256k1.base64_encode(p1);
    this.setState({
      priv1_verify: await secp256k1.raw_secKeyVerify(p1),
      pub1_compress: secp256k1.hex_encode(await secp256k1.raw_computePubkey(p1, true)),
      pub1: secp256k1.hex_encode(await secp256k1.raw_computePubkey(p1, false)),
      priv2_verify: await secp256k1.secKeyVerify(base64_p2),
      pub2_compress: await secp256k1.computePubkey(base64_p2, true),
      pub2: await secp256k1.computePubkey(base64_p2, false),

      sec1: await secp256k1.createECDHSecret(base64_p1, await secp256k1.computePubkey(base64_p2, true)),
      sec2: await secp256k1.createECDHSecret(base64_p2, await secp256k1.computePubkey(base64_p1, true)),
    });
  }
  render() {
    return (
      <View style={styles.container}>
        <Text style={styles.welcome}>Welcome to react-native-secp256k1</Text>
        <Text style={styles.instructions}>{`private1: ${private1} ${this.state.priv1_verify}`}</Text>
        <Text style={styles.instructions}>{`pub1_compress: ${this.state.pub1_compress}`}</Text>
        <Text style={styles.instructions}>{`pub1: ${this.state.pub1}`}</Text>
        <Text style={styles.instructions}>{`private2: ${private2} ${this.state.priv2_verify}`}</Text>
        <Text style={styles.instructions}>{`pub2_compress: ${this.state.pub2_compress}`}</Text>
        <Text style={styles.instructions}>{`pub2: ${this.state.pub2}`}</Text>
        <Text style={styles.instructions}>{`sec1: ${this.state.sec1}`}</Text>
        <Text style={styles.instructions}>{`sec2: ${this.state.sec2}`}</Text>
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
