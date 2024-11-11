import asset from '@ohos.security.asset';
import util from '@ohos.util';
import napi from 'libapp.so';

/**
 * 安全管理类
 */
export class SecurityManager {
  static shared: SecurityManager

  /**
   * 初始化
   * @param kvManager
   */
  public static async init() {
    if (SecurityManager.shared == undefined) {
      SecurityManager.shared = new SecurityManager()
    }
  }

  /**
   * 生成CSR文件
   * @returns
   */
  createCsr(): string | null {
    let key = "1596067469523820544-6FE4BCE901F74B2AA392E6E41FE7679A";
    let keyPair = this.loadKeyPair(key);
    if (keyPair == null) {
      return null
    }
    let csr = napi.generateCSR(keyPair, keyPair, key);
    return csr;
  }

  /**
   * 保存公私钥对
   * @param keyPair
   * @param key
   */
  private storeKeyPair(keyPair: string, key: string) {
    let pubKey = key + "-pub"
    let priKey = key + "-pri"
    let keyPairSplit = keyPair.split("-----BEGIN PUBLIC KEY-----")
    let priSecret = keyPairSplit[0]
      .replaceAll("-----BEGIN PRIVATE KEY-----", "")
      .replaceAll("-----END PRIVATE KEY-----", "")
      .replaceAll("\n", "");
    let pubSecret =
      keyPairSplit[1]
        .replaceAll("-----BEGIN PUBLIC KEY-----", "")
        .replaceAll("-----END PUBLIC KEY-----", "")
        .replaceAll("\n", "");
    let query: asset.AssetMap = new Map();
    try {
      query.set(asset.Tag.ALIAS, this.stringToUint8Array(pubKey));
      let res = asset.querySync(query);
      if (res.length > 0) {
        asset.removeSync(query);
      }
    } catch (error) {
    }
    try {
      let attributes: asset.AssetMap = new Map();
      attributes.set(asset.Tag.ALIAS, this.stringToUint8Array(pubKey));
      attributes.set(asset.Tag.SECRET, this.stringToUint8Array(pubSecret));
      asset.addSync(attributes);
    } catch (error) {
      console.error('Failed to save public key:', error);
    }
    try {
      query.set(asset.Tag.ALIAS, this.stringToUint8Array(priKey));
      let res = asset.querySync(query);
      if (res.length > 0) {
        asset.removeSync(query);
      }
    } catch (error) {
    }
    try {
      let attributes: asset.AssetMap = new Map();
      let priSecretUint8Array = this.stringToUint8Array(priSecret);
      attributes.set(asset.Tag.ALIAS, this.stringToUint8Array(priKey + "-0"));
      let priSecret0 = new Uint8Array(priSecretUint8Array.buffer, 0, 1024)
      attributes.set(asset.Tag.SECRET, priSecret0);
      asset.addSync(attributes);
      attributes.set(asset.Tag.ALIAS, this.stringToUint8Array(priKey + "-1"));
      let priSecret1 =
        new Uint8Array(priSecretUint8Array.buffer, 1024, priSecretUint8Array.length - 1024)
      attributes.set(asset.Tag.SECRET, priSecret1);
      asset.addSync(attributes);
    } catch (error) {
      console.error('Failed to save private key:', error);
    }
  }

  /**
   * 读取公私钥对
   * @param key
   * @returns
   */
  private loadKeyPair(key: string): string | null {
    let pubKey = key + "-pub"
    let priKey = key + "-pri"
    try {
      let query: asset.AssetMap = new Map();
      query.set(asset.Tag.ALIAS, this.stringToUint8Array(pubKey));
      query.set(asset.Tag.RETURN_TYPE, asset.ReturnType.ALL);
      let pubResult = asset.querySync(query)
      query.set(asset.Tag.ALIAS, this.stringToUint8Array(priKey + "-0"));
      let pri0Result = asset.querySync(query)
      query.set(asset.Tag.ALIAS, this.stringToUint8Array(priKey + "-1"));
      let pri1Result = asset.querySync(query)
      if (pubResult.length > 0 && pri0Result.length > 0 && pri1Result.length > 0) {
        let pubSecret = pubResult[0].get(asset.Tag.SECRET) as Uint8Array
        let pri0Secret = pri0Result[0].get(asset.Tag.SECRET) as Uint8Array
        let pri1Secret = pri1Result[0].get(asset.Tag.SECRET) as Uint8Array
        let priSecret = new Uint8Array(pri0Secret.length + pri1Secret.length);
        priSecret.set(new Uint8Array(pri0Secret), 0);
        priSecret.set(new Uint8Array(pri1Secret), pri0Secret.length);
        if (pubSecret.length > 0 && priSecret.length > 0) {
          return this.uint8ArrayToString(pubSecret) + this.uint8ArrayToString(priSecret);
        }
      }
    } catch (error) {
      if (error.code == 24000002) {
        let keyPair = napi.generateRSA2048KeyPair()
        if (keyPair != null) {
          this.storeKeyPair(keyPair, key);
          return keyPair
        }
      }
      console.error('Failed to load key pair:', error);
    }
    return null;
  }

  /**
   * 字符串转数字
   * @param str
   * @returns
   */
  private stringToUint8Array(str: string): Uint8Array {
    let encoder = new util.TextEncoder();
    return encoder.encodeInto(str);
  }

  /**
   * 数字转字符串
   * @param array
   * @returns
   */
  private uint8ArrayToString(array: Uint8Array): string {
    let decoder = new util.TextDecoder();
    return decoder.decodeWithStream(array);
  }
}