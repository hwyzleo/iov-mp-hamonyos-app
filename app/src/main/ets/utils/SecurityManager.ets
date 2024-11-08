import cryptoFramework from '@ohos.security.cryptoFramework';
import asset from '@ohos.security.asset';
import util from '@ohos.util';
import { buffer } from '@kit.ArkTS';
import { DerEncoder } from './DerEncoder';

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
    let key = "1596067469523820544-6FE4BCE901F74B2AA392E6E41FE7679E";
    let keyPair = this.loadKeyPair(key);
    if (keyPair == null) {
      return null
    }
    let publicKey = keyPair.pubKey
    // 构建主题信息
    const subject: SubjectInfo[] = [
      { key: 'CN', value: key },
      { key: 'O', value: "O" },
      { key: 'OU', value: "OU" },
      { key: 'L', value: "L" },
      { key: 'ST', value: "ST" },
      { key: 'C', value: "CN" }
    ];
    // 构建CSR主体
    const certificationRequestInfo: CertificationRequestInfo = {
      version: 1,
      subject: subject,
      subjectPKInfo: {
        algorithm: 'RSA',
        subjectPublicKey: publicKey.getEncoded().data
      },
      attributes: []
    };
    // 将CSR主体序列化为DER格式
    const certificationRequestInfoDer = this.encodeCSRBody(certificationRequestInfo);
    // 使用私钥对CSR主体进行签名
    const signature = this.signatureUint8(certificationRequestInfoDer, key);
    if (signature == null) {
      return null;
    }
    // 构建完整的CSR
    const csr: CertificationRequest = {
      certificationRequestInfo: certificationRequestInfo,
      signatureAlgorithm: 'SHA256withRSA',
      signature: signature
    };
    // 将CSR转换为PEM格式
    let csrDer = this.encodeCertificationRequest(csr);
    const csrPem = this.derToPem(csrDer, 'CERTIFICATE REQUEST');
    return csrPem;
  }

  /**
   * 将DER转换为PEM格式
   * @param der
   * @param label
   * @returns
   */
  private derToPem(der: Uint8Array, label: string): string {
    let base64 = new util.Base64Helper();
    const derStr = base64.encodeToStringSync(der);
    const pem = `-----BEGIN ${label}-----\n${derStr}\n-----END ${label}-----`;
    return pem;
  }

  /**
   * 对CSR Body编码
   * @param csrBody
   * @returns
   */
  private encodeCSRBody(certificationRequestInfo: CertificationRequestInfo): Uint8Array {
    const encoder = new DerEncoder();
    encoder.encodeSequence(() => {
      // Version
      encoder.encodeInteger(certificationRequestInfo.version);
      // Subject
      encoder.encodeSequence(() => {
        for (const item of certificationRequestInfo.subject) {
          encoder.encodeSet(() => {
            encoder.encodeSequence(() => {
              encoder.encodeOID(item.key);
              encoder.encodePrintableString(item.value);
            });
          });
        }
      });
      // SubjectPublicKeyInfo
      encoder.encodeSequence(() => {
        encoder.encodeSequence(() => {
          encoder.encodeOID(this.getOIDForAlgorithm(certificationRequestInfo.subjectPKInfo.algorithm));
          encoder.encodeNull();
        });
        encoder.encodeBitString(certificationRequestInfo.subjectPKInfo.subjectPublicKey);
      });
      // Attributes (if any)
      if (certificationRequestInfo.attributes.length > 0) {
        encoder.encodeSequence(() => {
          for (const attr of certificationRequestInfo.attributes) {
            encoder.encodeSequence(() => {
              encoder.encodeOID(attr.type);
              encoder.encodeSet(() => {
                // Encode attribute value based on its type
                if (typeof attr.value === 'string') {
                  encoder.encodePrintableString(attr.value);
                } else if (attr.value instanceof Uint8Array) {
                  encoder.encodeBitString(attr.value);
                }
                // Add more type checks and encoding as needed
              });
            });
          }
        });
      }
    });
    return encoder.getEncoded();
  }

  /**
   * 对CSR编码
   * @param certificationRequest
   * @returns
   */
  private encodeCertificationRequest(certificationRequest: CertificationRequest): Uint8Array {
    const encoder = new DerEncoder();

    encoder.encodeSequence(() => {
      // CSR Info (CertificationRequestInfo)
      encoder.encodeSequence(() => {
        // Version
        encoder.encodeInteger(certificationRequest.certificationRequestInfo.version);
        // Subject
        encoder.encodeSequence(() => {
          for (const item of certificationRequest.certificationRequestInfo.subject) {
            encoder.encodeSet(() => {
              encoder.encodeSequence(() => {
                encoder.encodeOID(item.key);
                encoder.encodePrintableString(item.value);
              });
            });
          }
        });

        // SubjectPublicKeyInfo
        encoder.encodeSequence(() => {
          encoder.encodeSequence(() => {
            encoder.encodeOID(this.getOIDForAlgorithm(certificationRequest.certificationRequestInfo.subjectPKInfo.algorithm));
            encoder.encodeNull();
          });
          encoder.encodeBitString(certificationRequest.certificationRequestInfo.subjectPKInfo.subjectPublicKey);
        });

        // Attributes (if any)
        if (certificationRequest.certificationRequestInfo.attributes.length > 0) {
          encoder.encodeSequence(() => {
            for (const attr of certificationRequest.certificationRequestInfo.attributes) {
              encoder.encodeSequence(() => {
                encoder.encodeOID(attr.type);
                encoder.encodeSet(() => {
                  // Encode attribute value based on its type
                  if (typeof attr.value === 'string') {
                    encoder.encodePrintableString(attr.value);
                  } else if (attr.value instanceof Uint8Array) {
                    encoder.encodeBitString(attr.value);
                  }
                });
              });
            }
          });
        }
      });

      // Signature Algorithm
      encoder.encodeSequence(() => {
        encoder.encodeOID(this.getOIDForAlgorithm(certificationRequest.signatureAlgorithm));
        encoder.encodeNull();
      });

      // Signature
      encoder.encodeBitString(certificationRequest.signature);
    });

    return encoder.getEncoded();
  }

  private getOIDForAlgorithm(algorithm: string): string {
    const oidMap = new Map([
      ['RSA', '1.2.840.113549.1.1.1'],
      ['SHA256withRSA', '1.2.840.113549.1.1.11'],
    ]);
    return oidMap.get(algorithm) || '1.2.840.113549.1.1.1';
  }

  /**
   * 生成公私钥对
   * @returns
   */
  private generateRSA2048KeyPair(): cryptoFramework.KeyPair | null {
    try {
      let asyKeyGenerator = cryptoFramework.createAsyKeyGenerator("RSA2048");
      let keyPair = asyKeyGenerator.generateKeyPairSync();
      console.log("Asymmetric key generator created successfully");
      return keyPair;
    } catch (error) {
      console.error("Failed to create asymmetric key generator:", error);
    }
    return null
  }

  /**
   * 保存公私钥对
   * @param keyPair
   * @param key
   */
  private storeKeyPair(keyPair: cryptoFramework.KeyPair, key: string) {
    let pubKey = key + "-pub"
    let priKey = key + "-pri"
    let query: asset.AssetMap = new Map();
    try {
      query.set(asset.Tag.ALIAS, this.stringToUint8Array(pubKey));
      let res = asset.querySync(query);
      if (res.length > 0) {
        asset.removeSync(query);
      }
    } catch (error) {
      console.error('Failed to save private key:', error);
    }
    try {
      let attributes: asset.AssetMap = new Map();
      attributes.set(asset.Tag.ALIAS, this.stringToUint8Array(pubKey));
      attributes.set(asset.Tag.SECRET, keyPair.pubKey.getEncoded().data);
      asset.addSync(attributes);
    } catch (error) {
      console.error('Failed to save private key:', error);
    }
    try {
      query.set(asset.Tag.ALIAS, this.stringToUint8Array(priKey));
      let res = asset.querySync(query);
      if (res.length > 0) {
        asset.removeSync(query);
      }
    } catch (error) {
      console.error('Failed to save private key:', error);
    }
    try {
      let attributes: asset.AssetMap = new Map();
      attributes.set(asset.Tag.ALIAS, this.stringToUint8Array(priKey + "-0"));
      let priSecret0 = new Uint8Array(keyPair.priKey.getEncoded().data.buffer, 0, 1024)
      attributes.set(asset.Tag.SECRET, priSecret0);
      asset.addSync(attributes);
      attributes.set(asset.Tag.ALIAS, this.stringToUint8Array(priKey + "-1"));
      let priSecret1 =
        new Uint8Array(keyPair.priKey.getEncoded().data.buffer, 1024, keyPair.priKey.getEncoded().data.length - 1024)
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
  private loadKeyPair(key: string): cryptoFramework.KeyPair | null {
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
        let asyKeyGenerator = cryptoFramework.createAsyKeyGenerator("RSA2048");
        let pkBlob: cryptoFramework.DataBlob = { data: pubSecret };
        let skBlob: cryptoFramework.DataBlob = { data: priSecret };
        let keyPair = asyKeyGenerator.convertKeySync(pkBlob, skBlob)
        if (keyPair != null) {
          return keyPair
        }
      }
    } catch (error) {
      if (error.code == 24000002) {
        let keyPair = this.generateRSA2048KeyPair();
        if (keyPair != null) {
          this.storeKeyPair(keyPair, key);
          return keyPair
        }
      }
      console.error('Failed to load private key:', error);
    }
    return null;
  }

  /**
   * 签名
   * @param plain
   * @param key
   */
  private signature(dataStr: string, key: string): string | null {
    let signData = this.signatureUint8(new Uint8Array(buffer.from(dataStr, 'utf-8').buffer), key);
    if (signData != null) {
      return util.Base64Helper.prototype.encodeToStringSync(signData);
    }
    return null;
  }

  /**
   * 签名
   * @param data
   * @param key
   * @returns
   */
  private signatureUint8(data: Uint8Array, key: string): Uint8Array | null {
    try {
      let dataArray: cryptoFramework.DataBlob = { data: data };
      const signer = cryptoFramework.createSign("RSA2048|PKCS1|SHA256");
      let keyPair = this.loadKeyPair(key)
      if (keyPair == null) {
        return null
      }
      signer.init(keyPair.priKey);
      let signData = signer.signSync(dataArray);
      return signData.data;
    } catch (error) {
      console.error('Signing failed:', error);
      return null;
    }
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

/**
 * 主题信息
 */
interface SubjectInfo {
  key: string;
  value: string;
}

/**
 * 主题公钥信息
 */
interface SubjectPKInfo {
  algorithm: string;
  subjectPublicKey: Uint8Array;
}

/**
 * 属性
 */
interface Attribute {
  type: string;
  value: string | number | boolean | Uint8Array;
}

/**
 * CSR主体
 */
interface CertificationRequestInfo {
  version: number;
  subject: SubjectInfo[];
  subjectPKInfo: SubjectPKInfo;
  attributes: Attribute[];
}

/**
 * CSR
 */
interface CertificationRequest {
  certificationRequestInfo: CertificationRequestInfo;
  signatureAlgorithm: string;
  signature: Uint8Array;
}