import distributedKVStore from '@ohos.data.distributedKVStore';
import { LoginResponse } from '../data/bean/HttpBean';
import { BusinessError } from '@kit.BasicServicesKit';

/**
 * 用户管理类
 *
 * @author hwyz_leo
 */
export class UserManager {
  static shared: UserManager
  private kvStore: distributedKVStore.SingleKVStore | null = null;
  private keyIsLogin: string = "isLogin"
  private keyToken: string = "token"
  private keyNickname: string = "nickname"
  private keyAvatar: string = "avatar"
  private valIsLogin?: boolean
  private valToken?: string
  private valNickname?: string
  private valAvatar?: string

  /**
   * 初始化
   * @param kvManager
   */
  public static async init(kvManager: distributedKVStore.KVManager) {
    if (UserManager.shared == undefined) {
      UserManager.shared = new UserManager()
      UserManager.shared.initKvStore(kvManager)
    }
  }

  /**
   * 初始化KV Store
   * @param kvManager
   */
  private initKvStore(kvManager: distributedKVStore.KVManager) {
    try {
      const options: distributedKVStore.Options = {
        createIfMissing: true,
        encrypt: false,
        backup: false,
        autoSync: false,
        kvStoreType: distributedKVStore.KVStoreType.SINGLE_VERSION,
        securityLevel: distributedKVStore.SecurityLevel.S2,
      };
      kvManager.getKVStore('user', options, (err: BusinessError, store: distributedKVStore.SingleKVStore) => {
        if (err) {
          console.error(`获取KVStore异常。[${err.code}:${err.message}]`);
          return;
        }
        this.kvStore = store;
        UserManager.shared.initData()
      });
    } catch (e) {
      let error = e as BusinessError;
      console.error(`初始化用户管理类异常。[${error.code}:${error.message}]`);
    }
  }

  /**
   * 初始化本地数据
   */
  private async initData() {
    this.valIsLogin = await this.getKvStoreValue(this.keyIsLogin) as boolean
    this.valToken = await this.getKvStoreValue(this.keyToken) as string
    this.valNickname = await this.getKvStoreValue(this.keyNickname) as string
    this.valAvatar = await this.getKvStoreValue(this.keyAvatar) as string
  }

  /**
   * 获取KV值
   * @param key
   * @returns
   */
  private getKvStoreValue(key: string): Promise<boolean | string | number | Uint8Array> {
    return new Promise((resolve, reject) => {
      if (this.kvStore != null) {
        this.kvStore.get(key, (err, data) => {
          if (err) {
            reject(err);
          } else {
            resolve(data);
          }
        });
      }
    });
  }

  /**
   * 是否登录
   * @returns true 已登录，false 未登录
   */
  isLogin(): boolean {
    if (this.valIsLogin == undefined) {
      this.valIsLogin = false;
    }
    return this.valIsLogin;
  }

  /**
   * 获取Token
   * @returns
   */
  token(): string | null {
    if (this.isLogin()) {
      return this.valToken!;
    }
    return null;
  }

  /**
   * 获取昵称
   * @returns
   */
  nickname(): string | null {
    if (this.isLogin()) {
      return this.valNickname!;
    }
    return null;
  }

  /**
   * 获取头像
   * @returns
   */
  avatar(): string | null {
    if (this.isLogin()) {
      return this.valAvatar!;
    }
    return null;
  }

  /**
   * 登录
   * @param loginResponse 登录返回
   */
  login(loginResponse: LoginResponse) {
    try {
      if (this.kvStore != null) {
        this.kvStore.put(this.keyIsLogin, true, (err: BusinessError) => {
          if (err != undefined) {
            console.error(`写入是否登录异常。[${err.code}:${err.message}]`);
            return;
          }
          this.valIsLogin = true;
        });
        this.kvStore.put(this.keyToken, loginResponse.token, (err: BusinessError) => {
          if (err != undefined) {
            console.error(`写入Token异常。[${err.code}:${err.message}]`);
            return;
          }
          this.valToken = loginResponse.token;
        });
        this.kvStore.put(this.keyNickname, loginResponse.nickname, (err: BusinessError) => {
          if (err != undefined) {
            console.error(`写入昵称异常。[${err.code}:${err.message}]`);
            return;
          }
          this.valNickname = loginResponse.nickname;
        });
        if (loginResponse.avatar != null) {
          this.kvStore.put(this.keyAvatar, loginResponse.avatar!, (err: BusinessError) => {
            if (err != undefined) {
              console.error(`写入头像异常。[${err.code}:${err.message}]`);
              return;
            }
            this.valAvatar = loginResponse.avatar;
          });
        }
      }
    } catch (e) {
      let error = e as BusinessError;
      console.error(`登录异常。[${error.code}:${error.message}]`);
    }
  }

  /**
   * 退出登录
   */
  logout() {
    try {
      if (this.kvStore != null) {
        this.kvStore.put(this.keyIsLogin, false, (err: BusinessError) => {
          if (err != undefined) {
            console.error(`写入是否登录异常。[${err.code}:${err.message}]`);
            return;
          }
          this.valIsLogin = false
        });
      }
    } catch (e) {
      let error = e as BusinessError;
      console.error(`退出登录异常。[${error.code}:${error.message}]`);
    }
  }
}