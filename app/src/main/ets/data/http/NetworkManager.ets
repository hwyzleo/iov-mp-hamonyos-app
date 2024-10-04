import http from '@ohos.net.http';

/**
 * 网络请求管理
 *
 * @author hwyz_leo
 */
export class NetworkManager {
  public static shared: NetworkManager = new NetworkManager()

  private constructor() {
  }

  /**
   * GET请求
   * @param path
   * @returns
   */
  async requestGet(path: string): Promise<string> {
    return new Promise((resolve, reject) => {
      let httpRequest = http.createHttp();
      httpRequest.request(
        path,
        {
          method: http.RequestMethod.GET,
          header: {
            'Content-Type': 'application/json'
          },
        },
        (err, data) => {
          if (!err) {
            resolve(data.result.toString());
          } else {
            reject(err);
          }
        }
      );
    });
  }

  /**
   * POST请求
   * @param path
   * @returns
   */
  async requestPost(path: string, header: object, body: string): Promise<string> {
    return new Promise((resolve, reject) => {
      let httpRequest = http.createHttp();
      httpRequest.request(
        path,
        {
          method: http.RequestMethod.POST,
          header: header,
          extraData: body
        },
        (err, data) => {
          if (!err) {
            resolve(data.result.toString());
          } else {
            reject(err);
          }
        }
      );
    });
  }
}