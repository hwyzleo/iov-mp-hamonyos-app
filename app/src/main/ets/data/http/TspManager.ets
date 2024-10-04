import { GlobalStateManager } from '../../utils/GlobalStateManager';
import { TspResponse } from '../bean/HttpBean';
import { NetworkManager } from './NetworkManager';

/**
 * TSP请求管理
 *
 * @author hwyz_leo
 */
export class TspManager {
  public static shared: TspManager = new TspManager()

  /**
   * GET请求
   * @param path
   * @returns
   */
  async requestGet<T>(path: string): Promise<TspResponse<T>> {
    try {
      const result = await NetworkManager.shared.requestGet(GlobalStateManager.apiUrl + path);
      return JSON.parse(result) as TspResponse<T>;
    } catch (error) {
      let tspResponse: TspResponse<T> = { code: 1, message: error, ts: 0 }
      return tspResponse;
    }
  }

  /**
   * POST请求
   * @param path
   * @returns
   */
  async requestPost<T>(path: string, body: object): Promise<TspResponse<T>> {
    try {
      let wholePath = GlobalStateManager.apiUrl + path
      let header: Record<string, string> = {
        'Content-Type': 'application/json',
        'clientId': '1733D7DE-0D5A-457A-946F-639C9F175B3C'
      };
      let bodyStr = JSON.stringify(body)
      const result = await NetworkManager.shared.requestPost(wholePath, header, bodyStr);
      return JSON.parse(result) as TspResponse<T>;
    } catch (error) {
      let tspResponse: TspResponse<T> = { code: 1, message: error, ts: 0 }
      return tspResponse;
    }
  }
}