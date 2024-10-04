import { GlobalStateManager } from '../../utils/GlobalStateManager';
import { LoginResponse, LoginVerifyCodeRequest, TspResponse, VerifyCodeLoginRequest } from '../bean/HttpBean';
import { mockLoginResponse, mockTspResponse } from '../bean/MockBean';
import { TspManager } from './TspManager';

/**
 * TSP接口
 *
 * @author hwyz_leo
 */
export class TspApi {
  // 发送登录验证码
  async sendLoginVerifyCode(request: LoginVerifyCodeRequest): Promise<TspResponse<void>> {
    if (GlobalStateManager.isMock) {
      return new Promise((resolve) => {
        setTimeout(() => {
          let tspResponse: TspResponse<void> = mockTspResponse()
          resolve(tspResponse);
        }, 200);
      });
    } else {
      let path = "/mp/login/action/sendSmsVerifyCode"
      return await TspManager.shared.requestPost<void>(path, request)
    }
  }

  // 验证码登录
  async verifyCodeLogin(request: VerifyCodeLoginRequest): Promise<TspResponse<LoginResponse>> {
    if (GlobalStateManager.isMock) {
      return new Promise((resolve) => {
        setTimeout(() => {
          let loginResponse: LoginResponse = mockLoginResponse()
          let tspResponse: TspResponse<LoginResponse> = { code: 0, ts: 0, data: loginResponse }
          resolve(tspResponse);
        }, 200);
      });
    } else {
      let path = "/mp/login/action/smsVerifyCodeLogin"
      return await TspManager.shared.requestPost<LoginResponse>(path, request)
    }
  }
}