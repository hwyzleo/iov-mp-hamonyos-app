import router from '@ohos.router';
import promptAction from '@ohos.promptAction';
import { LoginResponse, LoginVerifyCodeRequest, TspResponse, VerifyCodeLoginRequest } from '../../data/bean/HttpBean';
import { TspApi } from '../../data/http/TspApi';
import { UserManager } from '../../utils/UserManager';

@Observed
export class LoginViewModel {
  private tspApi: TspApi = new TspApi()
  public countryRegionCode: string = "";

  async sendLoginVerifyCode(countryRegionCode: string, mobile: string) {
    try {
      mobile = mobile.replaceAll(" ", "")
      let request: LoginVerifyCodeRequest = { countryRegionCode: countryRegionCode, mobile: mobile }
      let response = await this.tspApi.sendLoginVerifyCode(request)
      if (response.code == 0) {
        router.pushUrl({
          url: 'module/login/LoginMobileStep2Page',
          params: {
            countryRegionCode: countryRegionCode,
            mobile: mobile
          }
        })
      } else {
        promptAction.showToast({
          message: response.message,
          duration: 2000
        });
      }
    } catch (error) {
      console.error('Failed to sendLoginVerifyCode:', error)
    }
  }

  async verifyCodeLogin(countryRegionCode: string, mobile: string, verifyCode: string) {
    try {
      let request: VerifyCodeLoginRequest = {
        countryRegionCode: countryRegionCode,
        mobile: mobile,
        verifyCode: verifyCode
      }
      let response: TspResponse<LoginResponse> = await this.tspApi.verifyCodeLogin(request)
      if (response.code == 0) {
        let loginResponse: LoginResponse = response.data!
        UserManager.shared.login(loginResponse)
        router.pushUrl({
          url: 'module/my/page/MyPage',
          params: {
            isLogin: true,
            nickname: loginResponse.nickname,
            avatar: loginResponse.avatar
          }
        })
      } else {
        promptAction.showToast({
          message: response.message,
          duration: 2000
        });
      }
    } catch (error) {
      console.error('Failed to verifyCodeLogin:', error)
    }
  }
}