import { router } from '@kit.ArkUI'
import { TopBackTitleBar } from '../../component/bar/TopBackTitleBar'
import { OtpTextField } from '../../component/textfield/OtpTextField'
import { gAppTheme } from '../../theme/Theme'
import { LoginViewModel } from './LoginViewModel'

/**
 * 手机号登录第二步
 *
 * @author hwyz_leo
 */
@Component
struct LoginMobileStep2Page {
  @State loginViewModel: LoginViewModel = new LoginViewModel()
  @State countryRegionCode: string = ""
  @State mobile: string = ""

  aboutToAppear() {
    const params = router.getParams() as Record<string, string>;
    this.countryRegionCode = params['countryRegionCode']
    this.mobile = params['mobile'];
  }

  build() {
    Column() {
      TopBackTitleBar({
        onBackClick: () => {
          router.back()
        }
      })
      Blank().height(20)
      Row() {
        Text($r("app.string.input_verify_code"))
          .fontSize(20)
        Blank().layoutWeight(1)
      }

      Blank().height(20)
      Row() {
        Text($r("app.string.verify_code_has_sent"))
          .fontSize(14)
          .fontColor(gAppTheme.colors?.fontSecondary)
        Text(this.mobile)
          .fontSize(14)
          .fontColor(gAppTheme.colors?.fontSecondary)
        Blank().layoutWeight(1)
      }

      Blank().height(20)
      OtpTextField({
        onFinish: (value: string) => {
          this.loginViewModel.verifyCodeLogin(this.countryRegionCode, this.mobile, value)
        }
      })
    }
    .padding({ left: 20, right: 20 })
  }
}

@Entry
@Component
struct LoginMobileStep2PagePreview {
  build() {
    Column() {
      LoginMobileStep2Page()
    }
  }
}