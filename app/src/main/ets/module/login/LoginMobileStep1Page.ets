import router from '@ohos.router';
import { TopBackTitleBar } from '../../component/bar/TopBackTitleBar';
import { MobileTextField } from '../../component/textfield/MobileTextField';
import { LoginViewModel } from './LoginViewModel';

/**
 * 手机号登录第一步
 *
 * @author hwyz_leo
 */
@Component
struct LoginMobileStep1Page {
  @State loginViewModel: LoginViewModel = new LoginViewModel()
  @State mobile: string = ""
  @State isMobileFilled: boolean = false
  @State btnBgColor: Color = Color.Gray
  @State isSelect: boolean = false
  @State currentSelectImage: Resource = $r("app.media.icon_circle")

  build() {
    Column() {
      TopBackTitleBar({
        onBackClick: () => {
          router.back()
        }
      })
      Blank().height(20)
      Row() {
        Text($r("app.string.input_mobile"))
          .fontSize(20)
        Blank().layoutWeight(1)
      }

      Blank().height(20)
      Row() {
        Text("+86").width(40)
        Divider()
          .vertical(true)
          .height(24)
          .strokeWidth(1)
          .color(Color.Gray)
        MobileTextField({
          onChange: (value: string) => {
            this.mobile = value
            if (value.length == 13) {
              this.btnBgColor = Color.Black
              this.isMobileFilled = true
            } else {
              this.btnBgColor = Color.Gray
              this.isMobileFilled = false
            }
          }
        })
        Blank().layoutWeight(1)
      }

      Blank().height(20)
      Button($r("app.string.get_verify_code"))
        .width('100%')
        .backgroundColor(this.btnBgColor)
        .foregroundColor(Color.White)
        .onClick(() => {
          if (!this.isSelect) {
            AlertDialog.show({
              title: $r("app.string.tip"),
              message: $r("app.string.agree_user_agreement"),
              autoCancel: true,
              alignment: DialogAlignment.Default,
              offset: { dx: 0, dy: -20 },
              primaryButton: {
                value: $r("app.string.confirm"),
                action: () => {
                }
              }
            })
          } else if (!this.isMobileFilled) {
            AlertDialog.show({
              title: $r("app.string.tip"),
              message: $r("app.string.input_mobile"),
              autoCancel: true,
              alignment: DialogAlignment.Default,
              offset: { dx: 0, dy: -20 },
              primaryButton: {
                value: $r("app.string.confirm"),
                action: () => {
                }
              }
            })
          } else {
            this.loginViewModel.sendLoginVerifyCode("+86", this.mobile)
          }
        })
      Blank().height(10)
      Row() {
        Image(this.currentSelectImage)
          .width(14)
          .onClick(() => {
            if (this.isSelect) {
              this.isSelect = false
              this.currentSelectImage = $r("app.media.icon_circle")
            } else {
              this.isSelect = true
              this.currentSelectImage = $r("app.media.icon_circle_check")
            }
          })
        Blank().width(5)
        Text($r("app.string.login_confirm_tip"))
          .fontSize(12)
      }
      .padding({ left: 5, right: 25 })
      .alignItems(VerticalAlign.Top)
    }
    .padding({ left: 20, right: 20 })
  }
}

@Entry
@Component
struct LoginMobileStep1PagePreview {
  build() {
    Column() {
      LoginMobileStep1Page()
    }
  }
}