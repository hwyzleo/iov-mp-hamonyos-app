import router from '@ohos.router';
import { SecurityManager } from '../../../utils/SecurityManager';
import { UserManager } from '../../../utils/UserManager';

/**
 * 我的页面 - 已登录
 *
 * @author hwyz_leo
 */
@Component
export struct MyPageLogin {
  @State nickname: string = "nickname"
  @State avatar: string = ""
  @State csr: string = ""

  aboutToAppear(): void {
    const params = router.getParams() as Record<string, string>;
    if (params != undefined && params['nickname'] != undefined) {
      this.nickname = params['nickname']
    } else {
      this.nickname = UserManager.shared.nickname() as string;
    }
    if (params != undefined && params['avatar'] != undefined) {
      this.avatar = params['avatar']
    } else {
      this.avatar = UserManager.shared.avatar() as string;
    }
  }

  build() {
    Column() {
      Row() {
        Blank().layoutWeight(1)
        Image($r("app.media.icon_bell")).width(30)
        Blank().width(20)
        Image($r("app.media.icon_setting"))
          .width(30)
          .onClick(() => {
            router.pushUrl({
              url: 'module/my/page/SettingPage',
            })
          })
      }

      Blank().height(20)
      Row() {
        Text(this.nickname).fontSize(20)
        Blank().layoutWeight(1)
        Image(this.avatar).width(80)
      }
      Row() {
        TextInput({ text: this.csr })
      }
      Scroll() {
        Column() {
          Blank().height(40)
          Row() {
            Button($r("app.string.sign_in"))
              .width(80)
              .backgroundColor(Color.White)
              .foregroundColor(Color.Black)
              .borderColor(Color.Black)
              .borderWidth(1)
              .onClick(() => {
                let csr = SecurityManager.shared.createCsr()
                if(csr != null) {
                  this.csr = csr
                  console.info(csr)
                }
                // router.pushUrl({
                //   url: 'module/login/LoginMobileStep1Page',
                // })
              })
            Blank().layoutWeight(1)
          }

          Blank()
        }
      }
    }
    .padding({ left: 20, right: 20 })
  }
}

@Entry
@Component
struct MyPageLoginPreview {
  build() {
    Column() {
      MyPageLogin()
    }
  }
}