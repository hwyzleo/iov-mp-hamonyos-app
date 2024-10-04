import router from '@ohos.router';

/**
 * 我的页面 - 未登录
 *
 * @author hwyz_leo
 */
@Component
export struct MyPageNotLogin {
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
        Text($r("app.string.not_login_welcome")).fontSize(20)
        Blank().layoutWeight(1)
        Image($r("app.media.my_place_holder")).width(80)
      }

      Blank().height(40)
      Button($r("app.string.login_register"))
        .width('100%')
        .backgroundColor(Color.White)
        .foregroundColor(Color.Black)
        .borderColor(Color.Black)
        .borderWidth(1)
        .onClick(() => {
          router.pushUrl({
            url: 'module/login/LoginMobileStep1Page',
          })
        })
      Blank()
    }
    .padding({ left: 20, right: 20 })
  }
}

@Entry
@Component
struct MyPageNotLoginPreview {
  build() {
    Column() {
      MyPageNotLogin()
    }
  }
}