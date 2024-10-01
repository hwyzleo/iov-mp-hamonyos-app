import router from '@ohos.router';

@Entry
@Component
export struct MyView {

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
              url: 'module/my/view/SettingView',
            })
          })
      }
      Blank().height(20)
      Row() {
        Text("Hi,\n欢迎您的到来").fontSize(20)
        Blank().layoutWeight(1)
        Image($r("app.media.my_place_holder")).width(80)
      }
      Blank().height(40)
      Button("登录 / 注册")
        .width('100%')
        .backgroundColor(Color.White)
        .foregroundColor(Color.Black)
        .borderColor(Color.Black)
        .borderWidth(1)
      Blank()
    }
    .padding({ left: 20, right: 20 })
  }

}