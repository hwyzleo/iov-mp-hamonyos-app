/**
 * 圆角按钮
 */
@Component
export struct RoundedCornerButton {
  @Prop title: string
  @Prop titleLocal: Resource
  bindClick?: () => void

  build() {
    if (this.title != null) {
      Button(this.title)
        .width('100%')
        .backgroundColor(Color.White)
        .foregroundColor(Color.Black)
        .borderColor(Color.Black)
        .borderWidth(1)
        .onClick(() => {
          if (this.bindClick) {
            this.bindClick()
          }
        })
    } else if (this.titleLocal != null) {
      Button(this.titleLocal)
        .width('100%')
        .backgroundColor(Color.White)
        .foregroundColor(Color.Black)
        .borderColor(Color.Black)
        .borderWidth(1)
        .onClick(() => {
          if (this.bindClick) {
            this.bindClick()
          }
        })
    }
  }
}

@Entry
@Component
struct RoundedCornerButtonPreview {
  build() {
    Column() {
      RoundedCornerButton()
    }
  }
}