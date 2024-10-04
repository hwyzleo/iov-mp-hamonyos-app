@Component
export struct TopBackTitleBar {
  @Prop title: string = ""
  @Prop titleLocal: Resource = $r("app.string.title")
  @Prop titleType: string = "string"
  private onBackClick: () => void = () => {
  }

  build() {
    Stack() {
      Row() {
        Blank().layoutWeight(1)
        if (this.titleType == "string") {
          Text(`${this.title}`)
        } else if (this.titleType == "resource") {
          Text(this.titleLocal)
        }
        Blank().layoutWeight(1)
      }

      Row() {
        Image($r("app.media.icon_arrow_left"))
          .width(30)
          .onClick(() => this.onBackClick())
        Blank().layoutWeight(1)
      }
    }
  }
}

@Entry
@Component
struct TopBackTitleBarPreview {
  build() {
    Column() {
      TopBackTitleBar()
    }
  }
}