import { Constants } from './common/Constants';
import { hilog } from '@kit.PerformanceAnalysisKit';
import { MyPage } from './module/my/page/MyPage';

@Entry
@Component
struct Index {
  @State currentIndex: number = 0;
  private tabsController: TabsController = new TabsController();

  @Builder
  tabBuilder(title: Resource, index: number, selectedImg: Resource, normalImg: Resource) {
    Column() {
      Image(this.currentIndex === index ? selectedImg : normalImg)
        .width($r('app.float.mainPage_baseTab_size'))
        .height($r('app.float.mainPage_baseTab_size'))
        .objectFit(ImageFit.Contain)
      Text(title)
        .margin({ top: $r('app.float.mainPage_baseTab_top') })
        .fontSize($r('app.float.tab_text_font_size'))
        .fontColor(this.currentIndex === index ? $r('app.color.current_color') : $r('app.color.text_color'))
    }
    .justifyContent(FlexAlign.Center)
    .height("$r('app.float.mainPage_barHeight')")
    .width(Constants.FULL_WIDTH)
    .onClick(() => {
      this.currentIndex = index;
      this.tabsController.changeIndex(this.currentIndex);
    })
  }

  @Builder
  tabContentBuilder(text: Resource, index: number, selectedImg: Resource, normalImg: Resource): void {
    TabContent() {
      Flex({ direction: FlexDirection.Column, justifyContent: FlexAlign.Start }) {
        if (index == Constants.TAB_INDEX_FOUR) {
          MyPage()
        } else {
          Row() {
            Text(index.toString())
              .height(Constants.CONTENT_HEIGHT)
              .fontSize($r('app.float.content_font_size'))
          }
          .width(Constants.FULL_WIDTH)
          .justifyContent(FlexAlign.Center)
        }
      }
      .width('100%')
      .height('100%')
      .flexGrow(1)
    }
    .padding({ left: $r('app.float.padding_bottom_tab'), right: $r('app.float.padding_bottom_tab') })
    .backgroundColor(Color.White)
    .tabBar(this.tabBuilder(text, index, selectedImg, normalImg))
  }

  build() {
    Tabs({
      barPosition: BarPosition.End,
      controller: this.tabsController
    }) {
      this.tabContentBuilder($r('app.string.explore'),
        Constants.TAB_INDEX_ZERO, $r('app.media.icon_explore_fill'), $r('app.media.icon_explore'))
      this.tabContentBuilder($r('app.string.service'),
        Constants.TAB_INDEX_ONE, $r('app.media.icon_service_fill'), $r('app.media.icon_service'))
      this.tabContentBuilder($r('app.string.vehicle'),
        Constants.TAB_INDEX_TWO, $r('app.media.icon_vehicle_fill'), $r('app.media.icon_vehicle'))
      this.tabContentBuilder($r('app.string.mall'),
        Constants.TAB_INDEX_THREE, $r('app.media.icon_mall_fill'), $r('app.media.icon_mall'))
      this.tabContentBuilder($r('app.string.my'),
        Constants.TAB_INDEX_FOUR, $r('app.media.icon_person_fill'), $r('app.media.icon_person'))
    }
    .width(Constants.FULL_WIDTH)
    .backgroundColor($r('app.color.tab_color'))
    .barHeight($r('app.float.mainPage_barHeight'))
    .barMode(BarMode.Fixed)
    .onAnimationStart((index: number, targetIndex: number) => {
      hilog.info(0x0000, 'index', index.toString());
      this.currentIndex = targetIndex;
    })
  }
}
