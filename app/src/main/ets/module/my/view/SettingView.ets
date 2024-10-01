import router from '@ohos.router';
import bundleManager from '@ohos.bundle.bundleManager';
import { BusinessError } from '@ohos.base';
import { gAppTheme } from '../../../theme/Theme'
import { TopBackTitleBar } from '../../../widget/TopBackTitleBar'

@Entry
@Component
struct SettingView {
  @State versionName: string = '';
  @State versionCode: number = 0;

  aboutToAppear() {
    this.getAppVersion();
  }

  getAppVersion() {
    try {
      bundleManager.getBundleInfoForSelf(bundleManager.BundleFlag.GET_BUNDLE_INFO_WITH_APPLICATION)
        .then((bundleInfo) => {
          this.versionName = bundleInfo.versionName;
          this.versionCode = bundleInfo.versionCode;
        })
        .catch((err: BusinessError) => {
          console.error(`Failed to get bundle info. Code: ${err.code}, message: ${err.message}`);
        });
    } catch (error) {
      console.error(`Failed to get bundle info. Cause: ${error.message}`);
    }
  }

  build() {
    Column() {
      TopBackTitleBar({
        titleType: "resource",
        titleLocal: $r("app.string.setting"),
        onBackClick: () => router.back()
      })
      Blank().height(20)
      Row() {
        Text($r("app.string.version")).fontColor(gAppTheme.colors?.fontPrimary)
        Blank().layoutWeight(1)
        Text(`${this.versionName}`).fontColor(gAppTheme.colors?.fontSecondary)
      }
    }
    .padding({ left: 20, right: 20 })
  }
}