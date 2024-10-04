import router from '@ohos.router';
import bundleManager from '@ohos.bundle.bundleManager';
import { BusinessError } from '@ohos.base';
import { gAppTheme } from '../../../theme/Theme';
import { TopBackTitleBar } from '../../../component/bar/TopBackTitleBar';
import { UserManager } from '../../../utils/UserManager';
import { RoundedCornerButton } from '../../../component/button/RoundedCornerButton';
import { GlobalStateManager } from '../../../utils/GlobalStateManager';

@Entry
@Component
struct SettingView {
  @State versionName: string = '';
  @State versionCode: number = 0;
  @State mockCount: number = 0;
  @State showMock: boolean = false
  @State apiUrl: string = ""

  aboutToAppear() {
    this.getAppVersion();
    this.showMock = !GlobalStateManager.isMock
    this.apiUrl = GlobalStateManager.apiUrl.toString()
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
        if (!this.showMock) {
          Text("(Mock)").fontColor(gAppTheme.colors?.fontSecondary)
        }
      }
      .onClick(() => {
        this.mockCount = this.mockCount + 1
        if (GlobalStateManager.isMock && this.mockCount > 10) {
          this.showMock = true
          GlobalStateManager.isMock = false
        }
      })

      if (this.showMock) {
        Blank().height(20)
        Row() {
          TextInput({ text: this.apiUrl })
        }
      }


      if (UserManager.shared.isLogin()) {
        Blank().height(20)
        RoundedCornerButton({
          titleLocal: $r("app.string.logout"),
          bindClick: () => {
            AlertDialog.show({
              title: $r("app.string.tip"),
              message: $r("app.string.confirm_action"),
              autoCancel: true,
              alignment: DialogAlignment.Default,
              offset: { dx: 0, dy: -20 },
              primaryButton: {
                value: $r("app.string.confirm"),
                action: () => {
                  UserManager.shared.logout()
                  router.pushUrl({
                    url: "module/my/page/MyPage",
                    params: {
                      isLogin: false
                    }
                  })
                }
              },
              secondaryButton: {
                value: $r("app.string.cancel"),
                action: () => {
                }
              }
            })
          }
        })
      }
    }
    .padding({ left: 20, right: 20 })
  }
}