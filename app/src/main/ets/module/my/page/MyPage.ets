import { router } from '@kit.ArkUI';
import { UserManager } from '../../../utils/UserManager';
import { MyPageLogin } from './MyPage_Login';
import { MyPageNotLogin } from './MyPage_NotLogin';

/**
 * 我的页面
 *
 * @author hwyz_leo
 */
@Entry
@Component
export struct MyPage {
  @State isLogin: boolean = false

  aboutToAppear(): void {
    const params = router.getParams() as Record<string, boolean>;
    if (params != undefined && params['isLogin'] != undefined) {
      this.isLogin = params['isLogin']
    } else {
      this.isLogin = UserManager.shared.isLogin()
    }
  }

  build() {
    if (this.isLogin) {
      MyPageLogin()
    } else {
      MyPageNotLogin()
    }
  }
}