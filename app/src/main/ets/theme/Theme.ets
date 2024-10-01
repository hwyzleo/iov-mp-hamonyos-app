import {CustomTheme, CustomColors} from '@kit.ArkUI'

/**
 * 自定义应用颜色集
 */
export class AppColors implements CustomColors {
  fontPrimary: ResourceColor = $r("app.color.font_primary")
  fontSecondary: ResourceColor = $r("app.color.font_secondary")
}

/**
 * 自定义应用主题
 */
export class AppTheme implements CustomTheme {
  public colors: AppColors = new AppColors()
}

export let gAppTheme: CustomTheme = new AppTheme()