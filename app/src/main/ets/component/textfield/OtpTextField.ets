import { BusinessError } from '@kit.BasicServicesKit';
import { inputMethod } from '@kit.IMEKit';

@Extend(Text)
function verifyCodeUnitStyle() {
  .fontSize('16fp')
  .fontWeight(FontWeight.Bold)
  .textAlign(TextAlign.Center)
  .width('50vp')
  .aspectRatio(1)
  .margin({
    left: '5vp',
    right: '5vp'
  })
  .borderRadius('10vp')
}

@Component
export struct OtpTextField {
  @State codeText: string = '';
  private inputController: inputMethod.InputMethodController = inputMethod.getController();
  private arrArea: number[] = [0.0, 1, 0];
  private verifyCodeLength: number = 6;
  private codeIndexArray: Array<number> = Array.from([0, 1, 2, 3, 4, 5]);
  private textConfig: inputMethod.TextConfig = {
    inputAttribute: {
      textInputType: inputMethod.TextInputType.NUMBER,
      enterKeyType: inputMethod.EnterKeyType.GO
    }
  };
  onFinish?: (value: string) => void

  aboutToDisappear(): void {
    this.detach();
  }

  async attach() {
    await this.inputController.attach(true, this.textConfig);
  }

  listen() {
    this.inputController.on('insertText', (text: string) => {
      if (this.codeText.length >= this.verifyCodeLength || isNaN(Number(text)) || text === ' ') {
        return;
      }
      this.codeText += text;
      if (this.codeText.length == this.verifyCodeLength) {
        if (this.onFinish) {
          this.onFinish(this.codeText);
        }
      }
    })
    this.inputController.on('deleteLeft', () => {
      this.codeText = this.codeText.substring(0, this.codeText.length - 1);
    })
  }

  detach(): void {
    this.inputController.off('insertText');
    this.inputController.off('deleteLeft');
    this.inputController.detach((_err: BusinessError) => {
    });
  }

  @Builder
  buildVerifyCodeComponent() {
    Flex({ direction: FlexDirection.Row, alignItems: ItemAlign.Center, justifyContent: FlexAlign.SpaceBetween }) {
      ForEach(this.codeIndexArray, (item: number) => {
        Text(this.codeText[item])
          .verifyCodeUnitStyle()
          .backgroundColor(this.codeText[item] === undefined ? '#FFF1F3F5' :
            '#330a59f7')
      }, (item: number) => JSON.stringify(item))
    }
    .onVisibleAreaChange(this.arrArea, async (isVisible: boolean, currentRatio: number) => {
      if (isVisible && currentRatio >= 1.0) {
        await this.attach();
        this.listen();
      }
      if (!isVisible && currentRatio <= 0.0) {
        this.detach();
      }
    })
    .backgroundColor(Color.Transparent)
    .height('50vp')
    .defaultFocus(true)
    .onClick(() => {
      this.attach();
    })
  }

  build() {
    Column() {
      this.buildVerifyCodeComponent()
    }
    .height('100%')
    .width('100%')
  }
}

@Builder
export function getColorChange(name: string): void {
  if (name === 'BackgroundColorChange') {
    NavDestination() {
      OtpTextField()
    }
  }
}

export const wrappedBuilderColorChange: WrappedBuilder<[string, number]> = wrapBuilder(getColorChange);

@Entry
@Component
struct OtpTextFieldPreview {
  build() {
    Column() {
      OtpTextField()
    }
  }
}