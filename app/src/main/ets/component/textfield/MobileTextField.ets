/**
 * 手机号文本框
 *
 * @author hwyz_leo
 */
@Component
export struct MobileTextField {
  @State mobile: string = ""
  onChange?: (value: string) => void

  build() {
    TextInput({ text: this.mobile, placeholder: $r("app.string.input_mobile") })
      .width('100%')
      .height(34)
      .backgroundColor(Color.White)
      .maxLength(13)
      .type(InputType.PhoneNumber)
      .onChange((value: string) => {
        let cleaned = value.replace(/\D/g, '');
        let formatted = '';
        for (let i = 0; i < cleaned.length; i++) {
          if (i === 3 || i === 7) {
            formatted += ' ';
          }
          formatted += cleaned[i];
        }
        this.mobile = formatted
        if (this.onChange) {
          this.onChange(formatted);
        }
      })
  }
}

@Entry
@Component
struct MobileTextFieldPreview {
  build() {
    Column() {
      MobileTextField({mobile: ""})
    }
  }
}