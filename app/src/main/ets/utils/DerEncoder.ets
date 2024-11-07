import util from '@ohos.util';

export class DerEncoder {
  private buffer: number[] = [];

  private writeLength(length: number): void {
    if (length < 128) {
      this.buffer.push(length);
    } else {
      let lenBytes: number[] = [];
      while (length > 0) {
        lenBytes.unshift(length & 0xff);
        length >>= 8;
      }
      this.buffer.push(0x80 | lenBytes.length);
      this.buffer.push(...lenBytes);
    }
  }

  private writeType(type: ASN1Type): void {
    this.buffer.push(type);
  }

  encodeInteger(value: number): void {
    const bytes: number[] = [];
    while (value > 0) {
      bytes.unshift(value & 0xff);
      value >>= 8;
    }
    this.writeType(ASN1Type.INTEGER);
    this.writeLength(bytes.length);
    this.buffer.push(...bytes);
  }

  encodeOID(oid: string): void {
    const parts = oid.split('.').map(Number);
    const bytes = [40 * parts[0] + parts[1]];
    for (let i = 2; i < parts.length; i++) {
      let value = parts[i];
      if (value < 128) {
        bytes.push(value);
      } else {
        let encodedValue: number[] = [];
        while (value > 0) {
          encodedValue.unshift((value & 0x7f) | (encodedValue.length ? 0x80 : 0));
          value >>= 7;
        }
        bytes.push(...encodedValue);
      }
    }
    this.writeType(ASN1Type.OBJECT_IDENTIFIER);
    this.writeLength(bytes.length);
    this.buffer.push(...bytes);
  }

  encodePrintableString(str: string): void {
    const bytes = new util.TextEncoder().encodeInto(str);
    this.writeType(ASN1Type.PRINTABLE_STRING);
    this.writeLength(bytes.length);
    this.buffer.push(...bytes);
  }

  encodeBitString(bytes: Uint8Array): void {
    this.writeType(ASN1Type.BIT_STRING);
    this.writeLength(bytes.length + 1);
    this.buffer.push(0); // unused bits
    this.buffer.push(...bytes);
  }

  encodeSequence(fn: () => void): void {
    const oldBuffer = this.buffer;
    this.buffer = [];
    fn();
    const innerBuffer = this.buffer;
    this.buffer = oldBuffer;
    this.writeType(ASN1Type.SEQUENCE);
    this.writeLength(innerBuffer.length);
    this.buffer.push(...innerBuffer);
  }

  encodeSet(fn: () => void): void {
    const oldBuffer = this.buffer;
    this.buffer = [];
    fn();
    const innerBuffer = this.buffer;
    this.buffer = oldBuffer;
    this.writeType(ASN1Type.SET);
    this.writeLength(innerBuffer.length);
    this.buffer.push(...innerBuffer);
  }

  encodeNull(): void {
    this.writeType(ASN1Type.NULL);
    this.writeLength(0);
  }

  getEncoded(): Uint8Array {
    return new Uint8Array(this.buffer);
  }
}

enum ASN1Type {
  SEQUENCE = 0x30,
  SET = 0x31,
  INTEGER = 0x02,
  OBJECT_IDENTIFIER = 0x06,
  PRINTABLE_STRING = 0x13,
  UTF8_STRING = 0x0C,
  BIT_STRING = 0x03,
  NULL = 0x05,
}