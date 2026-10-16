declare module 'qrcode-svg' {
  interface Options {
    content: string;
    padding?: number;
    width?: number;
    height?: number;
    ecl?: 'L' | 'M' | 'Q' | 'H';
    join?: boolean;
    container?: 'svg' | 'svg-viewbox' | 'g' | 'none';
  }
  export default class QRCode {
    constructor(options: Options);
    svg(): string;
  }
}
