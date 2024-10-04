// TSP通用返回
export interface TspResponse<T> {
  code: number;
  message?: string;
  ts: number;
  data?: T;
}

// 登录验证码请求
export interface LoginVerifyCodeRequest {
  countryRegionCode: string;
  mobile: string;
}

/**
 * 验证码登录请求
 */
export interface VerifyCodeLoginRequest {
  countryRegionCode: string;
  mobile: string;
  verifyCode: string;
}

/**
 * 登录响应
 */
export interface LoginResponse {
  mobile: string;
  nickname: string;
  avatar?: string;
  token: string;
  tokenExpires: number;
  refreshToken: string;
  refreshTokenExpires: number;
}