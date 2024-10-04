import { LoginResponse, TspResponse } from './HttpBean'

export function mockTspResponse(): TspResponse<void> {
  return {
    code: 0,
    ts: 0
  }
}

export function mockTspResponseWithData<T>(data: T): TspResponse<T> {
  return {
    code: 0,
    ts: 0
  }
}

export function mockLoginResponse(): LoginResponse {
  return {
    mobile: "13917288107",
    nickname: "hwyz_leo",
    avatar: "https://pic.imgdb.cn/item/66e667a0d9c307b7e93075e8.png",
    token: "zgZA0dO9gTbhSb6PDBXCb_0mxFq-q33Uo81aNC4hT_hpPvwxJhQASovI0zGlw58K",
    tokenExpires: 1728051104375,
    refreshToken: "rWtoZhVVf6mZW-t1hhqkNazR0r92KkhxDItf05jfQYChT6SrnFi2IXaXD02irjVc",
    refreshTokenExpires: 1728051104375
  }
}