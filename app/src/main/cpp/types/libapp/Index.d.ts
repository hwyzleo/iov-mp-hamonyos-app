export const add: (a: number, b: number) => number;
export const generateRSA2048KeyPair: () => string;
export const generateCSR: (privateKey: string, publicKey: string, commonName: string) => string;