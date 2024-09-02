declare namespace NodeJS {
  export interface ProcessEnv {
    DATABASE_URL: string;
    JWT_SECRET: string;
    JWT_SECRET_REFRESH: string;
  }
}
