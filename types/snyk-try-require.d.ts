declare module 'snyk-try-require' {
  export interface Package {
    name: string;
    version: string;
  }
  export default function tryRequire(name: string): Promise<Package>;
}
