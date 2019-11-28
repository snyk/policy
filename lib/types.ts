import { AddOptions } from './add';

export type PolicyTypeName = 'ignore' | 'patch';

export interface SubPolicy {
  [id: string]: unknown[];
}

export interface Policy {
  ignore: SubPolicy;
  patch: SubPolicy;
  version: unknown;
  suggest?: boolean;
  skipVerifyPatch?: boolean;
  failThreshold?: string;
}

export interface LoadedPolicy extends Policy {
  __filename: string;
  __modified: number;
  __created: number;
}

export interface MethodsPolicy extends LoadedPolicy {
  filter(vulns, root): unknown;
  save(...args: any[]): unknown;
  demunge(...args: any[]): unknown;
  add(type: PolicyTypeName, options: AddOptions): MethodsPolicy;
  addIgnore(options: AddOptions): MethodsPolicy;
  addPatch(options: AddOptions): MethodsPolicy;
}

type Package = string;

export interface Vuln {
  id: string;
  from: Package[];
  isUpgradable: boolean;
  isPatchable: boolean;
  upgradePath: unknown[];
  patches: unknown[];
  __filename: string;
  severity: string;

  // added by us?
  filtered?: unknown;
  note?: string;
}
