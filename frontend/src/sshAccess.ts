import type { ServerForm } from './api'

export type AccessPolicy = Pick<ServerForm, 'ssh_jump_server_id' | 'ssh_source_mode' | 'ssh_source_ips' | 'ssh_firewall_mode'>
export const DEFAULT_ACCESS: AccessPolicy = { ssh_jump_server_id: null, ssh_source_mode: 'panel', ssh_source_ips: [], ssh_firewall_mode: 'add' }
export function accessPolicy(node: AccessPolicy): AccessPolicy {
  return { ...DEFAULT_ACCESS, ...Object.fromEntries(Object.keys(DEFAULT_ACCESS).map(key => [key, node[key as keyof AccessPolicy] ?? DEFAULT_ACCESS[key as keyof AccessPolicy]])) }
}
export function accessChanged(before: AccessPolicy, after: AccessPolicy) {
  return JSON.stringify(accessPolicy(before)) !== JSON.stringify(accessPolicy(after))
}
export type AccessPreview = { token: string; sources: string[]; unrestricted: boolean; firewall: string; actions: string[]; jump_user: string | null }
