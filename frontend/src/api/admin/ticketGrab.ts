/**
 * Admin OpenAI Codex 打票（turn-state 采集）API
 */

import { apiClient } from '../client'

/** 打票配置 */
export interface TicketGrabSettings {
  enabled: boolean
  proxy_url: string
  model: string
  account_ids: number[]
  lead_seconds: number
  ttl_seconds: number
  min_interval_seconds: number
  probe_timeout_seconds: number
  expected_length: number
  expected_blocks: number
  max_probes_per_round: number
}

/** 代理测试采样 */
export interface ProxyTestSample {
  ip: string
  colo: string
  latency_ms: number
  ok: boolean
}

/** 当前票据 */
export interface TicketInfo {
  account_id: number
  value: string
  state_length: number
  blocks: number
  issued_at: string
  expires_at: string
  exit_ip: string
  exit_colo: string
  fingerprint: string
  model: string
  plan_type: string
  used_percent: string
  http_status: number
  duration_ms: number
  updated_at: string
}

/** 窗口内统计 */
export interface TicketGrabStats {
  total: number
  success: number
  valid: number
}

/** 单账号状态 */
export interface TicketGrabAccountStatus {
  account_id: number
  account_name: string
  status: string
  ticket?: TicketInfo
  remaining_seconds: number
  next_probe_unix: number
  cooldown_unix: number
  last_result: string
  probing: boolean
  stats?: TicketGrabStats
}

/** 单条打票日志 */
export interface TicketGrabLog {
  id: number
  account_id: number
  result: string
  http_status: number
  state_length: number
  blocks: number
  exit_ip: string
  exit_colo: string
  detail?: string
  duration_ms: number
  created_at: string
}

export async function getConfig(): Promise<TicketGrabSettings> {
  const { data } = await apiClient.get<TicketGrabSettings>('/admin/openai/ticket-grab/config')
  return data
}

export async function updateConfig(settings: TicketGrabSettings): Promise<TicketGrabSettings> {
  const { data } = await apiClient.put<TicketGrabSettings>('/admin/openai/ticket-grab/config', settings)
  return data
}

export async function testProxy(proxyUrl: string): Promise<ProxyTestSample[]> {
  const { data } = await apiClient.post<{ samples: ProxyTestSample[] }>('/admin/openai/ticket-grab/test-proxy', {
    proxy_url: proxyUrl
  })
  return data.samples
}

export async function getStatus(): Promise<TicketGrabAccountStatus[]> {
  const { data } = await apiClient.get<TicketGrabAccountStatus[]>('/admin/openai/ticket-grab/status')
  return data
}

export async function runNow(accountId: number): Promise<void> {
  await apiClient.post('/admin/openai/ticket-grab/run', { account_id: accountId })
}

export async function getLogs(accountId?: number, limit = 50, offset = 0): Promise<TicketGrabLog[]> {
  const params: Record<string, number> = { limit, offset }
  if (accountId && accountId > 0) params.account_id = accountId
  const { data } = await apiClient.get<TicketGrabLog[]>('/admin/openai/ticket-grab/logs', { params })
  return data
}

const ticketGrabAPI = {
  getConfig,
  updateConfig,
  testProxy,
  getStatus,
  runNow,
  getLogs
}

export default ticketGrabAPI
