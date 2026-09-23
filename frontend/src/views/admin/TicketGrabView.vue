<template>
  <AppLayout>
    <div class="space-y-6">
      <div class="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <h1 class="text-2xl font-semibold text-gray-900 dark:text-white">{{ t('admin.ticketGrab.title') }}</h1>
          <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">{{ t('admin.ticketGrab.description') }}</p>
        </div>
        <div class="flex items-center gap-2">
          <span
            class="inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium"
            :class="form.enabled ? 'bg-green-50 text-green-700 dark:bg-green-900/30 dark:text-green-300' : 'bg-gray-100 text-gray-500 dark:bg-dark-700 dark:text-gray-400'"
          >
            <span class="h-1.5 w-1.5 rounded-full" :class="form.enabled ? 'bg-green-500' : 'bg-gray-400'"></span>
            {{ form.enabled ? t('admin.ticketGrab.enabled') : '—' }}
          </span>
        </div>
      </div>

      <!-- 设置 -->
      <section class="rounded-lg border border-gray-100 bg-white shadow-sm dark:border-dark-700 dark:bg-dark-800">
        <div class="border-b border-gray-100 px-5 py-4 dark:border-dark-700">
          <h2 class="text-base font-semibold text-gray-900 dark:text-white">{{ t('admin.ticketGrab.settings') }}</h2>
        </div>
        <div class="space-y-5 px-5 py-5">
          <div class="flex items-center justify-between gap-4">
            <div>
              <div class="text-sm font-medium text-gray-700 dark:text-gray-300">{{ t('admin.ticketGrab.enabled') }}</div>
              <div class="mt-0.5 text-xs text-gray-500 dark:text-gray-400">{{ t('admin.ticketGrab.enabledHelp') }}</div>
            </div>
            <Toggle v-model="form.enabled" />
          </div>

          <div class="flex items-center justify-between gap-4">
            <div>
              <div class="text-sm font-medium text-gray-700 dark:text-gray-300">{{ t('admin.ticketGrab.attach') }}</div>
              <div class="mt-0.5 text-xs text-gray-500 dark:text-gray-400">{{ t('admin.ticketGrab.attachHelp') }}</div>
            </div>
            <Toggle v-model="form.attach_to_forward" />
          </div>

          <div>
            <label class="input-label">{{ t('admin.ticketGrab.proxyUrl') }}</label>
            <div class="flex gap-2">
              <input
                v-model.trim="form.proxy_url"
                type="text"
                class="input font-mono text-xs"
                placeholder="socks5h://user:pass@host:port"
              />
              <button
                type="button"
                class="btn btn-secondary flex-shrink-0"
                :disabled="testingProxy || !form.proxy_url"
                @click="doTestProxy"
              >
                {{ testingProxy ? t('admin.ticketGrab.testing') : t('admin.ticketGrab.testProxy') }}
              </button>
            </div>
            <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">{{ t('admin.ticketGrab.proxyUrlHelp') }}</p>
            <div v-if="proxySamples" class="mt-3 rounded-md bg-gray-50 p-3 dark:bg-dark-900/60">
              <div class="mb-2 text-xs font-medium text-gray-600 dark:text-gray-300">{{ t('admin.ticketGrab.testResult') }}</div>
              <div class="grid grid-cols-1 gap-2 sm:grid-cols-3">
                <div
                  v-for="(s, i) in proxySamples"
                  :key="i"
                  class="rounded-md border border-gray-100 bg-white px-3 py-2 text-xs dark:border-dark-700 dark:bg-dark-800"
                >
                  <div class="flex items-center gap-1.5">
                    <span class="h-1.5 w-1.5 rounded-full" :class="s.ok ? 'bg-green-500' : 'bg-red-500'"></span>
                    <span class="font-mono text-gray-800 dark:text-gray-200">{{ s.ip || '—' }}</span>
                    <span v-if="s.colo" class="rounded bg-gray-100 px-1.5 py-0.5 font-mono text-[10px] text-gray-500 dark:bg-dark-700 dark:text-gray-400">{{ s.colo }}</span>
                  </div>
                  <div class="mt-1 text-gray-400">{{ s.latency_ms }}ms</div>
                </div>
              </div>
            </div>
          </div>

          <div class="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
            <div>
              <label class="input-label">{{ t('admin.ticketGrab.model') }}</label>
              <input v-model.trim="form.model" type="text" class="input" />
            </div>
            <div>
              <label class="input-label">{{ t('admin.ticketGrab.leadSeconds') }}</label>
              <input v-model.number="form.lead_seconds" type="number" min="30" class="input" />
              <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">{{ t('admin.ticketGrab.leadSecondsHelp') }}</p>
            </div>
            <div>
              <label class="input-label">{{ t('admin.ticketGrab.ttlSeconds') }}</label>
              <input v-model.number="form.ttl_seconds" type="number" min="60" class="input" />
              <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">{{ t('admin.ticketGrab.ttlSecondsHelp') }}</p>
            </div>
            <div>
              <label class="input-label">{{ t('admin.ticketGrab.minInterval') }}</label>
              <input v-model.number="form.min_interval_seconds" type="number" min="30" class="input" />
              <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">{{ t('admin.ticketGrab.minIntervalHelp') }}</p>
            </div>
            <div>
              <label class="input-label">{{ t('admin.ticketGrab.probeTimeout') }}</label>
              <input v-model.number="form.probe_timeout_seconds" type="number" min="15" max="300" class="input" />
            </div>
            <div>
              <label class="input-label">{{ t('admin.ticketGrab.expectedLength') }}</label>
              <input v-model.number="form.expected_length" type="number" min="1" class="input" />
              <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">{{ t('admin.ticketGrab.expectedLengthHelp') }}</p>
            </div>
            <div>
              <label class="input-label">{{ t('admin.ticketGrab.expectedBlocks') }}</label>
              <input v-model.number="form.expected_blocks" type="number" min="1" class="input" />
            </div>
            <div>
              <label class="input-label">{{ t('admin.ticketGrab.maxProbes') }}</label>
              <input v-model.number="form.max_probes_per_round" type="number" min="1" max="10" class="input" />
              <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">{{ t('admin.ticketGrab.maxProbesHelp') }}</p>
            </div>
          </div>

          <div class="flex justify-end">
            <button type="button" class="btn btn-primary" :disabled="saving" @click="saveSettings">
              {{ saving ? t('admin.ticketGrab.saving') : t('admin.ticketGrab.save') }}
            </button>
          </div>
        </div>
      </section>

      <!-- 账号选择 -->
      <section class="rounded-lg border border-gray-100 bg-white shadow-sm dark:border-dark-700 dark:bg-dark-800">
        <div class="flex flex-wrap items-center justify-between gap-3 border-b border-gray-100 px-5 py-4 dark:border-dark-700">
          <div>
            <h2 class="text-base font-semibold text-gray-900 dark:text-white">{{ t('admin.ticketGrab.accounts') }}</h2>
            <p class="mt-0.5 text-xs text-gray-500 dark:text-gray-400">{{ t('admin.ticketGrab.accountsHelp') }}</p>
          </div>
          <div class="flex items-center gap-3">
            <span class="text-xs text-gray-500 dark:text-gray-400">{{ t('admin.ticketGrab.selectedCount', { count: selectedAccountIds.size }) }}</span>
            <div class="w-56">
              <Select v-model="groupFilter" :options="groupOptions" :placeholder="t('admin.ticketGrab.selectGroup')" />
            </div>
          </div>
        </div>
        <div class="px-5 py-4">
          <div v-if="accountsLoading" class="flex items-center justify-center py-8">
            <div class="h-6 w-6 animate-spin rounded-full border-b-2 border-primary-600"></div>
          </div>
          <div v-else-if="filteredAccounts.length === 0" class="py-8 text-center text-sm text-gray-400">
            {{ groupFilter ? '—' : t('admin.ticketGrab.noAccountsSelected') }}
          </div>
          <div v-else class="grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-3">
            <label
              v-for="acc in filteredAccounts"
              :key="acc.id"
              class="flex cursor-pointer items-center gap-3 rounded-md border px-3 py-2 transition-colors"
              :class="selectedAccountIds.has(acc.id)
                ? 'border-primary-300 bg-primary-50 dark:border-primary-700 dark:bg-primary-900/20'
                : 'border-gray-100 hover:bg-gray-50 dark:border-dark-700 dark:hover:bg-dark-700/50'"
            >
              <input
                type="checkbox"
                class="checkbox"
                :checked="selectedAccountIds.has(acc.id)"
                @change="toggleAccount(acc.id)"
              />
              <div class="min-w-0 flex-1">
                <div class="truncate text-sm font-medium text-gray-800 dark:text-gray-200">{{ acc.name }}</div>
                <div class="mt-0.5 flex items-center gap-2 text-xs text-gray-400">
                  <span>#{{ acc.id }}</span>
                  <span
                    class="inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium"
                    :class="acc.status === 'active' ? 'bg-green-50 text-green-600 dark:bg-green-900/30 dark:text-green-300' : 'bg-gray-100 text-gray-500 dark:bg-dark-700'"
                  >{{ acc.status }}</span>
                  <span v-if="statusById.get(acc.id)?.ticket?.exit_ip" class="font-mono">{{ statusById.get(acc.id)?.ticket?.exit_ip }}</span>
                </div>
              </div>
              <button
                v-if="form.attach_to_forward && selectedAccountIds.has(acc.id)"
                type="button"
                class="flex-shrink-0 rounded px-2 py-1 text-[10px] font-medium transition-colors"
                :class="attachAccountIds.has(acc.id)
                  ? 'bg-indigo-50 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300'
                  : 'bg-gray-100 text-gray-500 hover:bg-gray-200 dark:bg-dark-700 dark:text-gray-400'"
                :title="t('admin.ticketGrab.attachAccountHelp')"
                @click.stop="toggleAttachAccount(acc.id)"
              >
                {{ t('admin.ticketGrab.attachAccount') }}
              </button>
            </label>
          </div>
        </div>
      </section>

      <!-- 状态 -->
      <section class="rounded-lg border border-gray-100 bg-white shadow-sm dark:border-dark-700 dark:bg-dark-800">
        <div class="flex items-center justify-between border-b border-gray-100 px-5 py-4 dark:border-dark-700">
          <h2 class="text-base font-semibold text-gray-900 dark:text-white">{{ t('admin.ticketGrab.status') }}</h2>
          <button type="button" class="btn btn-secondary" :disabled="statusLoading" @click="loadStatus">
            <Icon name="refresh" size="sm" :class="statusLoading ? 'animate-spin' : ''" />
            {{ t('admin.ticketGrab.refresh') }}
          </button>
        </div>
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-gray-200 dark:divide-dark-700">
            <thead class="bg-gray-50 dark:bg-dark-900/60">
              <tr>
                <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500 dark:text-gray-400">{{ t('admin.ticketGrab.account') }}</th>
                <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500 dark:text-gray-400">{{ t('admin.ticketGrab.ticketLength') }}</th>
                <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500 dark:text-gray-400">{{ t('admin.ticketGrab.validUntil') }}</th>
                <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500 dark:text-gray-400">{{ t('admin.ticketGrab.exitIp') }}</th>
                <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500 dark:text-gray-400">{{ t('admin.ticketGrab.lastGrab') }}</th>
                <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500 dark:text-gray-400">
                  <span :title="t('admin.ticketGrab.validRateHelp')">{{ t('admin.ticketGrab.successRate') }} / {{ t('admin.ticketGrab.validRate') }}</span>
                </th>
                <th class="px-4 py-3 text-right text-xs font-medium uppercase tracking-wider text-gray-500 dark:text-gray-400">{{ t('admin.ticketGrab.actions') }}</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-100 dark:divide-dark-700">
              <tr v-if="statuses.length === 0">
                <td colspan="7" class="px-4 py-8 text-center text-sm text-gray-400">{{ t('admin.ticketGrab.noAccountsSelected') }}</td>
              </tr>
              <tr v-for="st in statuses" :key="st.account_id" class="hover:bg-gray-50 dark:hover:bg-dark-700/40">
                <td class="px-4 py-3">
                  <div class="text-sm font-medium text-gray-800 dark:text-gray-200">{{ st.account_name }}</div>
                  <div class="mt-0.5 text-xs text-gray-400">
                    #{{ st.account_id }}
                    <span
                      v-if="st.attach_mode"
                      class="ml-1 rounded bg-indigo-50 px-1.5 py-0.5 text-[10px] font-medium text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300"
                      :title="t('admin.ticketGrab.attachHelp')"
                    >{{ t('admin.ticketGrab.attachBadge') }}</span>
                    <span v-if="st.probing" class="ml-1 inline-flex items-center gap-1 text-primary-600 dark:text-primary-400">
                      <span class="h-1.5 w-1.5 animate-pulse rounded-full bg-primary-500"></span>{{ t('admin.ticketGrab.running') }}
                    </span>
                    <span v-else-if="cooldownActive(st)" class="ml-1 text-amber-600 dark:text-amber-400">{{ t('admin.ticketGrab.cooldown') }}</span>
                  </div>
                </td>
                <td class="px-4 py-3">
                  <template v-if="st.ticket">
                    <span
                      class="rounded px-1.5 py-0.5 font-mono text-xs"
                      :class="st.ticket.state_length === form.expected_length && st.ticket.blocks === form.expected_blocks
                        ? 'bg-green-50 text-green-700 dark:bg-green-900/30 dark:text-green-300'
                        : 'bg-amber-50 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300'"
                    >{{ st.ticket.state_length }} / {{ st.ticket.blocks }}</span>
                    <div class="mt-0.5 font-mono text-[10px] text-gray-400">{{ st.ticket.fingerprint }}</div>
                  </template>
                  <span v-else class="text-xs text-gray-400">{{ t('admin.ticketGrab.noTicket') }}</span>
                </td>
                <td class="px-4 py-3">
                  <div v-if="st.ticket" class="w-28">
                    <div class="h-1.5 overflow-hidden rounded-full bg-gray-100 dark:bg-dark-700">
                      <div
                        class="h-full rounded-full transition-all"
                        :class="remainingPercent(st) > 30 ? 'bg-green-500' : remainingPercent(st) > 10 ? 'bg-amber-500' : 'bg-red-500'"
                        :style="{ width: `${Math.min(100, remainingPercent(st))}%` }"
                      ></div>
                    </div>
                    <div class="mt-1 text-xs text-gray-500 dark:text-gray-400">{{ formatRemaining(st.remaining_seconds) }}</div>
                  </div>
                  <span v-else class="text-xs text-gray-400">{{ t('admin.ticketGrab.noTicket') }}</span>
                </td>
                <td class="px-4 py-3">
                  <div v-if="st.egress_slots?.length" class="flex flex-wrap gap-1">
                    <span
                      v-for="sl in st.egress_slots"
                      :key="sl.index"
                      class="inline-flex items-center gap-1 rounded px-1.5 py-0.5 font-mono text-[10px]"
                      :class="sl.ticket_ok ? 'bg-green-50 text-green-700 dark:bg-green-900/30 dark:text-green-300' : 'bg-amber-50 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300'"
                      :title="`${t('admin.ticketGrab.slotTooltip', { index: sl.index, generation: sl.generation })} · ${sl.busy ? t('admin.ticketGrab.slotBusy') : t('admin.ticketGrab.slotIdle')}`"
                    >
                      <span class="h-1.5 w-1.5 rounded-full" :class="sl.busy ? 'bg-primary-500' : sl.ticket_ok ? 'bg-green-500' : 'bg-amber-500'"></span>
                      #{{ sl.index }} {{ sl.exit_ip || '—' }}<span v-if="sl.exit_colo" class="opacity-60">{{ sl.exit_colo }}</span>
                    </span>
                  </div>
                  <template v-else-if="st.ticket?.exit_ip">
                    <div class="font-mono text-xs text-gray-700 dark:text-gray-300">{{ st.ticket.exit_ip }}</div>
                    <div v-if="st.ticket.exit_colo" class="mt-0.5 text-[10px] text-gray-400">{{ st.ticket.exit_colo }}</div>
                  </template>
                  <span v-else class="text-xs text-gray-400">—</span>
                </td>
                <td class="px-4 py-3">
                  <template v-if="st.last_result">
                    <span class="text-xs" :class="resultClass(st.last_result)">{{ resultLabel(st.last_result) }}</span>
                    <div class="mt-0.5 text-[10px] text-gray-400" :title="st.ticket?.model || undefined">
                      {{ st.ticket ? formatDateTime(st.ticket.updated_at) : '' }}
                    </div>
                  </template>
                  <span v-else class="text-xs text-gray-400">—</span>
                </td>
                <td class="px-4 py-3">
                  <template v-if="st.stats && st.stats.total > 0">
                    <div class="text-xs">
                      <span class="font-medium text-gray-700 dark:text-gray-300">{{ pct(st.stats.success, st.stats.total) }}</span>
                      <span class="text-gray-400"> / </span>
                      <span class="font-medium text-gray-700 dark:text-gray-300">{{ pct(st.stats.valid, st.stats.total) }}</span>
                    </div>
                    <div class="mt-0.5 text-[10px] text-gray-400">{{ st.stats.total }}</div>
                  </template>
                  <span v-else class="text-xs text-gray-400">—</span>
                </td>
                <td class="px-4 py-3 text-right">
                  <button
                    type="button"
                    class="btn btn-secondary px-3 py-1.5 text-xs"
                    :disabled="st.probing || runningId === st.account_id"
                    @click="grabNow(st)"
                  >
                    {{ runningId === st.account_id ? t('admin.ticketGrab.running') : t('admin.ticketGrab.runNow') }}
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <!-- 日志 -->
      <section class="rounded-lg border border-gray-100 bg-white shadow-sm dark:border-dark-700 dark:bg-dark-800">
        <div class="flex flex-wrap items-center justify-between gap-3 border-b border-gray-100 px-5 py-4 dark:border-dark-700">
          <h2 class="text-base font-semibold text-gray-900 dark:text-white">{{ t('admin.ticketGrab.logs') }}</h2>
          <div class="flex items-center gap-2">
            <div class="w-52">
              <Select v-model="logAccountFilter" :options="logAccountOptions" @change="loadLogs" />
            </div>
            <button type="button" class="btn btn-secondary" :disabled="logsLoading" @click="loadLogs">
              <Icon name="refresh" size="sm" :class="logsLoading ? 'animate-spin' : ''" />
              {{ t('admin.ticketGrab.refresh') }}
            </button>
          </div>
        </div>
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-gray-200 dark:divide-dark-700">
            <thead class="bg-gray-50 dark:bg-dark-900/60">
              <tr>
                <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500 dark:text-gray-400">{{ t('admin.ticketGrab.time') }}</th>
                <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500 dark:text-gray-400">{{ t('admin.ticketGrab.account') }}</th>
                <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500 dark:text-gray-400">{{ t('admin.ticketGrab.result') }}</th>
                <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500 dark:text-gray-400">HTTP</th>
                <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500 dark:text-gray-400">{{ t('admin.ticketGrab.ticketLength') }}</th>
                <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500 dark:text-gray-400">{{ t('admin.ticketGrab.exitIp') }}</th>
                <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500 dark:text-gray-400">{{ t('admin.ticketGrab.duration') }}</th>
                <th class="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-gray-500 dark:text-gray-400">{{ t('admin.ticketGrab.detail') }}</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-100 dark:divide-dark-700">
              <tr v-if="logs.length === 0">
                <td colspan="8" class="px-4 py-8 text-center text-sm text-gray-400">—</td>
              </tr>
              <tr v-for="log in logs" :key="log.id" class="hover:bg-gray-50 dark:hover:bg-dark-700/40">
                <td class="whitespace-nowrap px-4 py-2.5 text-xs text-gray-500 dark:text-gray-400">{{ formatDateTime(log.created_at) }}</td>
                <td class="px-4 py-2.5 text-xs text-gray-700 dark:text-gray-300">{{ accountName(log.account_id) }}</td>
                <td class="px-4 py-2.5">
                  <span class="text-xs" :class="resultClass(log.result)">{{ resultLabel(log.result) }}</span>
                </td>
                <td class="px-4 py-2.5 text-xs text-gray-500 dark:text-gray-400">{{ log.http_status || '—' }}</td>
                <td class="px-4 py-2.5 font-mono text-xs text-gray-500 dark:text-gray-400">
                  <template v-if="log.state_length">{{ log.state_length }} / {{ log.blocks }}</template>
                  <template v-else>—</template>
                </td>
                <td class="px-4 py-2.5 font-mono text-xs text-gray-500 dark:text-gray-400">
                  {{ log.exit_ip || '—' }}<span v-if="log.exit_colo" class="ml-1 text-[10px] text-gray-400">{{ log.exit_colo }}</span>
                </td>
                <td class="px-4 py-2.5 text-xs text-gray-500 dark:text-gray-400">{{ log.duration_ms ? `${log.duration_ms}ms` : '—' }}</td>
                <td class="max-w-xs truncate px-4 py-2.5 text-xs text-gray-400" :title="log.detail || undefined">{{ log.detail || '—' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  </AppLayout>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useAppStore } from '@/stores/app'
import { adminAPI } from '@/api/admin'
import type { AccountListItem, AdminGroup } from '@/types'
import type { ProxyTestSample, TicketGrabAccountStatus, TicketGrabLog, TicketGrabSettings } from '@/api/admin/ticketGrab'
import AppLayout from '@/components/layout/AppLayout.vue'
import Select from '@/components/common/Select.vue'
import Toggle from '@/components/common/Toggle.vue'
import Icon from '@/components/icons/Icon.vue'
import { formatDateTime } from '@/utils/format'

const { t } = useI18n()
const appStore = useAppStore()

const defaultSettings = (): TicketGrabSettings => ({
  enabled: false,
  proxy_url: '',
  model: 'gpt-6-astra',
  account_ids: [],
  lead_seconds: 1200,
  ttl_seconds: 3600,
  min_interval_seconds: 180,
  probe_timeout_seconds: 60,
  expected_length: 780,
  expected_blocks: 33,
  max_probes_per_round: 3,
  attach_to_forward: false,
  attach_account_ids: []
})

const form = reactive<TicketGrabSettings>(defaultSettings())
const saving = ref(false)
const testingProxy = ref(false)
const proxySamples = ref<ProxyTestSample[] | null>(null)

// 账号选择
const groups = ref<AdminGroup[]>([])
const accounts = ref<AccountListItem[]>([])
const accountsLoading = ref(false)
const groupFilter = ref<number | ''>('')
const selectedAccountIds = ref(new Set<number>())
// 接入转发（出站走打票出口）的灰度账号
const attachAccountIds = ref(new Set<number>())

// 状态
const statuses = ref<TicketGrabAccountStatus[]>([])
const statusLoading = ref(false)
const runningId = ref<number | null>(null)

// 日志
const logs = ref<TicketGrabLog[]>([])
const logsLoading = ref(false)
const logAccountFilter = ref<number | ''>('')

let statusTimer: ReturnType<typeof setInterval> | null = null

const groupOptions = computed(() => [
  { value: '', label: t('admin.ticketGrab.allGroups') },
  ...groups.value.map((g) => ({ value: g.id, label: g.name }))
])

const filteredAccounts = computed(() => {
  if (groupFilter.value === '') return accounts.value
  const group = groups.value.find((g) => g.id === groupFilter.value)
  if (!group) return accounts.value
  return accounts.value.filter((a) => (a as AccountListItem & { groups?: { name?: string }[] }).groups?.some((g) => g.name === group.name) ?? false)
})

const statusById = computed(() => new Map(statuses.value.map((s) => [s.account_id, s])))

const logAccountOptions = computed(() => [
  { value: '', label: t('admin.ticketGrab.allAccounts') },
  ...statuses.value.map((s) => ({ value: s.account_id, label: s.account_name }))
])

function accountName(accountId: number): string {
  const acc = accounts.value.find((a) => a.id === accountId)
  return acc?.name ?? statusById.value.get(accountId)?.account_name ?? `#${accountId}`
}

function toggleAccount(accountId: number) {
  const next = new Set(selectedAccountIds.value)
  if (next.has(accountId)) {
    next.delete(accountId)
    // 移出打票名单时同步移出接入灰度名单
    const attach = new Set(attachAccountIds.value)
    attach.delete(accountId)
    attachAccountIds.value = attach
  } else {
    next.add(accountId)
  }
  selectedAccountIds.value = next
}

function toggleAttachAccount(accountId: number) {
  const next = new Set(attachAccountIds.value)
  if (next.has(accountId)) {
    next.delete(accountId)
  } else {
    next.add(accountId)
  }
  attachAccountIds.value = next
}

async function loadConfig() {
  try {
    const config = await adminAPI.ticketGrab.getConfig()
    Object.assign(form, defaultSettings(), config)
    selectedAccountIds.value = new Set(form.account_ids ?? [])
    attachAccountIds.value = new Set(form.attach_to_forward ? form.attach_account_ids ?? [] : [])
  } catch (e) {
    appStore.showError(String((e as Error)?.message ?? e))
  }
}

async function saveSettings() {
  saving.value = true
  try {
    const payload: TicketGrabSettings = {
      ...form,
      account_ids: [...selectedAccountIds.value].sort((a, b) => a - b),
      attach_to_forward: form.attach_to_forward,
      attach_account_ids: form.attach_to_forward ? [...attachAccountIds.value].sort((a, b) => a - b) : []
    }
    const saved = await adminAPI.ticketGrab.updateConfig(payload)
    Object.assign(form, saved)
    selectedAccountIds.value = new Set(saved.account_ids ?? [])
    attachAccountIds.value = new Set(saved.attach_to_forward ? saved.attach_account_ids ?? [] : [])
    appStore.showSuccess(t('admin.ticketGrab.save') + ' ✓')
    await loadStatus()
  } catch (e) {
    appStore.showError(String((e as Error)?.message ?? e))
  } finally {
    saving.value = false
  }
}

async function doTestProxy() {
  testingProxy.value = true
  proxySamples.value = null
  try {
    proxySamples.value = await adminAPI.ticketGrab.testProxy(form.proxy_url)
  } catch (e) {
    appStore.showError(String((e as Error)?.message ?? e))
  } finally {
    testingProxy.value = false
  }
}

async function loadGroupsAndAccounts() {
  accountsLoading.value = true
  try {
    const [allGroups, accountPage] = await Promise.all([
      adminAPI.groups.getAll('openai' as never).catch(() => adminAPI.groups.getAll()),
      adminAPI.accounts.list(1, 200, { platform: 'openai', type: 'oauth' })
    ])
    groups.value = allGroups.filter((g) => g.platform === 'openai')
    accounts.value = accountPage.items ?? []
  } catch (e) {
    appStore.showError(String((e as Error)?.message ?? e))
  } finally {
    accountsLoading.value = false
  }
}

async function loadStatus() {
  statusLoading.value = true
  try {
    statuses.value = await adminAPI.ticketGrab.getStatus()
  } catch {
    // 未配置时静默
  } finally {
    statusLoading.value = false
  }
}

async function grabNow(st: TicketGrabAccountStatus) {
  runningId.value = st.account_id
  try {
    await adminAPI.ticketGrab.runNow(st.account_id)
    appStore.showSuccess(`${st.account_name}: ${t('admin.ticketGrab.resultCodes.accepted')}`)
  } catch (e) {
    appStore.showError(`${st.account_name}: ${String((e as Error)?.message ?? e)}`)
  } finally {
    runningId.value = null
    await Promise.allSettled([loadStatus(), loadLogs()])
  }
}

async function loadLogs() {
  logsLoading.value = true
  try {
    logs.value = await adminAPI.ticketGrab.getLogs(
      logAccountFilter.value === '' ? undefined : logAccountFilter.value,
      100
    )
  } catch {
    // 静默
  } finally {
    logsLoading.value = false
  }
}

function cooldownActive(st: TicketGrabAccountStatus): boolean {
  return st.cooldown_unix > 0 && st.cooldown_unix > Math.floor(Date.now() / 1000)
}

function remainingPercent(st: TicketGrabAccountStatus): number {
  if (!st.ticket) return 0
  const total = new Date(st.ticket.expires_at).getTime() - new Date(st.ticket.issued_at).getTime()
  if (total <= 0) return 0
  return Math.max(0, Math.round((st.remaining_seconds * 1000 * 100) / total))
}

function formatRemaining(seconds: number): string {
  if (seconds <= 0) return t('admin.ticketGrab.expired')
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  const s = seconds % 60
  if (h > 0) return `${h}h ${m}m`
  if (m > 0) return `${m}m ${s}s`
  return `${s}s`
}

function pct(part: number, total: number): string {
  return `${Math.round((part / total) * 100)}%`
}

function resultLabel(result: string): string {
  const key = `admin.ticketGrab.resultCodes.${result}`
  const label = t(key)
  return label === key ? result : label
}

function resultClass(result: string): string {
  if (result === 'accepted') return 'text-green-600 dark:text-green-400'
  if (result === 'shape_mismatch') return 'text-amber-600 dark:text-amber-400'
  if (result.startsWith('http_4')) return 'text-red-600 dark:text-red-400'
  return 'text-gray-500 dark:text-gray-400'
}

watch(groupFilter, () => {
  /* 仅影响展示过滤，选中集合不变 */
})

onMounted(async () => {
  await Promise.allSettled([loadConfig(), loadGroupsAndAccounts()])
  await Promise.allSettled([loadStatus(), loadLogs()])
  statusTimer = setInterval(() => {
    loadStatus()
  }, 10000)
})

onUnmounted(() => {
  if (statusTimer) clearInterval(statusTimer)
})
</script>
