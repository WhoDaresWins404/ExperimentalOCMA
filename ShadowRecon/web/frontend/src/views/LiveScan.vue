<template>
  <div class="py-5">
    <button @click="goBack"
      class="bg-transparent border border-cyber-border text-cyber-muted px-4 py-2 rounded cursor-pointer mb-5 hover:text-cyber-accent hover:border-cyber-accent transition-colors">
      &larr; Back
    </button>
    <h1 class="text-cyber-accent text-2xl font-bold mb-5">Live Scan</h1>

    <div class="bg-cyber-surface border border-cyber-border rounded-lg p-4 mb-5 flex items-center gap-3 flex-wrap">
      <span class="w-2.5 h-2.5 rounded-full" :class="statusDotClass"></span>
      <span class="text-cyber-text font-bold text-sm">{{ statusLabel }}</span>
      <span v-if="wsError" class="text-cyber-warning text-xs ml-auto">WebSocket disconnected — polling for updates</span>
    </div>

    <div v-if="!scanStarted" class="flex flex-col items-center justify-center py-20 text-cyber-muted text-center">
      <div class="w-10 h-10 border-3 border-cyber-border border-t-cyber-accent rounded-full animate-spin mb-5"></div>
      <h2 class="text-cyber-text text-lg mb-2">Starting scan...</h2>
      <p>Initializing scan session. The scan will begin shortly.</p>
      <p class="text-cyber-muted-2 text-xs font-mono mt-2.5">Session: {{ sessionId }}</p>
    </div>

    <div v-else-if="scanStatus === 'completed'"
      class="bg-green-900 border border-cyber-accent rounded-lg p-4 text-cyber-accent mb-5 flex items-center gap-3 flex-wrap">
      Scan complete!
      <a :href="`/#/report/${sessionId}`" class="text-cyber-accent underline">View Report</a> &middot;
      <a :href="`/#/map/${sessionId}`" class="text-cyber-accent underline">View Map</a>
    </div>

    <div v-else-if="scanStatus === 'cancelled'"
      class="bg-yellow-900 border border-cyber-warning rounded-lg p-4 text-cyber-warning mb-5 flex items-center gap-3 flex-wrap">
      Scan cancelled — {{ store.cancelReason || 'User requested' }}
      <button @click="resumeScan" :disabled="resuming"
        class="ml-auto bg-cyber-surface border border-cyber-warning text-cyber-warning px-3 py-1.5 rounded text-xs cursor-pointer hover:bg-cyber-warning hover:text-black transition-colors disabled:opacity-50">
        {{ resuming ? 'Resuming...' : 'Resume Scan' }}
      </button>
      <span class="text-cyber-muted text-xs w-full">Partial results are available</span>
    </div>

    <div v-else-if="scanStatus === 'failed'"
      class="bg-red-900 border border-cyber-danger rounded-lg p-4 text-cyber-danger mb-5">
      Scan failed. Check the server logs for details.
    </div>

    <div v-else class="grid grid-cols-[300px_1fr] gap-5">
      <div class="bg-cyber-surface border border-cyber-border rounded-lg p-5 h-fit">
        <h3 class="text-cyber-accent font-bold mb-4">Progress</h3>
        <div class="space-y-2">
          <div class="flex justify-between items-center py-2 border-b border-cyber-surface-2">
            <span class="text-cyber-muted">Status:</span>
            <span class="text-cyber-text font-bold text-sm">{{ statusLabel }}</span>
          </div>
          <div class="flex justify-between items-center py-2 border-b border-cyber-surface-2">
            <span class="text-cyber-muted">Findings:</span>
            <span class="text-cyber-text font-bold">{{ findings.length }}</span>
          </div>
          <div class="flex justify-between items-center py-2 border-b border-cyber-surface-2">
            <span class="text-cyber-muted">Endpoints:</span>
            <span class="text-cyber-text font-bold">{{ endpoints.length }}</span>
          </div>
          <div class="flex justify-between items-center py-2 border-b border-cyber-surface-2">
            <span class="text-cyber-muted">HTTP Exchanges:</span>
            <span class="text-cyber-text font-bold">{{ httpExchanges.length }}</span>
          </div>
          <div class="flex justify-between items-center py-2">
            <span class="text-cyber-muted">WebSocket:</span>
            <span :class="connected ? 'text-cyber-accent' : 'text-cyber-danger'" class="font-bold text-sm">{{ connected ? 'Connected' : 'Disconnected' }}</span>
          </div>
          <button @click="showAbortModal = true" :disabled="aborting"
            class="w-full mt-4 bg-red-900 border border-cyber-danger text-cyber-danger px-4 py-2 rounded text-sm cursor-pointer hover:bg-red-800 hover:text-red-300 transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
            {{ aborting ? 'Aborting...' : 'Abort Scan' }}
          </button>
        </div>
      </div>

      <div class="bg-cyber-surface border border-cyber-border rounded-lg p-5">
        <div class="flex gap-1 border-b border-cyber-border mb-4">
          <button v-for="tab in tabs" :key="tab.key" @click="activeTab = tab.key"
            class="px-4 py-2 text-sm cursor-pointer transition-colors border-b-2 -mb-[1px]"
            :class="activeTab === tab.key ? 'text-cyber-accent border-cyber-accent' : 'text-cyber-muted border-transparent hover:text-cyber-text hover:border-cyber-muted-2'">
            {{ tab.label }}
          </button>
        </div>
        <div v-if="activeTab === 'findings'">
          <FindingsFeed :findings="findings" />
        </div>
        <div v-else-if="activeTab === 'http'">
          <HttpExchangeFeed :exchanges="httpExchanges" @select="selectExchange" />
        </div>
        <div v-else-if="activeTab === 'endpoints'">
          <div v-if="endpoints.length === 0" class="text-cyber-muted-2 text-center py-5">No endpoints discovered yet.</div>
          <div v-for="ep in endpoints" :key="ep.id" class="bg-cyber-surface-2 rounded-lg p-3 mb-2 border-l-4 border-cyber-border">
            <div class="text-cyber-muted text-xs">{{ ep.source || 'discovered' }}</div>
            <div class="text-cyber-text text-sm font-mono break-all">{{ ep.url }}</div>
            <div v-if="ep.response_code" class="text-xs font-mono mt-1"
              :class="ep.response_code < 300 ? 'text-cyber-accent' : ep.response_code < 400 ? 'text-cyber-medium' : 'text-cyber-warning'">
              {{ ep.response_code }}
            </div>
          </div>
        </div>
      </div>
    </div>
    <HttpExchangeDetail v-if="selectedExchangeData" :data="selectedExchangeData" @close="selectedExchangeData = null" />
    <!-- Abort confirmation modal -->
    <div v-if="showAbortModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div class="bg-cyber-surface border border-cyber-border rounded-lg p-6 w-full max-w-md mx-4">
        <h3 class="text-cyber-accent font-bold text-lg mb-4">Abort Scan?</h3>
        <p class="text-cyber-muted text-sm mb-4">Partial results will be saved. Choose a reason:</p>
        <div class="space-y-2 mb-4">
          <label v-for="opt in abortReasons" :key="opt.value"
            class="flex items-center gap-2 px-3 py-2 rounded border cursor-pointer text-sm transition-colors"
            :class="abortReason === opt.value ? 'border-cyber-accent bg-cyber-accent/10 text-cyber-accent' : 'border-cyber-border bg-cyber-bg text-cyber-muted hover:border-cyber-accent/40'">
            <input type="radio" :value="opt.value" v-model="abortReason" class="accent-cyber-accent" />
            {{ opt.label }}
          </label>
          <div v-if="abortReason === 'other'" class="pl-6">
            <textarea v-model="abortReasonCustom" placeholder="Describe why..."
              class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3 py-2 rounded text-sm outline-none focus:border-cyber-accent transition-colors resize-none" rows="2"></textarea>
          </div>
        </div>
        <div class="flex gap-3 justify-end">
          <button @click="showAbortModal = false"
            class="bg-cyber-bg border border-cyber-border text-cyber-text px-4 py-2 rounded text-sm cursor-pointer hover:bg-cyber-surface transition-colors">Cancel</button>
          <button @click="confirmAbort" :disabled="abortSubmitting"
            class="bg-red-900 border border-cyber-danger text-cyber-danger px-4 py-2 rounded text-sm cursor-pointer hover:bg-red-800 hover:text-red-300 transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
            {{ abortSubmitting ? 'Aborting...' : 'Confirm Abort' }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useScanStore } from '../store/scanStore'
import FindingsFeed from '../components/FindingsFeed.vue'
import HttpExchangeFeed from '../components/HttpExchangeFeed.vue'
import HttpExchangeDetail from '../components/HttpExchangeDetail.vue'

const props = defineProps({ id: String })
const route = useRoute()
const router = useRouter()
const store = useScanStore()
const sessionId = props.id || route.params.id
const wsError = ref(false)
const pollAttempts = ref(0)
const showAbortModal = ref(false)
const aborting = ref(false)
const abortSubmitting = ref(false)
const resuming = ref(false)
const abortReason = ref('user_requested')
const abortReasonCustom = ref('')
const activeTab = ref('findings')
const selectedExchangeData = ref(null)
const tabs = [
  { key: 'findings', label: 'Findings' },
  { key: 'http', label: 'HTTP' },
  { key: 'endpoints', label: 'Endpoints' },
]
const abortReasons = [
  { value: 'user_requested', label: 'User requested' },
  { value: 'taking_too_long', label: 'Taking too long' },
  { value: 'false_positives', label: 'False positives detected' },
  { value: 'target_changed', label: 'Target changed' },
  { value: 'other', label: 'Other' },
]
let pollTimer = null

const scanStatus = computed(() => store.scanStatus)
const findings = computed(() => store.findings)
const endpoints = computed(() => store.endpoints)
const httpExchanges = computed(() => store.httpExchanges)
const connected = computed(() => store.connected)
const scanStarted = computed(() => store.scanStatus !== 'idle' && store.scanStatus !== 'pending')

const statusLabel = computed(() => {
  const labels = {
    idle: 'Waiting...', pending: 'Pending', waf_check: 'Checking WAF',
    reconnaissance: 'Analyzing tech stack', strategize: 'Planning scan strategy',
    scanning: 'Scanning...', adaptive_scan: 'Scanning (adaptive)...',
    dedup: 'Deduplicating findings', llm_enrich: 'LLM enrichment',
    generating_report: 'Generating report', completed: 'Completed',
    cancelled: 'Cancelled', failed: 'Failed',
  }
  return labels[scanStatus.value] || scanStatus.value
})

const statusDotClass = computed(() => {
  const map = {
    scanning: 'bg-yellow-400 animate-pulse-dot', adaptive_scan: 'bg-yellow-400 animate-pulse-dot',
    reconnaissance: 'bg-yellow-400 animate-pulse-dot', strategize: 'bg-yellow-400 animate-pulse-dot',
    waf_check: 'bg-yellow-400 animate-pulse-dot', dedup: 'bg-yellow-400 animate-pulse-dot',
    llm_enrich: 'bg-yellow-400 animate-pulse-dot', generating_report: 'bg-yellow-400 animate-pulse-dot',
    completed: 'bg-cyber-accent', failed: 'bg-cyber-danger', cancelled: 'bg-cyber-muted',
  }
  return map[scanStatus.value] || 'bg-cyber-muted-2'
})

watch(activeTab, (tab) => {
  if (tab === 'http' && sessionId) {
    store.fetchExchanges(sessionId)
  }
})

onMounted(() => {
  store.reset()
  store.connectWebSocket(sessionId)
  startPolling()
})

onUnmounted(() => {
  store.disconnectWebSocket()
  if (pollTimer) clearInterval(pollTimer)
})

function startPolling() {
  pollOnce()
  pollTimer = setInterval(pollOnce, 3000)
}

async function selectExchange(exchangeId) {
  try {
    const data = await store.fetchRawResponse(sessionId, exchangeId)
    selectedExchangeData.value = data
  } catch (e) {
    console.error('Failed to load exchange detail:', e)
  }
}

async function pollOnce() {
  try {
    const status = await store.getScanStatus(sessionId)
    if (status && status.status) {
      store.scanStatus = status.status
      if (['completed', 'failed', 'cancelled'].includes(status.status)) {
        if (pollTimer) clearInterval(pollTimer)
      }
    }
    if (store.scanStatus && store.scanStatus !== 'idle' && store.scanStatus !== 'pending') {
      const data = await store.getScanResults(sessionId)
      if (data && data.findings && data.findings.length) {
        const existingIds = new Set(store.findings.map(f => f.id))
        for (const f of data.findings) { if (!existingIds.has(f.id)) store.findings.push(f) }
      }
      if (data && data.endpoints && data.endpoints.length) {
        const existingIds = new Set(store.endpoints.map(e => e.id))
        for (const ep of data.endpoints) { if (!existingIds.has(ep.id)) store.endpoints.push(ep) }
      }
      if (activeTab.value === 'http') {
        await store.fetchExchanges(sessionId)
      }
    }
    pollAttempts.value++
    wsError.value = false
  } catch (e) { wsError.value = true }
}

function goBack() { showAbortModal.value = false; store.reset(); router.push('/dashboard') }

async function confirmAbort() {
  abortSubmitting.value = true
  aborting.value = true
  try {
    const reason = abortReason.value === 'other' ? abortReasonCustom.value || 'other' : abortReason.value
    await store.cancelScan(sessionId, reason)
    showAbortModal.value = false
  } catch (e) {
    console.error('Abort failed:', e)
  } finally {
    abortSubmitting.value = false
  }
}

async function resumeScan() {
  resuming.value = true
  try {
    const data = await store.getScanResults(sessionId)
    const targetUrl = data?.session?.target || sessionId
    const params = {
      url: targetUrl,
      campaign_name: 'default',
      continue_from: sessionId,
    }
    const result = await store.startScan(params)
    if (result && result.session_id) {
      store.reset()
      router.push(`/scan/${result.session_id}`)
    }
  } catch (e) {
    console.error('Resume failed:', e)
  } finally {
    resuming.value = false
  }
}
</script>
