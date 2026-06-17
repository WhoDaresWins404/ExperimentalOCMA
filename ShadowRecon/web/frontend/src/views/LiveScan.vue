<template>
  <div class="live-scan">
    <button class="back-btn" @click="goBack">&larr; Back</button>
    <h1>Live Scan</h1>

    <div class="status-bar">
      <span :class="'status-indicator ' + statusClass"></span>
      <span><strong>{{ statusLabel }}</strong></span>
      <span v-if="wsError" class="ws-error">WebSocket disconnected — polling for updates</span>
    </div>

    <div v-if="!scanStarted" class="waiting-state">
      <div class="spinner"></div>
      <h2>Starting scan...</h2>
      <p>Initializing scan session. The scan will begin shortly.</p>
      <p class="session-id">Session: {{ sessionId }}</p>
    </div>

    <div v-else-if="scanStatus === 'completed'" class="completed-banner">
      Scan complete! <a :href="`/#/report/${sessionId}`">View Report</a> &middot;
      <a :href="`/#/map/${sessionId}`">View Map</a>
    </div>

    <div v-else-if="scanStatus === 'failed'" class="failed-banner">
      Scan failed. Check the server logs for details.
    </div>

    <div v-else class="scan-grid">
      <div class="stats-panel">
        <h3>Progress</h3>
        <div class="stat-row"><span class="stat-label">Status:</span><span class="stat-value">{{ statusLabel }}</span></div>
        <div class="stat-row"><span class="stat-label">Findings:</span><span class="stat-value">{{ findings.length }}</span></div>
        <div class="stat-row"><span class="stat-label">Endpoints:</span><span class="stat-value">{{ endpoints.length }}</span></div>
        <div class="stat-row"><span class="stat-label">WebSocket:</span><span class="stat-value" :style="{color: connected ? '#00e5ff' : '#ff1744'}">{{ connected ? 'Connected' : 'Disconnected' }}</span></div>
      </div>

      <div class="findings-panel">
        <h3>Live Findings</h3>
        <FindingsFeed :findings="findings" />
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useScanStore } from '../store/scanStore'
import FindingsFeed from '../components/FindingsFeed.vue'

const props = defineProps({ id: String })
const route = useRoute()
const router = useRouter()
const store = useScanStore()
const sessionId = props.id || route.params.id
const wsError = ref(false)
const pollAttempts = ref(0)
let pollTimer = null

const scanStatus = computed(() => store.scanStatus)
const findings = computed(() => store.findings)
const endpoints = computed(() => store.endpoints)
const connected = computed(() => store.connected)
const scanStarted = computed(() => store.scanStatus !== 'idle' && store.scanStatus !== 'pending')

const statusLabel = computed(() => {
  const labels = {
    idle: 'Waiting...', pending: 'Pending', waf_check: 'Checking WAF',
    scanning: 'Scanning...', dedup: 'Deduplicating findings',
    llm_enrich: 'LLM enrichment', generating_report: 'Generating report',
    completed: 'Completed', cancelled: 'Cancelled', failed: 'Failed',
  }
  return labels[scanStatus.value] || scanStatus.value
})

const statusClass = computed(() => {
  const map = {
    scanning: 'scanning', completed: 'completed', failed: 'error',
    cancelled: 'cancelled', waf_check: 'scanning', dedup: 'scanning',
    llm_enrich: 'scanning', generating_report: 'scanning',
  }
  return map[scanStatus.value] || 'idle'
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
        for (const f of data.findings) {
          if (!existingIds.has(f.id)) {
            store.findings.push(f)
          }
        }
      }
      if (data && data.endpoints && data.endpoints.length) {
        const existingIds = new Set(store.endpoints.map(e => e.id))
        for (const ep of data.endpoints) {
          if (!existingIds.has(ep.id)) {
            store.endpoints.push(ep)
          }
        }
      }
    }
    pollAttempts.value++
    wsError.value = false
  } catch (e) {
    wsError.value = true
  }
}

function goBack() {
  store.reset()
  router.push('/dashboard')
}
</script>

<style scoped>
.live-scan { padding: 20px 0; }
.back-btn { background: none; border: 1px solid #1e3a5f; color: #8899aa; padding: 8px 16px; border-radius: 5px; cursor: pointer; margin-bottom: 20px; }
.back-btn:hover { color: #00e5ff; border-color: #00e5ff; }
h1 { color: #00e5ff; margin-bottom: 20px; }
.status-bar {
  background: #111927; border: 1px solid #1e3a5f; border-radius: 8px;
  padding: 15px 20px; margin-bottom: 20px; display: flex;
  align-items: center; gap: 10px; color: #8899aa;
}
.status-indicator { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }
.status-indicator.scanning { background: #ffd600; animation: pulse 1s infinite; }
.status-indicator.completed { background: #00e5ff; }
.status-indicator.error { background: #ff1744; }
.status-indicator.cancelled { background: #8899aa; }
.status-indicator.idle { background: #556677; }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
.ws-error { color: #ff9100; font-size: 0.85em; margin-left: auto; }
.waiting-state {
  display: flex; flex-direction: column; align-items: center;
  justify-content: center; padding: 80px 20px; color: #8899aa;
  text-align: center;
}
.spinner {
  width: 40px; height: 40px; border: 3px solid #1e3a5f;
  border-top-color: #00e5ff; border-radius: 50%;
  animation: spin 0.8s linear infinite; margin-bottom: 20px;
}
@keyframes spin { to { transform: rotate(360deg); } }
.waiting-state h2 { color: #e0e0e0; margin-bottom: 10px; }
.session-id { font-size: 0.8em; color: #556677; margin-top: 10px; font-family: monospace; }
.completed-banner {
  background: #0f3a1e; border: 1px solid #00e5ff; border-radius: 8px;
  padding: 15px 20px; color: #00e5ff; margin-bottom: 20px;
}
.completed-banner a { color: #00e5ff; text-decoration: underline; }
.failed-banner {
  background: #3a0f0f; border: 1px solid #ff1744; border-radius: 8px;
  padding: 15px 20px; color: #ff1744; margin-bottom: 20px;
}
.scan-grid { display: grid; grid-template-columns: 300px 1fr; gap: 20px; }
.stats-panel { background: #111927; border: 1px solid #1e3a5f; border-radius: 8px; padding: 20px; height: fit-content; }
.stats-panel h3 { color: #00e5ff; margin-bottom: 15px; }
.stat-row { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #0f1a2e; }
.stat-label { color: #8899aa; }
.stat-value { color: #e0e0e0; font-weight: bold; }
.findings-panel { background: #111927; border: 1px solid #1e3a5f; border-radius: 8px; padding: 20px; }
.findings-panel h3 { color: #00e5ff; margin-bottom: 15px; }
</style>
