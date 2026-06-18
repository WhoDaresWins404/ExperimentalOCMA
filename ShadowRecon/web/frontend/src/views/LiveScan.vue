<template>
  <div class="live-scan">
    <Button icon="pi pi-arrow-left" label="Back" severity="secondary" text @click="goBack" class="back-btn" />
    <h1>Live Scan</h1>

    <Card class="status-bar">
      <template #content>
        <div class="status-bar-inner">
          <Tag :severity="statusSeverity" :value="statusLabel" />
          <Message v-if="wsError" severity="warn" :closable="false">WebSocket disconnected — polling for updates</Message>
        </div>
      </template>
    </Card>

    <div v-if="!scanStarted" class="waiting-state">
      <ProgressSpinner />
      <h2>Starting scan...</h2>
      <p>Initializing scan session. The scan will begin shortly.</p>
      <p class="session-id">Session: {{ sessionId }}</p>
    </div>

    <Message v-else-if="scanStatus === 'completed'" severity="success" :closable="false">
      Scan complete!
      <Button label="View Report" severity="success" size="small" @click="$router.push(`/report/${sessionId}`)" />
      <Button label="View Map" severity="success" size="small" @click="$router.push(`/map/${sessionId}`)" />
    </Message>

    <Message v-else-if="scanStatus === 'failed'" severity="error" :closable="false">
      Scan failed. Check the server logs for details.
    </Message>

    <div v-else class="scan-grid">
      <Card class="stats-panel">
        <template #title>Progress</template>
        <template #content>
          <div class="stat-row"><span class="stat-label">Status:</span><Tag :severity="statusSeverity" :value="statusLabel" /></div>
          <div class="stat-row"><span class="stat-label">Findings:</span><span class="stat-value">{{ findings.length }}</span></div>
          <div class="stat-row"><span class="stat-label">Endpoints:</span><span class="stat-value">{{ endpoints.length }}</span></div>
          <div class="stat-row">
            <span class="stat-label">WebSocket:</span>
            <Tag :severity="connected ? 'success' : 'danger'" :value="connected ? 'Connected' : 'Disconnected'" />
          </div>
        </template>
      </Card>

      <Card class="findings-panel">
        <template #title>Live Findings</template>
        <template #content>
          <FindingsFeed :findings="findings" />
        </template>
      </Card>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useScanStore } from '../store/scanStore'
import Button from 'primevue/button'
import Card from 'primevue/card'
import Tag from 'primevue/tag'
import Message from 'primevue/message'
import ProgressSpinner from 'primevue/progressspinner'
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
    reconnaissance: 'Analyzing tech stack',
    strategize: 'Planning scan strategy',
    scanning: 'Scanning...',
    adaptive_scan: 'Scanning (adaptive)...',
    dedup: 'Deduplicating findings',
    llm_enrich: 'LLM enrichment', generating_report: 'Generating report',
    completed: 'Completed', cancelled: 'Cancelled', failed: 'Failed',
  }
  return labels[scanStatus.value] || scanStatus.value
})

const statusSeverity = computed(() => {
  const map = {
    scanning: 'warn', adaptive_scan: 'warn',
    reconnaissance: 'info', strategize: 'info',
    waf_check: 'info', dedup: 'info',
    llm_enrich: 'info', generating_report: 'info',
    completed: 'success', failed: 'danger', cancelled: 'secondary',
  }
  return map[scanStatus.value] || 'info'
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
.live-scan { padding: 1.25rem 0; }
.back-btn { margin-bottom: 1.25rem; }
h1 { color: var(--p-primary-color); margin-bottom: 1.25rem; }
.status-bar { margin-bottom: 1.25rem; }
.status-bar-inner { display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; }
.waiting-state {
  display: flex; flex-direction: column; align-items: center;
  justify-content: center; padding: 5rem 1.25rem; color: var(--p-surface-300);
  text-align: center;
}
.waiting-state h2 { color: var(--p-surface-100); margin: 1rem 0 0.5rem; }
.session-id { font-size: 0.8rem; color: var(--p-surface-400); margin-top: 0.625rem; font-family: monospace; }
.scan-grid { display: grid; grid-template-columns: 300px 1fr; gap: 1.25rem; }
.stats-panel { height: fit-content; }
.stat-row { display: flex; justify-content: space-between; align-items: center; padding: 0.5rem 0; border-bottom: 1px solid var(--p-surface-700); }
.stat-label { color: var(--p-surface-300); }
.stat-value { color: var(--p-surface-100); font-weight: bold; }
.findings-panel :deep(.p-card-content) { padding: 0; }
</style>
