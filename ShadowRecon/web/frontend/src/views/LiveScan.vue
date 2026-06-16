<template>
  <div class="live-scan">
    <button class="back-btn" @click="goBack">&larr; Back</button>
    <h1>Live Scan: {{ sessionId ? sessionId.slice(0, 12) : '...' }}</h1>
    <div class="status-bar">
      <span :class="'status-indicator ' + statusClass"></span>
      Status: <strong>{{ scanStatus }}</strong>
    </div>

    <div class="scan-grid">
      <div class="stats-panel">
        <h3>Progress</h3>
        <div class="stat-row"><span class="stat-label">Findings:</span><span class="stat-value">{{ findings.length }}</span></div>
        <div class="stat-row"><span class="stat-label">Endpoints:</span><span class="stat-value">{{ endpoints.length }}</span></div>
        <div class="stat-row"><span class="stat-label">Status:</span><span class="stat-value">{{ scanStatus }}</span></div>
        <div class="stat-row"><span class="stat-label">WS Connected:</span><span class="stat-value" :style="{color: connected ? '#00e5ff' : '#ff1744'}">{{ connected ? 'Yes' : 'No' }}</span></div>
      </div>

      <div class="findings-panel">
        <h3>Live Findings</h3>
        <FindingsFeed :findings="findings" />
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onUnmounted, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useScanStore } from '../store/scanStore'
import FindingsFeed from '../components/FindingsFeed.vue'

const props = defineProps({ id: String })
const route = useRoute()
const router = useRouter()
const store = useScanStore()
const sessionId = props.id || route.params.id

const scanStatus = computed(() => store.scanStatus)
const findings = computed(() => store.findings)
const endpoints = computed(() => store.endpoints)
const connected = computed(() => store.connected)
const statusClass = computed(() => {
  const map = { scanning: 'scanning', completed: 'completed', error: 'error', cancelled: 'cancelled' }
  return map[scanStatus.value] || 'idle'
})

onMounted(() => {
  store.connectWebSocket(sessionId)
  pollStatus()
})

onUnmounted(() => {
  store.disconnectWebSocket()
})

async function pollStatus() {
  while (store.scanStatus === 'idle' || store.scanStatus === 'scanning' || store.scanStatus === 'waf_check') {
    try {
      const status = await store.getScanStatus(sessionId)
      if (status && status.status) {
        store.scanStatus = status.status
        if (status.status === 'completed' || status.status === 'failed' || status.status === 'cancelled') break
      }
    } catch (e) {}
    await new Promise(r => setTimeout(r, 2000))
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
.status-indicator {
  width: 10px; height: 10px; border-radius: 50%; display: inline-block;
}
.status-indicator.scanning { background: #ffd600; animation: pulse 1s infinite; }
.status-indicator.completed { background: #00e5ff; }
.status-indicator.error { background: #ff1744; }
.status-indicator.cancelled { background: #8899aa; }
.status-indicator.idle { background: #556677; }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
.scan-grid { display: grid; grid-template-columns: 300px 1fr; gap: 20px; }
.stats-panel { background: #111927; border: 1px solid #1e3a5f; border-radius: 8px; padding: 20px; }
.stats-panel h3 { color: #00e5ff; margin-bottom: 15px; }
.stat-row { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #0f1a2e; }
.stat-label { color: #8899aa; }
.stat-value { color: #e0e0e0; font-weight: bold; }
.findings-panel { background: #111927; border: 1px solid #1e3a5f; border-radius: 8px; padding: 20px; }
.findings-panel h3 { color: #00e5ff; margin-bottom: 15px; }
</style>
