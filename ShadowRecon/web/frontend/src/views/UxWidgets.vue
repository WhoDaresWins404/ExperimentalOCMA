<template>
  <div class="py-5">
    <div class="flex items-center justify-between mb-5 flex-wrap gap-3">
      <div class="flex items-center gap-4">
        <router-link to="/ux-test"
          class="bg-transparent border border-cyber-border text-cyber-muted px-4 py-2 rounded cursor-pointer no-underline hover:text-cyber-accent hover:border-cyber-accent transition-colors text-sm">
          &larr; UX Lab
        </router-link>
        <h1 class="text-cyber-accent text-2xl font-bold">Widget Dashboard</h1>
      </div>
      <div class="flex items-center gap-3">
        <div class="relative" ref="dropdownRef">
          <button @click="showWidgetMenu = !showWidgetMenu"
            class="bg-cyber-surface border border-cyber-border text-cyber-text px-4 py-2 rounded cursor-pointer hover:border-cyber-accent transition-colors text-sm flex items-center gap-2">
            + Add Widget
            <span class="text-xs">&#9660;</span>
          </button>
          <div v-if="showWidgetMenu"
            class="absolute right-0 top-full mt-1 bg-cyber-surface border border-cyber-border rounded-lg shadow-xl z-50 w-56 overflow-hidden">
            <div v-for="w in allWidgets" :key="w.id"
              class="flex items-center gap-3 px-4 py-2.5 cursor-pointer hover:bg-cyber-surface-2 transition-colors text-sm"
              @click="toggleWidget(w.id)">
              <input type="checkbox" :checked="activeWidgets.includes(w.id)"
                class="accent-cyber-accent cursor-pointer" @click.stop />
              <span>{{ w.icon }}</span>
              <span class="text-cyber-text">{{ w.label }}</span>
            </div>
          </div>
        </div>
        <div class="flex items-center gap-2 text-xs">
          <span class="w-2 h-2 rounded-full" :class="statusDotClass"></span>
          <span class="text-cyber-muted-2 font-mono">{{ statusLabel }}</span>
        </div>
      </div>
    </div>

    <div v-if="!sessionId" class="bg-cyber-surface border border-cyber-border rounded-lg p-6 mb-5">
      <h2 class="text-cyber-text font-bold text-lg mb-4">Start a Scan</h2>
      <div class="flex gap-4 flex-wrap items-end">
        <div class="flex-1 min-w-[200px]">
          <label class="text-cyber-muted-2 text-xs block mb-1">Target URL</label>
          <input v-model="scanUrl" placeholder="https://example.com"
            class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3 py-2 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
        </div>
        <div class="flex-1 min-w-[160px]">
          <label class="text-cyber-muted-2 text-xs block mb-1">Campaign Name</label>
          <input v-model="campaignName" placeholder="default"
            class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3 py-2 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
        </div>
        <button @click="startNewScan" :disabled="starting || !scanUrl"
          class="bg-cyber-accent text-black font-bold px-6 py-2 rounded text-sm cursor-pointer hover:bg-cyber-accent/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
          {{ starting ? 'Starting...' : 'Start Scan' }}
        </button>
      </div>
      <p v-if="errorMsg" class="text-cyber-danger text-xs mt-3">{{ errorMsg }}</p>
    </div>

    <div class="widget-grid">
      <div v-if="activeWidgets.includes('findings')" class="widget-card">
        <div class="widget-header">
          <span class="flex items-center gap-2 text-sm font-bold text-cyber-text"><span>&#128269;</span> Findings Timeline</span>
          <button @click="removeWidget('findings')" class="widget-close">&times;</button>
        </div>
        <div class="widget-body">
          <div v-if="findings.length === 0" class="text-cyber-muted-2 text-center py-8 text-sm">No findings yet.</div>
          <div v-for="f in findings.slice(0, 20)" :key="f.id"
            class="flex items-start gap-3 py-2.5 border-b border-cyber-surface-2 last:border-b-0">
            <span class="text-lg leading-none mt-0.5">{{ severityIcon(f.severity) }}</span>
            <div class="min-w-0 flex-1">
              <div class="text-cyber-text text-sm font-semibold truncate">{{ f.title || f.name || f.type || 'Finding' }}</div>
              <div class="text-cyber-muted-2 text-xs font-mono truncate">{{ f.endpoint || f.url || '' }}</div>
            </div>
          </div>
        </div>
      </div>

      <div v-if="activeWidgets.includes('progress')" class="widget-card">
        <div class="widget-header">
          <span class="flex items-center gap-2 text-sm font-bold text-cyber-text"><span>&#9201;</span> Scanner Progress</span>
          <button @click="removeWidget('progress')" class="widget-close">&times;</button>
        </div>
        <div class="widget-body">
          <div v-if="scannerStatuses.length === 0" class="text-cyber-muted-2 text-center py-8 text-sm">No scanner data.</div>
          <div v-for="s in scannerStatuses" :key="s.name" class="flex items-center justify-between py-2 border-b border-cyber-surface-2 last:border-b-0">
            <span class="text-cyber-text text-sm">{{ s.name }}</span>
            <span class="w-2.5 h-2.5 rounded-full" :class="scannerDotClass(s.status)"></span>
          </div>
        </div>
      </div>

      <div v-if="activeWidgets.includes('stats')" class="widget-card">
        <div class="widget-header">
          <span class="flex items-center gap-2 text-sm font-bold text-cyber-text"><span>&#128202;</span> Live Stats</span>
          <button @click="removeWidget('stats')" class="widget-close">&times;</button>
        </div>
        <div class="widget-body">
          <div class="grid grid-cols-2 gap-3">
            <div class="bg-cyber-bg rounded p-3 text-center">
              <div class="text-cyber-accent text-2xl font-bold">{{ findings.length }}</div>
              <div class="text-cyber-muted-2 text-xs">Findings</div>
            </div>
            <div class="bg-cyber-bg rounded p-3 text-center">
              <div class="text-cyber-accent text-2xl font-bold">{{ endpoints.length }}</div>
              <div class="text-cyber-muted-2 text-xs">Endpoints</div>
            </div>
            <div class="bg-cyber-bg rounded p-3 text-center">
              <div class="text-cyber-accent text-2xl font-bold">{{ httpExchanges.length }}</div>
              <div class="text-cyber-muted-2 text-xs">Exchanges</div>
            </div>
            <div class="bg-cyber-bg rounded p-3 text-center">
              <div class="text-cyber-text text-2xl font-bold">{{ severityCounts.total }}</div>
              <div class="text-cyber-muted-2 text-xs">Severity Total</div>
            </div>
          </div>
          <div class="flex gap-2 mt-3 flex-wrap">
            <span v-for="s in severityBreakdown" :key="s.label"
              class="text-xs px-2 py-1 rounded flex items-center gap-1"
              :class="s.bgClass">
              {{ s.icon }} {{ s.label }}: {{ s.count }}
            </span>
          </div>
        </div>
      </div>

      <div v-if="activeWidgets.includes('exchanges')" class="widget-card">
        <div class="widget-header">
          <span class="flex items-center gap-2 text-sm font-bold text-cyber-text"><span>&#127760;</span> HTTP Exchanges</span>
          <button @click="removeWidget('exchanges')" class="widget-close">&times;</button>
        </div>
        <div class="widget-body">
          <div v-if="httpExchanges.length === 0" class="text-cyber-muted-2 text-center py-8 text-sm">No exchanges yet.</div>
          <div v-for="ex in latestExchanges" :key="ex.id"
            class="flex items-center gap-3 py-2 border-b border-cyber-surface-2 last:border-b-0 text-xs font-mono">
            <span class="font-bold px-1.5 py-0.5 rounded shrink-0" :class="statusCodeClass(ex.status_code || ex.status)">
              {{ ex.status_code || ex.status }}
            </span>
            <span class="text-cyber-muted-2 shrink-0 w-10">{{ ex.method }}</span>
            <span class="text-cyber-text truncate flex-1">{{ ex.url }}</span>
            <span v-if="ex.duration" class="text-cyber-muted-2 shrink-0">{{ ex.duration }}ms</span>
          </div>
        </div>
      </div>

      <div v-if="activeWidgets.includes('chains')" class="widget-card">
        <div class="widget-header">
          <span class="flex items-center gap-2 text-sm font-bold text-cyber-text"><span>&#128279;</span> Chain Explorer</span>
          <button @click="removeWidget('chains')" class="widget-close">&times;</button>
        </div>
        <div class="widget-body">
          <div v-for="c in chainList" :key="c.name"
            class="flex items-center justify-between py-2.5 border-b border-cyber-surface-2 last:border-b-0">
            <div class="flex items-center gap-2 min-w-0 flex-1">
              <span class="text-cyber-accent shrink-0">&#128279;</span>
              <span class="text-cyber-text text-sm truncate">{{ c.name }}</span>
            </div>
            <span class="text-xs px-2 py-0.5 rounded shrink-0 ml-2"
              :class="c.active ? 'bg-cyber-accent/20 text-cyber-accent' : 'bg-cyber-surface-2 text-cyber-muted-2'">
              {{ c.active ? 'Active' : 'Inactive' }}
            </span>
          </div>
        </div>
      </div>

      <div v-if="activeWidgets.includes('endpoints')" class="widget-card">
        <div class="widget-header">
          <span class="flex items-center gap-2 text-sm font-bold text-cyber-text"><span>&#128205;</span> Endpoint Graph</span>
          <button @click="removeWidget('endpoints')" class="widget-close">&times;</button>
        </div>
        <div class="widget-body">
          <div v-if="endpoints.length === 0" class="text-cyber-muted-2 text-center py-8 text-sm">No endpoints discovered.</div>
          <div v-for="g in endpointGroups" :key="g.label" class="mb-3 last:mb-0">
            <div class="flex items-center justify-between mb-1.5">
              <span class="text-xs font-bold" :class="g.textClass">{{ g.label }}</span>
              <span class="text-cyber-muted-2 text-xs">{{ g.count }}</span>
            </div>
            <div class="bg-cyber-bg rounded-full h-2 overflow-hidden">
              <div class="h-full rounded-full transition-all duration-500" :class="g.barClass"
                :style="{ width: endpointGroupsMax > 0 ? (g.count / endpointGroupsMax * 100) + '%' : '0%' }"></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, watch, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useScanStore } from '../store/scanStore'

const route = useRoute()
const router = useRouter()
const store = useScanStore()

const sessionId = computed(() => route.query.sessionId || '')
const showWidgetMenu = ref(false)
const dropdownRef = ref(null)
const scanUrl = ref('')
const campaignName = ref('default')
const starting = ref(false)
const errorMsg = ref('')
const scannerStatuses = ref([])

const WIDGETS_KEY = 'uxwidgets_active'

const allWidgets = [
  { id: 'findings', icon: '\uD83D\uDD0D', label: 'Findings Timeline' },
  { id: 'progress', icon: '\u23F1', label: 'Scanner Progress' },
  { id: 'stats', icon: '\uD83D\uDCCA', label: 'Live Stats' },
  { id: 'exchanges', icon: '\uD83C\uDF10', label: 'HTTP Exchanges' },
  { id: 'chains', icon: '\uD83D\uDD17', label: 'Chain Explorer' },
  { id: 'endpoints', icon: '\uD83D\uDCCD', label: 'Endpoint Graph' },
]

const chainList = [
  { name: 'SSRF \u2192 Cloud Metadata', active: true },
  { name: 'XSS \u2192 Blind XSS', active: true },
  { name: 'SQLi \u2192 Deep Exploit', active: true },
  { name: 'LFI \u2192 RCE', active: false },
  { name: 'Open Redirect \u2192 SSRF', active: false },
]

function loadActiveWidgets() {
  try {
    const saved = localStorage.getItem(WIDGETS_KEY)
    if (saved) {
      const parsed = JSON.parse(saved)
      if (Array.isArray(parsed) && parsed.length > 0) return parsed
    }
  } catch (e) {}
  return allWidgets.map(w => w.id)
}

const activeWidgets = ref(loadActiveWidgets())

watch(activeWidgets, (val) => {
  localStorage.setItem(WIDGETS_KEY, JSON.stringify(val))
}, { deep: true })

function toggleWidget(id) {
  const idx = activeWidgets.value.indexOf(id)
  if (idx >= 0) {
    activeWidgets.value.splice(idx, 1)
  } else {
    activeWidgets.value.push(id)
  }
}

function removeWidget(id) {
  const idx = activeWidgets.value.indexOf(id)
  if (idx >= 0) activeWidgets.value.splice(idx, 1)
}

document.addEventListener('click', (e) => {
  if (dropdownRef.value && !dropdownRef.value.contains(e.target)) {
    showWidgetMenu.value = false
  }
})

const findings = computed(() => store.findings)
const endpoints = computed(() => store.endpoints)
const httpExchanges = computed(() => store.httpExchanges)

const latestExchanges = computed(() => {
  return [...httpExchanges.value].reverse().slice(0, 20)
})

const statusLabel = computed(() => {
  const labels = {
    idle: 'Idle', pending: 'Pending', waf_check: 'WAF Check',
    reconnaissance: 'Recon', strategize: 'Planning',
    scanning: 'Scanning', adaptive_scan: 'Adaptive Scan',
    dedup: 'Dedup', llm_enrich: 'LLM Enrich',
    generating_report: 'Generating Report', completed: 'Completed',
    cancelled: 'Cancelled', failed: 'Failed',
  }
  return labels[store.scanStatus] || store.scanStatus || 'No session'
})

const statusDotClass = computed(() => {
  const map = {
    scanning: 'bg-yellow-400 animate-pulse-dot', adaptive_scan: 'bg-yellow-400 animate-pulse-dot',
    reconnaissance: 'bg-yellow-400 animate-pulse-dot', strategize: 'bg-yellow-400 animate-pulse-dot',
    waf_check: 'bg-yellow-400 animate-pulse-dot', dedup: 'bg-yellow-400 animate-pulse-dot',
    llm_enrich: 'bg-yellow-400 animate-pulse-dot', generating_report: 'bg-yellow-400 animate-pulse-dot',
    completed: 'bg-cyber-accent', failed: 'bg-cyber-danger', cancelled: 'bg-cyber-muted',
  }
  return map[store.scanStatus] || 'bg-cyber-muted-2'
})

function severityIcon(sev) {
  const map = { critical: '\uD83D\uDD34', high: '\uD83D\uDFE0', medium: '\uD83D\uDFE1', low: '\uD83D\uDD35', info: '\uD83D\uDD36' }
  return map[(sev || '').toLowerCase()] || '\uD83D\uDD36'
}

const severityCounts = computed(() => {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  for (const f of findings.value) {
    const s = (f.severity || '').toLowerCase()
    if (counts[s] !== undefined) counts[s]++
  }
  counts.total = findings.value.length
  return counts
})

const severityBreakdown = computed(() => {
  const c = severityCounts.value
  return [
    { label: 'CRIT', icon: '\uD83D\uDD34', count: c.critical, bgClass: 'bg-red-900/50 text-red-400' },
    { label: 'HIGH', icon: '\uD83D\uDFE0', count: c.high, bgClass: 'bg-orange-900/50 text-orange-400' },
    { label: 'MED', icon: '\uD83D\uDFE1', count: c.medium, bgClass: 'bg-yellow-900/50 text-yellow-400' },
    { label: 'LOW', icon: '\uD83D\uDD35', count: c.low, bgClass: 'bg-blue-900/50 text-blue-400' },
  ]
})

const endpointGroups = computed(() => {
  const groups = { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0 }
  for (const ep of endpoints.value) {
    const code = ep.response_code || ep.status || 0
    if (code >= 200 && code < 300) groups['2xx']++
    else if (code >= 300 && code < 400) groups['3xx']++
    else if (code >= 400 && code < 500) groups['4xx']++
    else if (code >= 500) groups['5xx']++
  }
  return [
    { label: '2xx Success', count: groups['2xx'], textClass: 'text-cyber-accent', barClass: 'bg-cyber-accent' },
    { label: '3xx Redirect', count: groups['3xx'], textClass: 'text-blue-400', barClass: 'bg-blue-500' },
    { label: '4xx Client', count: groups['4xx'], textClass: 'text-cyber-warning', barClass: 'bg-cyber-warning' },
    { label: '5xx Server', count: groups['5xx'], textClass: 'text-cyber-danger', barClass: 'bg-cyber-danger' },
  ]
})

const endpointGroupsMax = computed(() => Math.max(...endpointGroups.value.map(g => g.count), 1))

function statusCodeClass(code) {
  if (!code) return 'text-cyber-muted-2 bg-cyber-surface-2'
  if (code < 300) return 'text-cyber-accent bg-cyber-accent/20'
  if (code < 400) return 'text-blue-400 bg-blue-900/30'
  if (code < 500) return 'text-cyber-warning bg-yellow-900/30'
  return 'text-cyber-danger bg-red-900/30'
}

function scannerDotClass(status) {
  const map = { completed: 'bg-cyber-accent', running: 'bg-yellow-400 animate-pulse-dot', queued: 'bg-cyber-muted-2', failed: 'bg-cyber-danger' }
  return map[(status || '').toLowerCase()] || 'bg-cyber-muted-2'
}

let pollTimer = null

async function pollOnce() {
  if (!sessionId.value) return
  try {
    const status = await store.getScanStatus(sessionId.value)
    if (status && status.status) {
      store.scanStatus = status.status
      if (status.scanners && Array.isArray(status.scanners)) {
        scannerStatuses.value = status.scanners
      }
      if (['completed', 'failed', 'cancelled'].includes(status.status)) {
        if (pollTimer) clearInterval(pollTimer)
      }
    }
    const data = await store.getScanResults(sessionId.value)
    if (data) {
      if (data.findings && data.findings.length) {
        const existingIds = new Set(store.findings.map(f => f.id))
        for (const f of data.findings) {
          if (!existingIds.has(f.id)) store.findings.push(f)
        }
      }
      if (data.endpoints && data.endpoints.length) {
        const existingIds = new Set(store.endpoints.map(e => e.id))
        for (const ep of data.endpoints) {
          if (!existingIds.has(ep.id)) store.endpoints.push(ep)
        }
      }
    }
    await store.fetchExchanges(sessionId.value)
  } catch (e) {}
}

function startPolling() {
  pollOnce()
  pollTimer = setInterval(pollOnce, 3000)
}

async function startNewScan() {
  if (!scanUrl.value) return
  starting.value = true
  errorMsg.value = ''
  try {
    const result = await store.startScan({
      url: scanUrl.value,
      campaign_name: campaignName.value || 'default',
    })
    if (result && result.session_id) {
      router.replace({ query: { sessionId: result.session_id } })
      store.currentSession = result
      store.scanStatus = 'pending'
      startPolling()
    }
  } catch (e) {
    errorMsg.value = e?.response?.data?.detail || e?.message || 'Failed to start scan'
  } finally {
    starting.value = false
  }
}

onMounted(() => {
  if (sessionId.value) {
    startPolling()
  }
})

onUnmounted(() => {
  if (pollTimer) clearInterval(pollTimer)
})
</script>

<style scoped>
.widget-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(380px, 1fr));
  gap: 16px;
}
.widget-card {
  background: var(--cyber-surface, #1b2838);
  border: 1px solid var(--cyber-border, #2a3a4a);
  border-radius: 8px;
  overflow: hidden;
}
.widget-header {
  background: var(--cyber-surface-2, #233244);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 16px;
}
.widget-body {
  padding: 12px 16px;
}
.widget-close {
  background: none;
  border: none;
  color: var(--cyber-muted-2, #5a7a9a);
  font-size: 18px;
  cursor: pointer;
  line-height: 1;
  padding: 0 4px;
}
.widget-close:hover {
  color: var(--cyber-danger, #f04747);
}
</style>
