<template>
  <div class="text-xs leading-relaxed space-y-1.5">
    <!-- WAF -->
    <div v-if="isWaf">
      <div class="flex items-baseline gap-2 flex-wrap" v-if="evidence.waf_name || evidence.waf">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">WAF</span>
        <span class="text-cyber-text word-break break-all"><span class="bg-cyber-llm text-white px-2 py-0.5 rounded text-xs">{{ evidence.waf_name || evidence.waf || 'Unknown' }}</span></span>
      </div>
      <div class="flex items-baseline gap-2 flex-wrap" v-if="evidence.confidence">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">Confidence</span>
        <span class="text-cyber-text">{{ (evidence.confidence * 100).toFixed(0) }}%</span>
      </div>
      <div class="flex items-baseline gap-2 flex-wrap" v-if="evidence.fingerprint">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">Fingerprint</span>
        <code class="bg-cyber-bg px-1.5 py-0.5 rounded text-cyber-text">{{ evidence.fingerprint }}</code>
      </div>
      <div class="flex items-baseline gap-2 flex-wrap" v-if="evidence.techniques">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">Techniques</span>
        <span class="flex gap-1 flex-wrap">
          <span v-for="t in evList(evidence.techniques)" :key="t" class="bg-cyber-bg px-1.5 py-0.5 rounded text-cyber-muted border border-cyber-border text-[0.9em]">{{ t }}</span>
        </span>
      </div>
      <div class="flex items-baseline gap-2 flex-wrap" v-if="evidence.results">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">Results</span>
        <pre class="bg-cyber-bg p-2 rounded overflow-x-auto text-cyber-text whitespace-pre-wrap max-h-[120px] overflow-y-auto w-full">{{ evString(evidence.results) }}</pre>
      </div>
      <div class="flex items-baseline gap-2 flex-wrap" v-if="evidence.probes_sent">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">Probes</span>
        <span class="text-cyber-text">{{ evidence.probes_sent }}</span>
      </div>
      <div class="flex items-baseline gap-2 flex-wrap" v-if="evidence.signatures_checked">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">Signatures</span>
        <span class="text-cyber-text">{{ evidence.signatures_checked }}</span>
      </div>
    </div>

    <!-- Redirect -->
    <div v-else-if="isRedirect">
      <div class="flex items-baseline gap-2 flex-wrap">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">Redirect</span>
        <span class="text-cyber-text">{{ evidence.from }} <span class="text-cyber-accent font-bold">&rarr;</span> {{ evidence.to }}</span>
      </div>
    </div>

    <!-- Directory Paths -->
    <div v-else-if="isDirPaths">
      <div class="flex items-baseline gap-2 flex-wrap">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">Paths Found</span>
        <span class="text-cyber-text">{{ evidence.count }} blocked</span>
      </div>
      <details class="w-full mt-1">
        <summary class="text-cyber-accent cursor-pointer text-sm font-bold">Show all {{ evidence.count }} paths</summary>
        <ul class="mt-1.5 ml-4 max-h-[120px] overflow-y-auto space-y-0.5">
          <li v-for="p in evList(evidence.paths)" :key="p" class="text-cyber-muted text-xs font-mono">{{ p }}</li>
        </ul>
      </details>
    </div>

    <!-- Single Path -->
    <div v-else-if="isSinglePath">
      <div v-if="evidence.url" class="flex items-baseline gap-2 flex-wrap">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">URL</span>
        <span class="text-cyber-accent word-break break-all">{{ evidence.url }}</span>
      </div>
      <div v-if="evidence.path" class="flex items-baseline gap-2 flex-wrap">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">Path</span>
        <span class="text-cyber-accent word-break break-all">{{ evidence.path }}</span>
      </div>
      <div v-if="evidence.status" class="flex items-baseline gap-2 flex-wrap">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">Status</span>
        <span class="inline-block px-2 py-0.5 rounded text-xs font-bold" :class="statusClass(evidence.status)">{{ evidence.status }}</span>
      </div>
      <div v-if="evidence.size" class="flex items-baseline gap-2 flex-wrap">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">Size</span>
        <span class="text-cyber-text">{{ evSize(evidence.size) }}</span>
      </div>
      <div v-if="evidence.content_preview" class="flex items-baseline gap-2 flex-wrap">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">Preview</span>
        <pre class="bg-cyber-bg p-2 rounded overflow-x-auto text-cyber-text whitespace-pre-wrap max-h-[80px] overflow-y-auto w-full">{{ evidence.content_preview }}</pre>
      </div>
      <div v-if="evidence.content" class="flex items-baseline gap-2 flex-wrap">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">Content</span>
        <pre class="bg-cyber-bg p-2 rounded overflow-x-auto text-cyber-text whitespace-pre-wrap max-h-[80px] overflow-y-auto w-full">{{ evidence.content }}</pre>
      </div>
    </div>

    <!-- Headers -->
    <div v-else-if="isHeaders">
      <div v-if="evidence.missing" class="flex items-baseline gap-2 flex-wrap">
        <span class="text-cyber-warning text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">Missing</span>
        <span class="flex gap-1 flex-wrap">
          <span v-for="h in evList(evidence.missing)" :key="h" class="text-cyber-warning border border-cyber-warning bg-cyber-bg px-1.5 py-0.5 rounded text-[0.9em]">{{ h }}</span>
        </span>
      </div>
      <div v-if="evidence.present" class="flex items-baseline gap-2 flex-wrap">
        <span class="text-cyber-accent text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">Present</span>
        <span class="flex gap-1 flex-wrap">
          <span v-for="h in evList(evidence.present)" :key="h" class="text-cyber-accent border border-cyber-accent bg-cyber-bg px-1.5 py-0.5 rounded text-[0.9em]">{{ h }}</span>
        </span>
      </div>
    </div>

    <!-- CORS -->
    <div v-else-if="isCors">
      <div v-if="evidence.access_control_allow_origin" class="flex items-baseline gap-2 flex-wrap">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">ACAO</span>
        <span class="text-cyber-text">{{ evidence.access_control_allow_origin }}</span>
      </div>
      <div v-if="evidence.access_control_allow_credentials" class="flex items-baseline gap-2 flex-wrap">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">ACAC</span>
        <span class="text-cyber-text">{{ evidence.access_control_allow_credentials }}</span>
      </div>
      <div v-if="evidence.sent_origin" class="flex items-baseline gap-2 flex-wrap">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">Sent Origin</span>
        <span class="text-cyber-text">{{ evidence.sent_origin }}</span>
      </div>
      <div v-if="evidence.received_acao" class="flex items-baseline gap-2 flex-wrap">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">Received ACAO</span>
        <span class="text-cyber-text">{{ evidence.received_acao }}</span>
      </div>
      <div v-if="evidence.acao" class="flex items-baseline gap-2 flex-wrap">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">ACAO</span>
        <span class="text-cyber-text">{{ evidence.acao }}</span>
      </div>
      <div v-if="evidence.acac" class="flex items-baseline gap-2 flex-wrap">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">ACAC</span>
        <span class="text-cyber-text">{{ evidence.acac }}</span>
      </div>
    </div>

    <!-- Timing -->
    <div v-else-if="isTiming">
      <div class="flex items-baseline gap-2 flex-wrap">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">Mean</span>
        <span class="text-cyber-text">{{ evFloat(evidence.mean_ms) }}ms</span>
      </div>
      <div v-if="evidence.timings_ms" class="flex items-baseline gap-2 flex-wrap">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">All Timings</span>
        <span class="text-cyber-text">{{ evList(evidence.timings_ms).join(', ') }}ms</span>
      </div>
      <div v-if="evidence.stdev_ms" class="flex items-baseline gap-2 flex-wrap">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">Std Dev</span>
        <span class="text-cyber-text">{{ evFloat(evidence.stdev_ms) }}ms</span>
      </div>
      <div v-if="evidence.cv" class="flex items-baseline gap-2 flex-wrap">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">CV</span>
        <span class="text-cyber-text">{{ evFloat(evidence.cv) }}</span>
      </div>
    </div>

    <!-- Status Counts -->
    <div v-else-if="isStatusCounts">
      <div v-for="(count, code) in evObj(evidence.status_counts)" :key="code" class="flex items-center gap-2 mb-1">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">Status {{ code }}</span>
        <span class="text-cyber-text">{{ count }}</span>
        <span class="h-1 rounded-sm bg-cyber-accent opacity-50" :style="{ width: (count / maxCount * 100) + '%', minWidth: '4px' }"></span>
      </div>
    </div>

    <!-- Cookie -->
    <div v-else-if="isCookie">
      <div class="flex items-baseline gap-2 flex-wrap">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">Cookie</span>
        <code class="bg-cyber-bg px-1.5 py-0.5 rounded text-cyber-text">{{ evidence.cookie }}</code>
      </div>
      <div v-if="evidence.issues" class="flex items-baseline gap-2 flex-wrap">
        <span class="text-cyber-warning text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">Issues</span>
        <span class="flex gap-1 flex-wrap">
          <span v-for="i in evList(evidence.issues)" :key="i" class="text-cyber-warning border border-cyber-warning bg-cyber-bg px-1.5 py-0.5 rounded text-[0.9em]">{{ i }}</span>
        </span>
      </div>
    </div>

    <!-- Server Tech -->
    <div v-else-if="isServerTech">
      <div v-if="evidence.server" class="flex items-baseline gap-2 flex-wrap">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">Server</span>
        <span class="text-cyber-text">{{ evidence.server }}</span>
      </div>
      <div v-if="evidence.server_header" class="flex items-baseline gap-2 flex-wrap">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">Server Header</span>
        <span class="text-cyber-text">{{ evidence.server_header }}</span>
      </div>
      <div v-if="evidence['x-powered-by']" class="flex items-baseline gap-2 flex-wrap">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">X-Powered-By</span>
        <span class="text-cyber-text">{{ evidence['x-powered-by'] }}</span>
      </div>
    </div>

    <!-- API -->
    <div v-else-if="isApi">
      <div v-if="evidence.item_count" class="flex items-baseline gap-2 flex-wrap">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">Items</span>
        <span class="text-cyber-text">{{ evidence.item_count }}</span>
      </div>
      <div v-if="evidence.sample" class="flex items-baseline gap-2 flex-wrap">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">Sample</span>
        <pre class="bg-cyber-bg p-2 rounded overflow-x-auto text-cyber-text whitespace-pre-wrap max-h-[120px] overflow-y-auto w-full">{{ evString(evidence.sample) }}</pre>
      </div>
      <div v-if="evidence.keys" class="flex items-baseline gap-2 flex-wrap">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">Keys</span>
        <span class="text-cyber-text">{{ evList(evidence.keys).join(', ') }}</span>
      </div>
      <div v-if="evidence.has_data" class="flex items-baseline gap-2 flex-wrap">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">Has Data</span>
        <span class="text-cyber-text">{{ evidence.has_data }}</span>
      </div>
    </div>

    <!-- Same Size Data -->
    <div v-else-if="sameSizeData">
      <div class="flex items-baseline gap-2 flex-wrap">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider">Response Sizes</span>
        <span class="text-cyber-text">{{ evList(evidence.response_sizes).join(', ') }}</span>
      </div>
      <div class="flex items-baseline gap-2 flex-wrap">
        <span class="text-cyber-muted-2 text-[0.85em] min-w-[70px] font-semibold uppercase tracking-wider"></span>
        <span class="text-cyber-text">Possible WAF block page</span>
      </div>
    </div>

    <!-- Raw fallback -->
    <div v-else>
      <pre class="bg-cyber-bg p-2 rounded overflow-x-auto text-cyber-text whitespace-pre-wrap max-h-[200px] overflow-y-auto w-full">{{ evString(evidence) }}</pre>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({
  evidence: { type: [Object, Array, String], default: () => ({}) },
  scannerName: { type: String, default: '' },
})

const evidence = computed(() => {
  const e = props.evidence
  if (typeof e === 'string') { try { return JSON.parse(e) } catch { return { _raw: e } } }
  return e || {}
})

const keys = computed(() => Object.keys(evidence.value))

const isWaf = computed(() => keys.value.some(k => ['waf_name', 'waf', 'fingerprint', 'techniques', 'probes_sent', 'signatures_checked'].includes(k)) && !keys.value.includes('url') && !keys.value.includes('from'))
const isRedirect = computed(() => keys.value.includes('from') && keys.value.includes('to'))
const isDirPaths = computed(() => keys.value.includes('paths') && keys.value.includes('count'))
const isSinglePath = computed(() => {
  if (isWaf.value || isDirPaths.value || isRedirect.value) return false
  return keys.value.some(k => ['url', 'path'].includes(k)) && (keys.value.includes('status') || keys.value.includes('content_preview') || keys.value.includes('content'))
})
const isHeaders = computed(() => keys.value.includes('missing') || (keys.value.includes('present') && keys.value.length <= 3))
const isCors = computed(() => keys.value.some(k => k.toLowerCase().includes('cors') || k.includes('access_control') || k.includes('acao') || k.includes('acac') || k === 'sent_origin'))
const isTiming = computed(() => keys.value.includes('mean_ms') || keys.value.includes('timings_ms'))
const isStatusCounts = computed(() => keys.value.includes('status_counts'))
const isCookie = computed(() => keys.value.includes('cookie'))
const isServerTech = computed(() => keys.value.some(k => ['server', 'server_header', 'x-powered-by'].includes(k)))
const isApi = computed(() => keys.value.some(k => ['item_count', 'sample', 'keys', 'has_data'].includes(k)))
const sameSizeData = computed(() => keys.value.includes('response_sizes') && keys.value.includes('paths_tested'))

const maxCount = computed(() => {
  if (!isStatusCounts.value) return 1
  return Math.max(...Object.values(evidence.value.status_counts || {}), 1)
})

function statusClass(code) {
  const c = Math.floor(code / 100) * 100
  return {
    200: 'bg-green-600 text-white',
    300: 'bg-cyber-accent text-black',
    400: 'bg-cyber-warning text-black',
    500: 'bg-cyber-danger text-white',
  }[c] || 'bg-cyber-muted text-black'
}

function evList(v) { return Array.isArray(v) ? v : (typeof v === 'string' ? v.split(/,\s*/) : []) }
function evObj(v) { return (v && typeof v === 'object') ? v : {} }
function evString(v) { return typeof v === 'object' ? JSON.stringify(v, null, 2) : String(v) }
function evFloat(v) { return v != null ? Number(v).toFixed(1) : '' }
function evSize(v) { const s = Number(v); return s > 1024 ? (s / 1024).toFixed(1) + 'KB' : s + 'B' }
</script>
