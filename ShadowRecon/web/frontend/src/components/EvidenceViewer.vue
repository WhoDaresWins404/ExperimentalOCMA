<template>
  <div class="ev-viewer">
    <div v-if="isWaf" class="ev-section">
      <div class="ev-row"><span class="ev-label">WAF</span><span class="ev-val badge">{{ evidence.waf_name || evidence.waf || 'Unknown' }}</span></div>
      <div v-if="evidence.confidence" class="ev-row"><span class="ev-label">Confidence</span><span class="ev-val">{{ (evidence.confidence * 100).toFixed(0) }}%</span></div>
      <div v-if="evidence.fingerprint" class="ev-row"><span class="ev-label">Fingerprint</span><code class="ev-code">{{ evidence.fingerprint }}</code></div>
      <div v-if="evidence.techniques" class="ev-row">
        <span class="ev-label">Techniques</span>
        <div class="ev-tags"><Tag v-for="t in evList(evidence.techniques)" :key="t" :value="t" severity="secondary" /></div>
      </div>
      <div v-if="evidence.results" class="ev-row">
        <span class="ev-label">Evasion Results</span>
        <pre class="ev-pre">{{ evString(evidence.results) }}</pre>
      </div>
      <div v-if="evidence.probes_sent" class="ev-row"><span class="ev-label">Probes</span><span class="ev-val">{{ evidence.probes_sent }}</span></div>
      <div v-if="evidence.signatures_checked" class="ev-row"><span class="ev-label">Signatures</span><span class="ev-val">{{ evidence.signatures_checked }}</span></div>
    </div>

    <div v-else-if="isRedirect" class="ev-section">
      <div class="ev-row"><span class="ev-label">Redirect</span><span class="ev-val">{{ evidence.from }} <span class="ev-arrow">&rarr;</span> {{ evidence.to }}</span></div>
    </div>

    <div v-else-if="isDirPaths" class="ev-section">
      <div class="ev-row"><span class="ev-label">Paths Found</span><span class="ev-val">{{ evidence.count }} blocked</span></div>
      <Accordion>
        <AccordionPanel value="0">
          <AccordionHeader>Show all {{ evidence.count }} paths</AccordionHeader>
          <AccordionContent>
            <ul class="ev-pathlist"><li v-for="p in evList(evidence.paths)" :key="p">{{ p }}</li></ul>
          </AccordionContent>
        </AccordionPanel>
      </Accordion>
    </div>

    <div v-else-if="isSinglePath" class="ev-section">
      <div v-if="evidence.url" class="ev-row"><span class="ev-label">URL</span><span class="ev-val ev-url">{{ evidence.url }}</span></div>
      <div v-if="evidence.path" class="ev-row"><span class="ev-label">Path</span><span class="ev-val ev-url">{{ evidence.path }}</span></div>
      <div v-if="evidence.status" class="ev-row"><span class="ev-label">Status</span><span :class="'status-code status-' + Math.floor(evidence.status / 100) * 100">{{ evidence.status }}</span></div>
      <div v-if="evidence.size" class="ev-row"><span class="ev-label">Size</span><span class="ev-val">{{ evSize(evidence.size) }}</span></div>
      <div v-if="evidence.content_preview" class="ev-row">
        <span class="ev-label">Preview</span>
        <pre class="ev-pre ev-preview">{{ evidence.content_preview }}</pre>
      </div>
      <div v-if="evidence.content" class="ev-row">
        <span class="ev-label">Content</span>
        <pre class="ev-pre ev-preview">{{ evidence.content }}</pre>
      </div>
    </div>

    <div v-else-if="isHeaders" class="ev-section">
      <div v-if="evidence.missing" class="ev-row">
        <span class="ev-label ev-miss">Missing Headers</span>
        <div class="ev-tags"><Tag v-for="h in evList(evidence.missing)" :key="h" :value="h" severity="warn" /></div>
      </div>
      <div v-if="evidence.present" class="ev-row">
        <span class="ev-label ev-pres">Present Headers</span>
        <div class="ev-tags"><Tag v-for="h in evList(evidence.present)" :key="h" :value="h" severity="success" /></div>
      </div>
    </div>

    <div v-else-if="isCors" class="ev-section">
      <div v-if="evidence.access_control_allow_origin" class="ev-row"><span class="ev-label">ACAO</span><span class="ev-val">{{ evidence.access_control_allow_origin }}</span></div>
      <div v-if="evidence.access_control_allow_credentials" class="ev-row"><span class="ev-label">ACAC</span><span class="ev-val">{{ evidence.access_control_allow_credentials }}</span></div>
      <div v-if="evidence.sent_origin" class="ev-row"><span class="ev-label">Sent Origin</span><span class="ev-val">{{ evidence.sent_origin }}</span></div>
      <div v-if="evidence.received_acao" class="ev-row"><span class="ev-label">Received ACAO</span><span class="ev-val">{{ evidence.received_acao }}</span></div>
      <div v-if="evidence.acao" class="ev-row"><span class="ev-label">ACAO</span><span class="ev-val">{{ evidence.acao }}</span></div>
      <div v-if="evidence.acac" class="ev-row"><span class="ev-label">ACAC</span><span class="ev-val">{{ evidence.acac }}</span></div>
    </div>

    <div v-else-if="isTiming" class="ev-section">
      <div class="ev-row"><span class="ev-label">Mean</span><span class="ev-val">{{ evFloat(evidence.mean_ms) }}ms</span></div>
      <div v-if="evidence.timings_ms" class="ev-row"><span class="ev-label">All Timings</span><span class="ev-val">{{ evList(evidence.timings_ms).join(', ') }}ms</span></div>
      <div v-if="evidence.stdev_ms" class="ev-row"><span class="ev-label">Std Dev</span><span class="ev-val">{{ evFloat(evidence.stdev_ms) }}ms</span></div>
      <div v-if="evidence.cv" class="ev-row"><span class="ev-label">CV</span><span class="ev-val">{{ evFloat(evidence.cv) }}</span></div>
    </div>

    <div v-else-if="isStatusCounts" class="ev-section">
      <div v-for="(count, code) in evObj(evidence.status_counts)" :key="code" class="ev-row">
        <span class="ev-label">Status {{ code }}</span>
        <span class="ev-val">{{ count }}</span>
        <span class="ev-bar" :style="{ width: (count / maxCount * 100) + '%' }"></span>
      </div>
    </div>

    <div v-else-if="isCookie" class="ev-section">
      <div class="ev-row"><span class="ev-label">Cookie</span><code class="ev-code">{{ evidence.cookie }}</code></div>
      <div v-if="evidence.issues" class="ev-row">
        <span class="ev-label ev-miss">Issues</span>
        <div class="ev-tags"><Tag v-for="i in evList(evidence.issues)" :key="i" :value="i" severity="warn" /></div>
      </div>
    </div>

    <div v-else-if="isServerTech" class="ev-section">
      <div v-if="evidence.server" class="ev-row"><span class="ev-label">Server</span><span class="ev-val">{{ evidence.server }}</span></div>
      <div v-if="evidence.server_header" class="ev-row"><span class="ev-label">Server Header</span><span class="ev-val">{{ evidence.server_header }}</span></div>
      <div v-if="evidence['x-powered-by']" class="ev-row"><span class="ev-label">X-Powered-By</span><span class="ev-val">{{ evidence['x-powered-by'] }}</span></div>
    </div>

    <div v-else-if="isApi" class="ev-section">
      <div v-if="evidence.item_count" class="ev-row"><span class="ev-label">Items</span><span class="ev-val">{{ evidence.item_count }}</span></div>
      <div v-if="evidence.sample" class="ev-row">
        <span class="ev-label">Sample</span>
        <pre class="ev-pre">{{ evString(evidence.sample) }}</pre>
      </div>
      <div v-if="evidence.keys" class="ev-row"><span class="ev-label">Keys</span><span class="ev-val">{{ evList(evidence.keys).join(', ') }}</span></div>
      <div v-if="evidence.has_data" class="ev-row"><span class="ev-label">Has Data</span><span class="ev-val">{{ evidence.has_data }}</span></div>
    </div>

    <div v-else-if="sameSizeData" class="ev-section">
      <div class="ev-row"><span class="ev-label">Response Sizes</span><span class="ev-val">{{ evList(evidence.response_sizes).join(', ') }}</span></div>
      <div class="ev-row"><span class="ev-label">Possible WAF block page</span></div>
    </div>

    <div v-else class="ev-section">
      <pre class="ev-pre ev-raw">{{ evString(evidence) }}</pre>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import Tag from 'primevue/tag'
import Accordion from 'primevue/accordion'
import AccordionPanel from 'primevue/accordionpanel'
import AccordionHeader from 'primevue/accordionheader'
import AccordionContent from 'primevue/accordioncontent'

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

function evList(v) { return Array.isArray(v) ? v : (typeof v === 'string' ? v.split(/,\s*/) : []) }
function evObj(v) { return (v && typeof v === 'object') ? v : {} }
function evString(v) { return typeof v === 'object' ? JSON.stringify(v, null, 2) : String(v) }
function evFloat(v) { return v != null ? Number(v).toFixed(1) : '' }
function evSize(v) { const s = Number(v); return s > 1024 ? (s / 1024).toFixed(1) + 'KB' : s + 'B' }
</script>

<style scoped>
.ev-viewer { font-size: 0.82rem; line-height: 1.5; }
.ev-section { display: flex; flex-direction: column; gap: 0.375rem; }
.ev-row { display: flex; align-items: baseline; gap: 0.5rem; flex-wrap: wrap; }
.ev-label { color: var(--p-surface-400); font-size: 0.85em; min-width: 70px; flex-shrink: 0; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
.ev-val { color: var(--p-surface-100); word-break: break-all; }
.ev-url { color: var(--p-primary-color); }
.ev-code { background: var(--p-surface-800); padding: 0.125rem 0.375rem; border-radius: 3px; font-size: 0.9em; color: var(--p-surface-200); }
.ev-pre { background: var(--p-surface-800); padding: 0.5rem; border-radius: 4px; font-size: 0.9em; overflow-x: auto; color: var(--p-surface-200); white-space: pre-wrap; max-height: 120px; overflow-y: auto; width: 100%; }
.ev-preview { max-height: 80px; }
.ev-raw { max-height: 200px; }
.ev-tags { display: flex; gap: 0.25rem; flex-wrap: wrap; }
.ev-miss { color: var(--p-orange-400); }
.ev-pres { color: var(--p-primary-color); }
.ev-bar { height: 4px; background: var(--p-primary-color); border-radius: 2px; min-width: 4px; opacity: 0.5; }
.ev-arrow { color: var(--p-primary-color); font-weight: bold; }
.ev-pathlist { margin: 0.375rem 0 0 1rem; padding: 0; max-height: 120px; overflow-y: auto; }
.ev-pathlist li { color: var(--p-surface-300); font-size: 0.85em; font-family: monospace; }
.badge { display: inline-block; padding: 1px 8px; border-radius: 8px; background: var(--p-primary-400); color: #fff; font-size: 0.9em; }
.status-code { display: inline-block; padding: 1px 8px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }
.status-200 { background: var(--p-green-500); color: #000; }
.status-300 { background: var(--p-primary-color); color: #000; }
.status-400 { background: var(--p-orange-400); color: #000; }
.status-500 { background: var(--p-red-500); color: #fff; }
</style>
