<template>
  <div class="h-full flex flex-col bg-cyber-bg text-cyber-text overflow-hidden">
    <div class="flex items-center justify-between px-4 py-2 border-b border-cyber-border bg-cyber-surface shrink-0">
      <div class="flex items-center gap-3">
        <router-link to="/ux/launcher" class="text-cyber-muted hover:text-cyber-accent text-sm transition-colors">&larr; UX Lab</router-link>
        <span class="text-cyber-muted-2">|</span>
        <span class="text-cyber-text font-bold text-sm">IDE Workspace</span>
      </div>
      <div v-if="sessionId" class="flex items-center gap-3">
        <button @click="showConfigForm = true" class="px-3 py-1 rounded text-xs bg-cyber-accent text-cyber-bg font-bold cursor-pointer hover:bg-[#00b8d4] transition-colors">New Scan</button>
        <span class="text-cyber-muted-2 text-xs font-mono">session: {{ sessionId }}</span>
        <button @click="closeSession" class="text-cyber-muted hover:text-cyber-danger text-lg leading-none cursor-pointer">&times;</button>
      </div>
    </div>

    <div v-if="!sessionId || showConfigForm" class="flex-1 overflow-y-auto">
      <div class="max-w-2xl mx-auto py-8 px-6">
        <h2 class="text-cyber-accent text-xl font-bold mb-6">{{ sessionId ? 'New Scan' : 'Start a Scan' }}</h2>
        <form @submit.prevent="handleStartScan" class="space-y-4">
          <div>
            <label class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Target URL</label>
            <input v-model="form.url" type="text" placeholder="https://example.com" required
              class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
          </div>
          <div class="flex gap-4">
            <div class="flex-1">
              <label class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Campaign Name</label>
              <input v-model="form.campaign_name" type="text" placeholder="Pentest Week"
                class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
            </div>
            <div class="flex-1">
              <label class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Campaign Description</label>
              <input v-model="form.campaign_description" type="text" placeholder="Optional"
                class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
            </div>
          </div>
          <div class="grid grid-cols-4 gap-2.5">
            <label v-for="p in profileDefs" :key="p.key"
              class="flex flex-col items-center gap-1 bg-cyber-surface border-2 rounded-lg p-3.5 text-center cursor-pointer transition-all"
              :class="scanProfile === p.key ? 'border-cyber-accent bg-cyber-surface-2' : 'border-cyber-border hover:border-cyber-accent'">
              <input type="radio" v-model="scanProfile" :value="p.key" class="absolute opacity-0 pointer-events-none" />
              <div class="text-cyber-text font-bold text-sm">{{ p.title }}</div>
              <div class="text-cyber-muted-2 text-xs leading-tight">{{ p.desc }}</div>
              <div class="text-[0.6rem] uppercase tracking-wider px-2 py-0.5 rounded mt-1" :class="badgeClass(p.key)">{{ p.badge }}</div>
            </label>
          </div>
          <div class="flex items-center gap-3 flex-wrap">
            <label class="flex items-center gap-1.5 cursor-pointer bg-cyber-surface border border-cyber-border rounded px-3.5 py-2 hover:border-cyber-accent transition-colors">
              <input type="checkbox" v-model="form.enable_llm" class="accent-cyber-accent" />
              <span class="text-cyber-text text-sm">Enable LLM</span>
            </label>
            <label class="flex items-center gap-1.5 cursor-pointer bg-cyber-surface border border-cyber-border rounded px-3.5 py-2 hover:border-cyber-accent transition-colors">
              <input type="checkbox" v-model="form.enable_proxy" class="accent-cyber-accent" />
              <span class="text-cyber-text text-sm">Proxy Chain</span>
            </label>
          </div>
          <button type="submit" :disabled="submitting"
            class="w-full bg-cyber-accent text-cyber-bg font-bold py-3.5 rounded text-base cursor-pointer hover:bg-[#00b8d4] transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
            {{ submitting ? 'Starting Scan...' : 'Start Scan' }}
          </button>
        </form>
      </div>
    </div>

    <div v-else class="flex-1 flex overflow-hidden">
      <div :style="{ flex: `0 0 ${explorerWidth}px` }" class="bg-cyber-surface border-r border-cyber-border overflow-y-auto overflow-x-hidden">
        <div class="p-3">
          <div class="text-cyber-muted-2 text-xs uppercase tracking-wider font-bold mb-2 px-2">Explorer</div>
          <div v-for="cat in scannerCategories" :key="cat.name">
            <div @click="toggleCategory(cat.name)" class="flex items-center gap-2 px-2 py-1.5 rounded cursor-pointer hover:bg-cyber-surface-2 text-sm transition-colors">
              <span class="text-xs transition-transform" :class="expandedCategories[cat.name] ? 'rotate-90' : ''">&#9654;</span>
              <span class="text-cyber-muted">{{ cat.label }}</span>
            </div>
            <div v-if="expandedCategories[cat.name]" class="ml-3 border-l border-cyber-border pl-2">
              <div v-for="item in cat.items" :key="item.name" @click="selectScanner(item.name)"
                class="flex items-center gap-2 px-2 py-1 rounded cursor-pointer hover:bg-cyber-surface-2 text-xs transition-colors group"
                :class="selectedScannerName === item.name ? 'bg-cyber-surface-2 text-cyber-accent' : 'text-cyber-muted'">
                <span v-if="scannerDot(item.name)" class="w-2 h-2 rounded-full shrink-0" :class="scannerDot(item.name)"></span>
                <span v-else class="w-2 shrink-0"></span>
                <span class="truncate">{{ item.label }}</span>
                <span v-if="scannerCount(item.name)" class="ml-auto text-cyber-muted-2 text-[10px]">{{ scannerCount(item.name) }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div @pointerdown="startDrag('explorer', $event)" class="w-1 cursor-col-resize bg-cyber-border hover:bg-cyber-accent shrink-0 relative z-10 transition-colors"></div>

      <div class="flex-1 flex flex-col overflow-hidden min-w-0">
        <div class="flex gap-1 border-b border-cyber-border bg-cyber-surface shrink-0 px-3">
          <button v-for="tab in tabs" :key="tab.key" @click="activeTab = tab.key"
            class="px-4 py-2 text-sm cursor-pointer transition-colors border-b-2 -mb-[1px] whitespace-nowrap"
            :class="activeTab === tab.key ? 'text-cyber-accent border-cyber-accent' : 'text-cyber-muted border-transparent hover:text-cyber-text hover:border-cyber-muted-2'">
            {{ tab.label }}
            <span v-if="tab.key === 'findings' && store.findings.length" class="ml-1.5 text-xs bg-cyber-accent/20 text-cyber-accent px-1.5 py-0.5 rounded-full">{{ store.findings.length }}</span>
            <span v-if="tab.key === 'http' && store.httpExchanges.length" class="ml-1.5 text-xs bg-cyber-accent/20 text-cyber-accent px-1.5 py-0.5 rounded-full">{{ store.httpExchanges.length }}</span>
          </button>
        </div>

        <div class="flex-1 overflow-y-auto p-4">
          <div v-if="activeTab === 'findings'">
            <div v-if="store.findings.length === 0" class="text-cyber-muted-2 text-center py-10">No findings yet.</div>
            <div v-for="f in sortedFindings" :key="f.id" @click="selectFinding(f)"
              class="bg-cyber-surface-2 rounded-lg p-4 mb-3 border-l-4 cursor-pointer transition-colors hover:bg-cyber-surface-2/80"
              :class="[severityBorder(f.severity), selectedFinding?.id === f.id ? 'ring-1 ring-cyber-accent' : '']">
              <div class="flex items-center gap-2.5 mb-2">
                <RiskBadge :severity="f.severity" :score="f.cvss_score" />
                <span class="text-cyber-text font-bold text-sm min-w-0 break-words">{{ f.title }}</span>
              </div>
              <div class="text-cyber-muted text-xs mb-2 flex items-center gap-1.5">
                Scanner: {{ f.scanner_name }} &middot; Confidence: {{ (f.confidence * 100).toFixed(0) }}%
                <span v-if="f.is_llm_enhanced" class="bg-cyber-llm text-white px-2 py-0.5 rounded text-xs">LLM</span>
              </div>
              <div class="text-cyber-text text-sm leading-relaxed opacity-80 break-words">{{ f.description }}</div>
              <div v-if="f.remediation" class="text-cyber-accent text-sm mt-2">
                <strong>Remediation:</strong> {{ f.remediation }}
              </div>
              <div v-if="expandedFinding === f.id" class="mt-2.5">
                <EvidenceViewer :evidence="f.evidence" :scanner-name="f.scanner_name" />
              </div>
              <div class="flex gap-2 mt-2">
                <button v-if="hasEvidence(f)" @click.stop="toggleExpandFinding(f.id)"
                  class="bg-transparent border border-cyber-border text-cyber-muted px-3 py-1 rounded text-xs cursor-pointer hover:text-cyber-accent hover:border-cyber-accent transition-colors">
                  {{ expandedFinding === f.id ? 'Hide' : 'Show' }} Evidence
                </button>
                <button :disabled="llmLoading === f.id" @click.stop="runLlmAnalysis(f)"
                  class="bg-transparent border border-cyber-llm text-cyber-llm-light px-3 py-1 rounded text-xs cursor-pointer hover:bg-cyber-llm hover:text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
                  {{ llmLoading === f.id ? 'Analyzing...' : 'LLM Analyze' }}
                </button>
              </div>
              <div v-if="llmResults[f.id]" class="mt-2.5 bg-cyber-bg border border-cyber-llm rounded-lg p-3 flex flex-col gap-2.5">
                <div v-if="llmResults[f.id].technical_impact">
                  <div class="text-cyber-llm-light text-xs uppercase tracking-wider font-bold mb-1">Technical Impact</div>
                  <LlmValueRenderer :value="llmResults[f.id].technical_impact" />
                </div>
                <div v-if="llmResults[f.id].exploitation_path">
                  <div class="text-cyber-llm-light text-xs uppercase tracking-wider font-bold mb-1">Exploitation Path</div>
                  <LlmValueRenderer :value="llmResults[f.id].exploitation_path" />
                </div>
                <div v-if="llmResults[f.id].remediation">
                  <div class="text-cyber-llm-light text-xs uppercase tracking-wider font-bold mb-1">Remediation</div>
                  <LlmValueRenderer :value="llmResults[f.id].remediation" />
                </div>
                <div v-if="llmResults[f.id].chaining_potential">
                  <div class="text-cyber-llm-light text-xs uppercase tracking-wider font-bold mb-1">Chaining Potential</div>
                  <LlmValueRenderer :value="llmResults[f.id].chaining_potential" />
                </div>
                <div v-if="llmResults[f.id].analyst_confidence">
                  <div class="text-cyber-llm-light text-xs uppercase tracking-wider font-bold mb-1">Analyst Confidence</div>
                  <LlmValueRenderer :value="llmResults[f.id].analyst_confidence" />
                </div>
                <div v-if="llmResults[f.id].error" class="text-cyber-danger text-xs">{{ llmResults[f.id].error }}</div>
              </div>
            </div>
          </div>

          <div v-else-if="activeTab === 'http'">
            <HttpExchangeFeed :exchanges="store.httpExchanges" @select="selectExchange" />
          </div>

          <div v-else-if="activeTab === 'progress'">
            <div class="space-y-1">
              <div v-for="item in sortedProgressScanners" :key="item.name"
                class="flex items-center gap-3 px-3 py-2 rounded bg-cyber-surface-2 text-sm">
                <span class="w-5 text-center shrink-0">{{ statusIcon(item.status) }}</span>
                <span :class="statusTextClass(item.status)" class="font-medium truncate">{{ item.label }}</span>
                <span v-if="item.findingCount" class="ml-auto text-xs text-cyber-muted-2">{{ item.findingCount }} findings</span>
              </div>
              <div v-if="allScannersList.length === 0" class="text-cyber-muted-2 text-center py-5">No scanners loaded.</div>
            </div>
          </div>
        </div>
      </div>

      <div @pointerdown="startDrag('context', $event)" class="w-1 cursor-col-resize bg-cyber-border hover:bg-cyber-accent shrink-0 relative z-10 transition-colors"></div>

      <div :style="{ flex: `0 0 ${contextWidth}px` }" class="bg-cyber-surface border-l border-cyber-border overflow-y-auto">
        <div class="p-4">
          <div class="text-cyber-muted-2 text-xs uppercase tracking-wider font-bold mb-3">Context</div>

          <div v-if="selectedExchange" class="space-y-3">
            <div class="grid grid-cols-2 gap-2 text-xs">
              <div class="bg-cyber-bg rounded p-2">
                <span class="text-cyber-muted-2 block">Status</span>
                <span class="font-bold font-mono" :class="exStatusColor(selectedExchange.status_code)">{{ selectedExchange.status_code }}</span>
              </div>
              <div class="bg-cyber-bg rounded p-2">
                <span class="text-cyber-muted-2 block">Method</span>
                <span class="font-mono text-cyber-text">{{ selectedExchange.method }}</span>
              </div>
            </div>
            <div class="bg-cyber-bg rounded p-2 text-xs">
              <span class="text-cyber-muted-2 block mb-1">URL</span>
              <span class="text-cyber-text break-all font-mono">{{ selectedExchange.url }}</span>
            </div>
            <div v-if="selectedExchange.timing_ms" class="bg-cyber-bg rounded p-2 text-xs">
              <span class="text-cyber-muted-2 block">Timing</span>
              <span class="text-cyber-text">{{ selectedExchange.timing_ms }}ms</span>
            </div>
            <div v-if="selectedExchange.request_headers" class="bg-cyber-bg rounded p-2 text-xs">
              <span class="text-cyber-muted-2 block mb-1">Request Headers</span>
              <pre class="text-cyber-text whitespace-pre-wrap break-all max-h-32 overflow-y-auto">{{ formatHeaders(selectedExchange.request_headers) }}</pre>
            </div>
            <div v-if="selectedExchange.response_headers" class="bg-cyber-bg rounded p-2 text-xs">
              <span class="text-cyber-muted-2 block mb-1">Response Headers</span>
              <pre class="text-cyber-text whitespace-pre-wrap break-all max-h-32 overflow-y-auto">{{ formatHeaders(selectedExchange.response_headers) }}</pre>
            </div>
            <div v-if="selectedExchange.response_body" class="bg-cyber-bg rounded p-2 text-xs">
              <span class="text-cyber-muted-2 block mb-1">Response Body</span>
              <pre class="text-cyber-text whitespace-pre-wrap break-all max-h-48 overflow-y-auto">{{ selectedExchange.response_body }}</pre>
            </div>
            <div v-if="selectedExchange.scanner" class="bg-cyber-bg rounded p-2 text-xs">
              <span class="text-cyber-muted-2 block mb-1">Scanner</span>
              <span class="text-cyber-text">{{ selectedExchange.scanner }}</span>
            </div>
          </div>

          <div v-else-if="selectedFinding" class="space-y-3">
            <div>
              <RiskBadge :severity="selectedFinding.severity" :score="selectedFinding.cvss_score" />
            </div>
            <h3 class="text-cyber-text font-bold text-sm leading-snug">{{ selectedFinding.title }}</h3>
            <div class="text-xs text-cyber-muted">
              Scanner: <span class="text-cyber-text">{{ selectedFinding.scanner_name }}</span>
            </div>
            <div v-if="selectedFinding.tags && selectedFinding.tags.length" class="flex flex-wrap gap-1">
              <span v-for="tag in selectedFinding.tags" :key="tag"
                class="bg-cyber-bg border border-cyber-border text-cyber-muted-2 px-2 py-0.5 rounded text-[10px]">{{ tag }}</span>
            </div>
            <div v-if="selectedFinding.description" class="text-cyber-text text-xs leading-relaxed opacity-80">{{ selectedFinding.description }}</div>
            <div v-if="selectedFinding.evidence" class="bg-cyber-bg border border-cyber-border rounded p-2 text-xs">
              <div class="text-cyber-muted-2 text-[10px] uppercase tracking-wider mb-1">Evidence</div>
              <pre class="text-cyber-text whitespace-pre-wrap break-all max-h-40 overflow-y-auto">{{ formatEvidence(selectedFinding.evidence) }}</pre>
            </div>
            <button @click="runLlmAnalysis(selectedFinding)" :disabled="llmLoading === selectedFinding.id"
              class="w-full bg-cyber-llm text-white px-3 py-2 rounded text-xs font-bold cursor-pointer hover:bg-cyber-llm/80 transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
              {{ llmLoading === selectedFinding.id ? 'Analyzing...' : 'LLM Analyze' }}
            </button>
            <div v-if="llmResults[selectedFinding.id]" class="space-y-2">
              <div v-if="llmResults[selectedFinding.id].technical_impact" class="bg-cyber-bg border border-cyber-llm rounded p-2 text-xs">
                <div class="text-cyber-llm-light text-[10px] uppercase tracking-wider font-bold mb-1">Technical Impact</div>
                <LlmValueRenderer :value="llmResults[selectedFinding.id].technical_impact" />
              </div>
              <div v-if="llmResults[selectedFinding.id].exploitation_path" class="bg-cyber-bg border border-cyber-llm rounded p-2 text-xs">
                <div class="text-cyber-llm-light text-[10px] uppercase tracking-wider font-bold mb-1">Exploitation Path</div>
                <LlmValueRenderer :value="llmResults[selectedFinding.id].exploitation_path" />
              </div>
              <div v-if="llmResults[selectedFinding.id].remediation" class="bg-cyber-bg border border-cyber-llm rounded p-2 text-xs">
                <div class="text-cyber-llm-light text-[10px] uppercase tracking-wider font-bold mb-1">Remediation</div>
                <LlmValueRenderer :value="llmResults[selectedFinding.id].remediation" />
              </div>
              <div v-if="llmResults[selectedFinding.id].chaining_potential" class="bg-cyber-bg border border-cyber-llm rounded p-2 text-xs">
                <div class="text-cyber-llm-light text-[10px] uppercase tracking-wider font-bold mb-1">Chaining Potential</div>
                <LlmValueRenderer :value="llmResults[selectedFinding.id].chaining_potential" />
              </div>
              <div v-if="llmResults[selectedFinding.id].analyst_confidence" class="bg-cyber-bg border border-cyber-llm rounded p-2 text-xs">
                <div class="text-cyber-llm-light text-[10px] uppercase tracking-wider font-bold mb-1">Analyst Confidence</div>
                <LlmValueRenderer :value="llmResults[selectedFinding.id].analyst_confidence" />
              </div>
              <div v-if="llmResults[selectedFinding.id].error" class="text-cyber-danger text-xs">{{ llmResults[selectedFinding.id].error }}</div>
            </div>
          </div>

          <div v-else class="text-cyber-muted-2 text-xs text-center py-10">Select an item to inspect</div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, computed, watch, onMounted, onUnmounted, nextTick } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useScanStore } from '../store/scanStore'
import HttpExchangeFeed from '../components/HttpExchangeFeed.vue'
import RiskBadge from '../components/RiskBadge.vue'
import EvidenceViewer from '../components/EvidenceViewer.vue'
import LlmValueRenderer from '../components/LlmValueRenderer.vue'

const route = useRoute()
const router = useRouter()
const store = useScanStore()

const sessionId = ref(null)
const showConfigForm = ref(false)
const activeTab = ref('findings')
const explorerWidth = ref(260)
const contextWidth = ref(360)
const submitting = ref(false)
const expandedFinding = ref(null)
const llmLoading = ref(null)
const llmResults = reactive({})
const selectedFinding = ref(null)
const selectedExchange = ref(null)
const selectedScannerName = ref(null)
const expandedCategories = reactive({})
let pollTimer = null

const tabs = [
  { key: 'findings', label: 'Findings' },
  { key: 'http', label: 'HTTP' },
  { key: 'progress', label: 'Progress' },
]

const profileDefs = [
  { key: 'quick', title: 'Quick', desc: 'Light scan, no crawl, ~5 min', badge: 'fast' },
  { key: 'standard', title: 'Standard', desc: 'Full scan, depth 1, LLM critical+', badge: 'balanced' },
  { key: 'deep', title: 'Deep', desc: 'Full scan, depth 2, LLM exploit', badge: 'thorough' },
  { key: 'custom', title: 'Custom', desc: 'Fine-tune every setting', badge: 'manual' },
]

const PROFILES = {
  quick: { scan_mode: 'light', crawl_depth: 0, threads: 10, timeout: 30, xss_mode: 'probe', enable_llm: false, enable_llm_payloads: false, detection_mode: 'detect' },
  standard: { scan_mode: 'full', crawl_depth: 1, threads: 25, timeout: 30, xss_mode: 'probe', enable_llm: true, enable_llm_payloads: false, detection_mode: 'detect' },
  deep: { scan_mode: 'full', crawl_depth: 2, threads: 50, timeout: 60, xss_mode: 'exploit', enable_llm: true, enable_llm_payloads: true, detection_mode: 'confirm' },
}

const scanProfile = ref('standard')

const form = reactive({
  url: '',
  campaign_name: 'default',
  campaign_description: '',
  threads: 25,
  timeout: 30,
  scan_mode: 'full',
  detection_mode: 'detect',
  enable_proxy: false,
  enable_llm: false,
  auth_type: 'none',
  auth_cookie_string: '',
  auth_bearer_token: '',
  auth_header_key: '',
  auth_header_value: '',
  auth_basic_username: '',
  auth_basic_password: '',
  crawl_depth: 1,
  xss_mode: 'probe',
  enable_llm_payloads: false,
  enabled_scanners: [],
})

const scannerCategories = [
  {
    name: 'recon', label: 'Recon',
    items: [
      { name: 'tech_scanner', label: 'Tech Stack' },
      { name: 'waf_detector', label: 'WAF Detection' },
      { name: 'recon_scanner', label: 'Reconnaissance' },
    ],
  },
  {
    name: 'discovery', label: 'Discovery',
    items: [
      { name: 'directory_scanner', label: 'Directory Scanner' },
      { name: 'api_scanner', label: 'API Scanner' },
      { name: 'subdomain_scanner', label: 'Subdomain Scanner' },
      { name: 'misconfig_scanner', label: 'Misconfiguration' },
      { name: 'crawler_scanner', label: 'Crawler' },
      { name: 'openapi_scanner', label: 'OpenAPI Scanner' },
    ],
  },
  {
    name: 'exploit', label: 'Exploit',
    items: [
      { name: 'sqli_scanner', label: 'SQL Injection' },
      { name: 'xss_scanner', label: 'XSS' },
      { name: 'nosqli_scanner', label: 'NoSQL Injection' },
      { name: 'ssrf_scanner', label: 'SSRF' },
      { name: 'lfi_scanner', label: 'LFI' },
      { name: 'cmdi_scanner', label: 'Command Injection' },
      { name: 'ssti_scanner', label: 'SSTI' },
      { name: 'redirect_scanner', label: 'Open Redirect' },
      { name: 'blind_xss_scanner', label: 'Blind XSS' },
      { name: 'deser_scanner', label: 'Deserialization' },
      { name: 'xxe_scanner', label: 'XXE' },
      { name: 'smuggling_scanner', label: 'HTTP Smuggling' },
      { name: 'race_condition_scanner', label: 'Race Condition' },
      { name: 'proto_pollution_scanner', label: 'Prototype Pollution' },
      { name: 'idor_scanner', label: 'IDOR' },
      { name: 'mass_assignment_scanner', label: 'Mass Assignment' },
    ],
  },
  {
    name: 'web3', label: 'Web3 / Cloud',
    items: [
      { name: 'web3_scanner', label: 'Web3 Scanner' },
      { name: 'cloud_metadata_scanner', label: 'Cloud Metadata' },
    ],
  },
  {
    name: 'auth', label: 'Auth / Logic',
    items: [
      { name: 'jwt_scanner', label: 'JWT Scanner' },
      { name: 'ratelimit_scanner', label: 'Rate Limit' },
      { name: 'cors_scanner', label: 'CORS' },
      { name: 'csrf_scanner', label: 'CSRF' },
      { name: 'graphql_scanner', label: 'GraphQL' },
      { name: 'account_takeover_scanner', label: 'Account Takeover' },
      { name: 'websocket_scanner', label: 'WebSocket' },
    ],
  },
]

const allScannersList = computed(() => {
  return scannerCategories.flatMap(cat => cat.items)
})

const scannerStatuses = reactive({})

const sortedProgressScanners = computed(() => {
  const items = allScannersList.value.map(item => ({
    ...item,
    status: scannerStatuses[item.name] || 'queued',
    findingCount: store.findings.filter(f => f.scanner_name === item.name).length,
  }))
  const order = { running: 0, queued: 1, completed: 2, failed: 3 }
  return items.sort((a, b) => (order[a.status] || 9) - (order[b.status] || 9))
})

const sortedFindings = computed(() => {
  return [...store.findings].sort((a, b) => (b.cvss_score || 0) - (a.cvss_score || 0))
})

watch(() => store.findings.length, () => {
  for (const f of store.findings) {
    if (f.scanner_name && scannerStatuses[f.scanner_name] !== 'completed') {
      scannerStatuses[f.scanner_name] = 'completed'
    }
  }
})

watch(() => store.scanStatus, (status) => {
  if (status === 'scanning' || status === 'adaptive_scan' || status === 'reconnaissance' || status === 'strategize' || status === 'waf_check') {
    for (const item of allScannersList.value) {
      if (!scannerStatuses[item.name]) {
        scannerStatuses[item.name] = 'queued'
      }
    }
  }
  if (status === 'completed') {
    for (const item of allScannersList.value) {
      if (!scannerStatuses[item.name] || scannerStatuses[item.name] === 'queued') {
        scannerStatuses[item.name] = 'completed'
      }
    }
  }
  if (status === 'failed' || status === 'cancelled') {
    for (const item of allScannersList.value) {
      if (!scannerStatuses[item.name] || scannerStatuses[item.name] === 'queued') {
        scannerStatuses[item.name] = 'failed'
      }
    }
  }
})

function statusIcon(status) {
  return { completed: '\u2713', running: '\u25B6', queued: '\u23F3', failed: '\u2717' }[status] || '\u23F3'
}

function statusTextClass(status) {
  return {
    completed: 'text-cyber-accent',
    running: 'text-yellow-400 animate-pulse',
    queued: 'text-cyber-muted-2',
    failed: 'text-cyber-danger',
  }[status] || 'text-cyber-muted-2'
}

function severityBorder(severity) {
  return {
    critical: 'border-cyber-danger',
    high: 'border-cyber-warning',
    medium: 'border-cyber-medium',
    low: 'border-cyber-accent',
  }[severity?.toLowerCase()] || 'border-cyber-border'
}

function exStatusColor(code) {
  if (code >= 200 && code < 300) return 'text-cyber-accent'
  if (code >= 300 && code < 400) return 'text-cyber-medium'
  if (code >= 400 && code < 500) return 'text-cyber-warning'
  if (code >= 500) return 'text-cyber-danger'
  return 'text-cyber-muted-2'
}

function badgeClass(key) {
  return {
    quick: 'bg-green-900 text-green-400',
    standard: 'bg-cyan-900 text-cyber-accent',
    deep: 'bg-red-900 text-red-400',
    custom: 'bg-purple-900 text-purple-300',
  }[key] || ''
}

function hasEvidence(f) {
  return f.evidence && Object.keys(f.evidence).length > 0
}

function toggleExpandFinding(id) {
  expandedFinding.value = expandedFinding.value === id ? null : id
}

function formatEvidence(evidence) {
  if (!evidence) return ''
  if (typeof evidence === 'string') return evidence
  try { return JSON.stringify(evidence, null, 2) } catch { return String(evidence) }
}

function formatHeaders(headers) {
  if (!headers) return '(empty)'
  if (typeof headers === 'string') {
    try {
      const parsed = JSON.parse(headers)
      return Object.entries(parsed).map(([k, v]) => `${k}: ${v}`).join('\n')
    } catch { return headers }
  }
  if (typeof headers === 'object') {
    return Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\n')
  }
  return String(headers)
}

function scannerDot(scannerName) {
  const findingsForScanner = store.findings.filter(f => f.scanner_name === scannerName)
  if (findingsForScanner.length === 0) return null
  const severities = findingsForScanner.map(f => f.severity?.toLowerCase())
  if (severities.includes('critical')) return 'bg-red-500'
  if (severities.includes('high')) return 'bg-yellow-500'
  if (severities.includes('medium')) return 'bg-orange-400'
  return 'bg-blue-400'
}

function scannerCount(scannerName) {
  const count = store.findings.filter(f => f.scanner_name === scannerName).length
  return count || null
}

function toggleCategory(name) {
  expandedCategories[name] = !expandedCategories[name]
}

function selectScanner(name) {
  selectedScannerName.value = name
  const scannerFindings = store.findings.filter(f => f.scanner_name === name)
  if (scannerFindings.length) {
    selectedFinding.value = scannerFindings[0]
    activeTab.value = 'findings'
  }
}

function selectFinding(f) {
  selectedFinding.value = f
  selectedExchange.value = null
}

function selectExchange(exchangeId) {
  const ex = store.httpExchanges.find(e => e.id === exchangeId)
  if (ex) {
    selectedExchange.value = ex
    selectedFinding.value = null
  }
}

async function runLlmAnalysis(f) {
  if (!f || !f.id) return
  llmLoading.value = f.id
  llmResults[f.id] = null
  try {
    if (!sessionId.value) throw new Error('No session ID')
    const result = await store.analyzeFinding(sessionId.value, f.id)
    llmResults[f.id] = result
    await nextTick()
  } catch (e) {
    llmResults[f.id] = { error: e.message }
    await nextTick()
  } finally {
    llmLoading.value = null
  }
}

function startDrag(panel, e) {
  e.preventDefault()
  const handle = e.currentTarget
  handle.setPointerCapture(e.pointerId)
  const startX = e.clientX
  const startWidth = panel === 'explorer' ? explorerWidth.value : contextWidth.value

  function onMove(ev) {
    const delta = ev.clientX - startX
    if (panel === 'explorer') {
      explorerWidth.value = Math.max(180, Math.min(500, startWidth + delta))
    } else {
      contextWidth.value = Math.max(250, Math.min(600, startWidth - delta))
    }
  }

  function onUp() {
    handle.removeEventListener('pointermove', onMove)
    handle.removeEventListener('pointerup', onUp)
    handle.releasePointerCapture(e.pointerId)
  }

  handle.addEventListener('pointermove', onMove)
  handle.addEventListener('pointerup', onUp)
}

async function handleStartScan() {
  submitting.value = true
  try {
    const payload = { ...form }
    delete payload.scope_text
    const result = await store.startScan(payload)
    if (result && result.session_id) {
      sessionId.value = result.session_id
      showConfigForm.value = false
      router.replace({ query: { sessionId: result.session_id } })
      connectToSession(result.session_id)
    }
  } catch (e) {
    console.error('Failed to start scan:', e)
  } finally {
    submitting.value = false
  }
}

function connectToSession(id) {
  store.reset()
  store.connectWebSocket(id)
  startPolling()
}

function startPolling() {
  pollOnce()
  pollTimer = setInterval(pollOnce, 3000)
}

async function pollOnce() {
  try {
    const sid = sessionId.value
    if (!sid) return
    const status = await store.getScanStatus(sid)
    if (status && status.status) {
      store.scanStatus = status.status
      if (['completed', 'failed', 'cancelled'].includes(status.status)) {
        if (pollTimer) clearInterval(pollTimer)
      }
    }
    if (store.scanStatus && store.scanStatus !== 'idle' && store.scanStatus !== 'pending') {
      const data = await store.getScanResults(sid)
      if (data && data.findings && data.findings.length) {
        const existingIds = new Set(store.findings.map(f => f.id))
        for (const f of data.findings) {
          if (!existingIds.has(f.id)) store.findings.push(f)
        }
      }
      if (data && data.endpoints && data.endpoints.length) {
        const existingIds = new Set(store.endpoints.map(e => e.id))
        for (const ep of data.endpoints) {
          if (!existingIds.has(ep.id)) store.endpoints.push(ep)
        }
      }
      await store.fetchExchanges(sid)
    }
  } catch (e) {
    console.error('Poll error:', e)
  }
}

function closeSession() {
  store.disconnectWebSocket()
  if (pollTimer) clearInterval(pollTimer)
  store.reset()
  sessionId.value = null
  showConfigForm.value = false
  selectedFinding.value = null
  selectedExchange.value = null
  router.replace({ query: {} })
}

watch(scanProfile, (profile) => {
  if (profile !== 'custom' && PROFILES[profile]) {
    Object.assign(form, PROFILES[profile])
  }
})

watch(() => store.httpExchanges.length, () => {
  if (selectedExchange.value) {
    const updated = store.httpExchanges.find(e => e.id === selectedExchange.value.id)
    if (updated) selectedExchange.value = updated
  }
})

onMounted(() => {
  const qSessionId = route.query.sessionId
  if (qSessionId) {
    sessionId.value = qSessionId
    connectToSession(qSessionId)
  }
})

watch(() => route.query.sessionId, (newId) => {
  if (newId && newId !== sessionId.value) {
    sessionId.value = newId
    connectToSession(newId)
  }
})

onUnmounted(() => {
  if (pollTimer) clearInterval(pollTimer)
})
</script>
