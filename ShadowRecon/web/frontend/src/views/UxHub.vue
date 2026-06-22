<template>
  <div class="flex min-h-screen bg-cyber-bg">
    <aside class="w-60 flex-shrink-0 bg-cyber-surface border-r border-cyber-border flex flex-col">
      <div class="px-5 py-5 border-b border-cyber-border">
        <h1 class="text-cyber-accent text-lg font-bold tracking-wider flex items-center gap-2">
          <span>&#9889;</span> ShadowRecon Hub
        </h1>
      </div>
      <nav class="flex-1 py-3">
        <button v-for="item in navItems" :key="item.key" @click="activeNav = item.key; showPanel = false"
          class="w-full flex items-center gap-3 px-5 py-2.5 text-sm text-left transition-all cursor-pointer border-l-2 bg-transparent"
          :class="activeNav === item.key ? 'text-cyber-accent border-l-cyber-accent bg-cyber-accent/5' : 'text-cyber-muted border-l-transparent hover:text-cyber-text hover:bg-cyber-surface-2'">
          <span class="text-base">{{ item.icon }}</span>
          <span>{{ item.label }}</span>
        </button>
      </nav>
      <div class="px-5 py-4 border-t border-cyber-border">
        <button @click="$router.push('/ux-test')"
          class="w-full bg-transparent border border-cyber-border text-cyber-muted px-3 py-2 rounded text-xs cursor-pointer hover:text-cyber-accent hover:border-cyber-accent transition-colors">
          &larr; Back to UX Lab
        </button>
      </div>
    </aside>

    <main class="flex-1 overflow-y-auto p-6">
      <div v-if="activeNav === 'dashboard'">
        <div class="grid grid-cols-5 gap-4 mb-6">
          <div v-for="card in countCards" :key="card.label"
            class="bg-cyber-surface border border-cyber-border rounded-lg p-4 text-center"
            :class="'border-l-4 ' + card.border">
            <div class="text-3xl font-bold text-cyber-text">{{ card.count }}</div>
            <div class="text-xs uppercase tracking-wider mt-1" :class="card.textClass">{{ card.label }}</div>
          </div>
        </div>

        <div v-if="activeScans.length === 0" class="bg-cyber-surface border border-dashed border-cyber-border rounded-lg py-12 text-center text-cyber-muted-2 mb-6">
          No active scans running.
        </div>

        <div v-for="s in activeScans" :key="s.session_id || s.id"
          class="bg-cyber-surface border border-cyber-border rounded-lg p-4 mb-3 flex items-center gap-4 flex-wrap">
          <div class="flex-1 min-w-0">
            <div class="text-cyber-text font-bold text-sm truncate">{{ s.target || s.url || 'Unknown target' }}</div>
            <div class="text-cyber-muted-2 text-xs mt-0.5">Scan #{{ s.id || s.session_id }}</div>
          </div>
          <div class="w-40">
            <div class="bg-cyber-bg rounded-full h-2 overflow-hidden">
              <div class="h-full rounded-full transition-all duration-700" :class="progressBarClass(s)" :style="{ width: scanProgress(s) + '%' }"></div>
            </div>
            <div class="text-cyber-muted-2 text-[10px] text-right mt-0.5">{{ scanProgress(s) }}%</div>
          </div>
          <div class="text-cyber-muted text-xs">{{ s.findings_count || 0 }} findings</div>
          <div class="flex gap-2">
            <button @click="viewScan(s)"
              class="bg-cyber-accent/10 border border-cyber-accent text-cyber-accent px-3 py-1.5 rounded text-xs cursor-pointer hover:bg-cyber-accent hover:text-cyber-bg transition-colors">View</button>
            <button @click="abortScan(s)"
              class="bg-red-900/30 border border-cyber-danger text-cyber-danger px-3 py-1.5 rounded text-xs cursor-pointer hover:bg-red-800 hover:text-red-300 transition-colors">Abort</button>
          </div>
        </div>

        <button @click="openNewScan"
          class="w-full bg-cyber-accent text-cyber-bg font-bold py-4 rounded-lg text-base cursor-pointer hover:bg-[#00b8d4] transition-colors mt-4">
          + New Scan
        </button>
      </div>

      <div v-if="activeNav === 'templates'">
        <div class="flex items-center justify-between mb-5">
          <h2 class="text-cyber-accent font-bold text-lg">Scan Templates</h2>
          <button @click="saveCurrentAsTemplate"
            class="bg-cyber-surface border border-cyber-accent text-cyber-accent px-4 py-2 rounded text-sm cursor-pointer hover:bg-cyber-accent/10 transition-colors">
            Save Current as Template
          </button>
        </div>
        <div v-if="templates.length === 0" class="bg-cyber-surface border border-dashed border-cyber-border rounded-lg py-12 text-center text-cyber-muted-2">
          No saved templates. Configure a scan and save it as a template.
        </div>
        <div v-for="(t, i) in templates" :key="i"
          class="bg-cyber-surface border border-cyber-border rounded-lg p-4 mb-3 flex items-center gap-4">
          <div class="flex-1">
            <div class="text-cyber-text font-bold text-sm">{{ t.name }}</div>
            <div class="text-cyber-muted text-xs mt-0.5">{{ t.description || 'No description' }}</div>
            <div class="text-cyber-muted-2 text-[10px] mt-1">Target: {{ t.config?.url || 'Not set' }}</div>
          </div>
          <button @click="loadTemplate(t)"
            class="bg-cyber-accent/10 border border-cyber-accent text-cyber-accent px-3 py-1.5 rounded text-xs cursor-pointer hover:bg-cyber-accent hover:text-cyber-bg transition-colors">Load</button>
          <button @click="deleteTemplate(i)"
            class="bg-red-900/30 border border-cyber-danger text-cyber-danger px-3 py-1.5 rounded text-xs cursor-pointer hover:bg-red-800 hover:text-red-300 transition-colors">Delete</button>
        </div>
      </div>

      <div v-if="activeNav === 'history'">
        <div class="mb-5">
          <input v-model="historySearch" type="text" placeholder="Search campaigns..."
            class="w-full max-w-xs bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
        </div>
        <div v-if="filteredCampaigns.length === 0" class="bg-cyber-surface border border-dashed border-cyber-border rounded-lg py-12 text-center text-cyber-muted-2">
          No campaigns found.
        </div>
        <div v-for="c in filteredCampaigns" :key="c.id"
          class="bg-cyber-surface border border-cyber-border rounded-lg p-4 mb-3 flex items-center gap-4">
          <div class="flex-1">
            <div class="text-cyber-text font-bold text-sm">{{ c.name }}</div>
            <div class="text-cyber-muted text-xs mt-0.5">{{ c.description || 'No description' }}</div>
            <div class="text-cyber-muted-2 text-[10px] mt-1">{{ new Date(c.created_at).toLocaleDateString() }} &middot; {{ c.scan_count || 0 }} scans</div>
          </div>
          <button @click="$router.push('/campaign/' + c.id)"
            class="bg-cyber-accent/10 border border-cyber-accent text-cyber-accent px-3 py-1.5 rounded text-xs cursor-pointer hover:bg-cyber-accent hover:text-cyber-bg transition-colors">View</button>
        </div>
      </div>

      <div v-if="activeNav === 'scannerConfig'">
        <div class="mb-5 flex items-center gap-4">
          <h2 class="text-cyber-accent font-bold text-lg">Scanner Modules</h2>
          <select v-model="scannerCategoryFilter"
            class="bg-cyber-bg border border-cyber-border text-cyber-text px-3 py-2 rounded text-sm outline-none focus:border-cyber-accent transition-colors cursor-pointer">
            <option value="">All Categories</option>
            <option v-for="cat in scannerCategories" :key="cat" :value="cat">{{ cat }}</option>
          </select>
        </div>
        <div v-if="filteredScanners.length === 0" class="bg-cyber-surface border border-dashed border-cyber-border rounded-lg py-12 text-center text-cyber-muted-2">
          No scanner modules loaded.
        </div>
        <div class="bg-cyber-surface border border-cyber-border rounded-lg overflow-hidden">
          <table class="w-full text-sm">
            <thead>
              <tr class="border-b border-cyber-border text-cyber-muted-2 text-xs uppercase tracking-wider">
                <th class="text-left px-4 py-3 font-medium">Name</th>
                <th class="text-left px-4 py-3 font-medium">Category</th>
                <th class="text-left px-4 py-3 font-medium">Risk Level</th>
                <th class="text-left px-4 py-3 font-medium">Cost</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="s in filteredScanners" :key="s.name"
                class="border-b border-cyber-border last:border-0 text-cyber-text hover:bg-cyber-surface-2 transition-colors">
                <td class="px-4 py-3 font-bold">{{ s.name }}</td>
                <td class="px-4 py-3 text-cyber-muted">{{ s.category || 'Uncategorized' }}</td>
                <td class="px-4 py-3">
                  <span class="px-2 py-0.5 rounded text-xs font-bold" :class="riskBadgeClass(s.risk_level)">{{ s.risk_level || 'unknown' }}</span>
                </td>
                <td class="px-4 py-3 text-cyber-muted">{{ s.cost ?? '-' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </main>

    <transition name="panel-slide">
      <div v-if="showPanel" class="fixed inset-0 z-40 flex justify-end">
        <div class="absolute inset-0 bg-black/60" @click="showPanel = false"></div>
        <div class="relative w-[480px] bg-cyber-surface border-l border-cyber-border h-full overflow-y-auto z-50">
          <div class="sticky top-0 bg-cyber-surface border-b border-cyber-border px-5 py-4 flex items-center justify-between z-10">
            <h2 class="text-cyber-accent font-bold text-lg">New Scan</h2>
            <button @click="showPanel = false"
              class="bg-transparent border-none text-cyber-muted text-xl cursor-pointer hover:text-cyber-text transition-colors">&times;</button>
          </div>

          <div class="p-5 space-y-4">
            <details open class="bg-cyber-bg border border-cyber-border rounded-lg group">
              <summary class="px-4 py-3 text-cyber-accent font-bold text-sm cursor-pointer outline-none select-none flex items-center gap-2">
                <span class="text-cyber-muted-2">&#9654;</span> Basic
              </summary>
              <div class="px-4 pb-4 pt-2 border-t border-cyber-border space-y-3">
                <div>
                  <label class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Target URL</label>
                  <input v-model="newForm.url" type="text" placeholder="https://example.com"
                    class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
                </div>
                <div class="flex gap-3">
                  <div class="flex-1">
                    <label class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Campaign Name</label>
                    <input v-model="newForm.campaign_name" type="text" placeholder="Pentest Week"
                      class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
                  </div>
                  <div class="flex-1">
                    <label class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Description</label>
                    <input v-model="newForm.campaign_description" type="text" placeholder="Optional"
                      class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
                  </div>
                </div>
              </div>
            </details>

            <details class="bg-cyber-bg border border-cyber-border rounded-lg group">
              <summary class="px-4 py-3 text-cyber-accent font-bold text-sm cursor-pointer outline-none select-none flex items-center gap-2">
                <span class="text-cyber-muted-2">&#9654;</span> Profile
              </summary>
              <div class="px-4 pb-4 pt-2 border-t border-cyber-border space-y-3">
                <div class="grid grid-cols-2 gap-2.5">
                  <label v-for="p in profileDefs" :key="p.key"
                    class="flex flex-col items-center gap-1 bg-cyber-surface border-2 rounded-lg p-3 text-center cursor-pointer transition-all"
                    :class="scanProfile === p.key ? 'border-cyber-accent bg-cyber-surface-2' : 'border-cyber-border hover:border-cyber-accent'">
                    <input type="radio" v-model="scanProfile" :value="p.key" class="absolute opacity-0 pointer-events-none" />
                    <div class="text-cyber-text font-bold text-xs">{{ p.title }}</div>
                    <div class="text-cyber-muted-2 text-[10px] leading-tight">{{ p.desc }}</div>
                    <span class="text-[9px] uppercase tracking-wider px-2 py-0.5 rounded mt-1" :class="badgeClass(p.key)">{{ p.badge }}</span>
                  </label>
                </div>
              </div>
            </details>

            <details class="bg-cyber-bg border border-cyber-border rounded-lg group">
              <summary @click="expandScanners" class="px-4 py-3 text-cyber-accent font-bold text-sm cursor-pointer outline-none select-none flex items-center gap-2">
                <span class="text-cyber-muted-2">&#9654;</span> Scanners
                <span v-if="newForm.enabled_scanners.length" class="ml-auto text-[10px] text-cyber-muted-2 bg-cyber-surface px-2 py-0.5 rounded">{{ newForm.enabled_scanners.length }} selected</span>
              </summary>
              <div v-if="scannersLoaded" class="px-4 pb-4 pt-2 border-t border-cyber-border space-y-3">
                <input v-model="scannerSearch" type="text" placeholder="Search scanners..."
                  class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3 py-2 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
                <div v-for="(group, cat) in filteredScannerGroups" :key="cat">
                  <div class="text-cyber-muted-2 text-[10px] uppercase tracking-wider mb-1.5">{{ cat }}</div>
                  <div class="flex flex-wrap gap-2">
                    <label v-for="m in group" :key="m.name"
                      class="flex items-center gap-1.5 px-2.5 py-1.5 rounded border cursor-pointer text-xs transition-colors"
                      :class="newForm.enabled_scanners.includes(m.name) ? 'border-cyber-accent bg-cyber-accent/10 text-cyber-accent' : 'border-cyber-border bg-cyber-bg text-cyber-muted hover:border-cyber-accent/40'">
                      <input type="checkbox" :value="m.name" v-model="newForm.enabled_scanners" class="accent-cyber-accent" />
                      {{ m.name }}
                    </label>
                  </div>
                </div>
                <div class="flex gap-2 mt-1">
                  <button type="button" @click="selectAllScanners"
                    class="text-[10px] px-2 py-1 rounded bg-cyber-bg border border-cyber-border text-cyber-muted hover:text-cyber-accent transition-colors cursor-pointer">Select All</button>
                  <button type="button" @click="deselectAllScanners"
                    class="text-[10px] px-2 py-1 rounded bg-cyber-bg border border-cyber-border text-cyber-muted hover:text-cyber-accent transition-colors cursor-pointer">Deselect All</button>
                </div>
              </div>
              <div v-else class="px-4 pb-4 pt-2 border-t border-cyber-border">
                <div class="text-cyber-muted-2 text-xs text-center py-3">Loading scanners...</div>
              </div>
            </details>

            <details class="bg-cyber-bg border border-cyber-border rounded-lg group">
              <summary class="px-4 py-3 text-cyber-accent font-bold text-sm cursor-pointer outline-none select-none flex items-center gap-2">
                <span class="text-cyber-muted-2">&#9654;</span> Auth
              </summary>
              <div class="px-4 pb-4 pt-2 border-t border-cyber-border space-y-3">
                <div class="w-full">
                  <select v-model="newForm.auth_type"
                    class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3 py-2 rounded text-sm outline-none focus:border-cyber-accent transition-colors cursor-pointer">
                    <option value="none">None</option>
                    <option value="cookie">Cookie</option>
                    <option value="bearer">Bearer Token</option>
                    <option value="header">Custom Header</option>
                    <option value="basic">Basic Auth</option>
                  </select>
                </div>
                <div v-if="newForm.auth_type === 'cookie'">
                  <label class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Cookie String</label>
                  <input v-model="newForm.auth_cookie_string" type="text" placeholder="session=abc123; token=xyz"
                    class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
                </div>
                <div v-if="newForm.auth_type === 'bearer'">
                  <label class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Bearer Token</label>
                  <input v-model="newForm.auth_bearer_token" type="text" placeholder="eyJhbGci..."
                    class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
                </div>
                <div v-if="newForm.auth_type === 'header'" class="flex gap-3">
                  <div class="flex-1">
                    <label class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Header Key</label>
                    <input v-model="newForm.auth_header_key" type="text" placeholder="X-API-Key"
                      class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
                  </div>
                  <div class="flex-1">
                    <label class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Header Value</label>
                    <input v-model="newForm.auth_header_value" type="text" placeholder="YourValue123"
                      class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
                  </div>
                </div>
                <div v-if="newForm.auth_type === 'basic'" class="flex gap-3">
                  <div class="flex-1">
                    <label class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Username</label>
                    <input v-model="newForm.auth_basic_username" type="text" placeholder="admin"
                      class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
                  </div>
                  <div class="flex-1">
                    <label class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Password</label>
                    <input v-model="newForm.auth_basic_password" type="password" placeholder="********"
                      class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
                  </div>
                </div>
              </div>
            </details>

            <details class="bg-cyber-bg border border-cyber-border rounded-lg group">
              <summary class="px-4 py-3 text-cyber-accent font-bold text-sm cursor-pointer outline-none select-none flex items-center gap-2">
                <span class="text-cyber-muted-2">&#9654;</span> Advanced
              </summary>
              <div class="px-4 pb-4 pt-2 border-t border-cyber-border space-y-3">
                <div class="flex items-center gap-3 flex-wrap">
                  <label class="flex items-center gap-1.5 cursor-pointer bg-cyber-surface border border-cyber-border rounded px-3 py-2 hover:border-cyber-accent transition-colors">
                    <input type="checkbox" v-model="newForm.enable_llm" class="accent-cyber-accent" />
                    <span class="text-cyber-text text-xs">Enable LLM Analysis</span>
                  </label>
                  <label class="flex items-center gap-1.5 cursor-pointer bg-cyber-surface border border-cyber-border rounded px-3 py-2 hover:border-cyber-accent transition-colors">
                    <input type="checkbox" v-model="newForm.enable_proxy" class="accent-cyber-accent" />
                    <span class="text-cyber-text text-xs">Proxy Chain</span>
                  </label>
                </div>
                <div class="flex gap-3">
                  <div class="w-24">
                    <label class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Threads</label>
                    <input v-model.number="newForm.threads" type="number" min="1" max="100"
                      class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3 py-2 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
                  </div>
                  <div class="w-24">
                    <label class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Timeout</label>
                    <input v-model.number="newForm.timeout" type="number" min="5" max="120"
                      class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3 py-2 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
                  </div>
                  <div class="flex-1">
                    <label class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Rate Limit</label>
                    <input v-model.number="newForm.rate_limit" type="number" min="0" placeholder="requests/sec"
                      class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3 py-2 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
                  </div>
                </div>
                <div>
                  <label class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Schedule (cron)</label>
                  <input v-model="newForm.schedule" type="text" placeholder="0 2 * * * (optional)"
                    class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
                </div>
              </div>
            </details>

            <button @click="handleStartScan" :disabled="submitting"
              class="w-full bg-cyber-accent text-cyber-bg font-bold py-3.5 rounded text-base cursor-pointer hover:bg-[#00b8d4] transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
              {{ submitting ? 'Starting Scan...' : 'Start Scan' }}
            </button>
          </div>
        </div>
      </div>
    </transition>
  </div>
</template>

<script setup>
import { ref, reactive, computed, watch, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useScanStore } from '../store/scanStore'
import axios from 'axios'

const store = useScanStore()
const router = useRouter()
const API = ''

const activeNav = ref('dashboard')
const showPanel = ref(false)
const submitting = ref(false)
const scannerSearch = ref('')
const scannerCategoryFilter = ref('')
const historySearch = ref('')

const scannerManifests = ref([])
const scannersLoaded = ref(false)

const navItems = [
  { key: 'dashboard', icon: '\u25c9', label: 'Dashboard' },
  { key: 'newScan', icon: '\u2795', label: 'New Scan' },
  { key: 'templates', icon: '\ud83d\udccb', label: 'Templates' },
  { key: 'history', icon: '\ud83d\udd50', label: 'History' },
  { key: 'scannerConfig', icon: '\u2699\ufe0f', label: 'Scanner Config' },
]

const PROFILES = {
  quick:   { scan_mode: 'light',   crawl_depth: 0, threads: 10, timeout: 30,   xss_mode: 'probe',  enable_llm: false, enable_llm_payloads: false, detection_mode: 'detect' },
  standard:{ scan_mode: 'full',    crawl_depth: 1, threads: 25, timeout: 30,   xss_mode: 'probe',  enable_llm: true,  enable_llm_payloads: false, detection_mode: 'detect' },
  deep:    { scan_mode: 'full',    crawl_depth: 2, threads: 50, timeout: 60,   xss_mode: 'exploit', enable_llm: true,  enable_llm_payloads: true,  detection_mode: 'confirm' },
}

const profileDefs = [
  { key: 'quick',    title: 'Quick',     desc: 'Light scan, no crawl',      badge: 'fast' },
  { key: 'standard', title: 'Standard',  desc: 'Full scan, depth 1, LLM',    badge: 'balanced' },
  { key: 'deep',     title: 'Deep',      desc: 'Full scan, depth 2, LLM+',   badge: 'thorough' },
  { key: 'custom',   title: 'Custom',    desc: 'Fine-tune every setting',    badge: 'manual' },
]

const scanProfile = ref('standard')

const newForm = reactive({
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
  rate_limit: 0,
  schedule: '',
})

watch(scanProfile, (profile) => {
  if (profile !== 'custom') {
    const p = PROFILES[profile]
    if (p) Object.assign(newForm, p)
  }
})

const campaigns = computed(() => store.campaigns)

const countCards = computed(() => {
  const items = store.campaigns || []
  const active = items.filter(c => c.status === 'running' || c.status === 'scanning').length
  const queued = items.filter(c => c.status === 'queued' || c.status === 'pending').length
  const completed = items.filter(c => c.status === 'completed').length
  const failed = items.filter(c => c.status === 'failed').length
  const scheduled = items.filter(c => c.status === 'scheduled').length
  return [
    { label: 'Active', count: active, border: 'border-l-cyber-accent', textClass: 'text-cyber-accent' },
    { label: 'Queue', count: queued, border: 'border-l-cyber-warning', textClass: 'text-cyber-warning' },
    { label: 'Done', count: completed, border: 'border-l-cyber-success', textClass: 'text-cyber-success' },
    { label: 'Fail', count: failed, border: 'border-l-cyber-danger', textClass: 'text-cyber-danger' },
    { label: 'Sched', count: scheduled, border: 'border-l-cyber-medium', textClass: 'text-cyber-medium' },
  ]
})

const activeScans = computed(() => {
  const items = store.campaigns || []
  return items.filter(c => c.status === 'running' || c.status === 'scanning' || c.status === 'queued')
})

const filteredCampaigns = computed(() => {
  const items = store.campaigns || []
  if (!historySearch.value) return items
  const q = historySearch.value.toLowerCase()
  return items.filter(c => (c.name || '').toLowerCase().includes(q))
})

const scannerGroups = computed(() => {
  const groups = {}
  for (const m of scannerManifests.value) {
    const cat = m.category || 'other'
    if (!groups[cat]) groups[cat] = []
    groups[cat].push(m)
  }
  return groups
})

const filteredScannerGroups = computed(() => {
  const q = scannerSearch.value.toLowerCase()
  const groups = {}
  for (const [cat, items] of Object.entries(scannerGroups.value)) {
    const filtered = q ? items.filter(m => m.name.toLowerCase().includes(q)) : items
    if (filtered.length) groups[cat] = filtered
  }
  return groups
})

const scannerCategories = computed(() => {
  const cats = new Set()
  for (const m of scannerManifests.value) {
    if (m.category) cats.add(m.category)
  }
  return [...cats].sort()
})

const filteredScanners = computed(() => {
  let items = scannerManifests.value
  if (scannerCategoryFilter.value) {
    items = items.filter(s => s.category === scannerCategoryFilter.value)
  }
  return items
})

const templates = ref([])

function loadTemplates() {
  try {
    const raw = localStorage.getItem('uxhub_templates')
    templates.value = raw ? JSON.parse(raw) : []
  } catch { templates.value = [] }
}

function saveTemplates() {
  localStorage.setItem('uxhub_templates', JSON.stringify(templates.value))
}

function saveCurrentAsTemplate() {
  const name = prompt('Template name:')
  if (!name) return
  const t = {
    name,
    description: prompt('Template description (optional):') || '',
    config: { ...newForm },
  }
  templates.value.push(t)
  saveTemplates()
}

function loadTemplate(t) {
  if (t.config) Object.assign(newForm, t.config)
  if (t.config.url) newForm.url = t.config.url
  showPanel.value = true
}

function deleteTemplate(i) {
  templates.value.splice(i, 1)
  saveTemplates()
}

function badgeClass(key) {
  return {
    quick: 'bg-green-900 text-green-400',
    standard: 'bg-cyan-900 text-cyber-accent',
    deep: 'bg-red-900 text-red-400',
    custom: 'bg-purple-900 text-purple-300',
  }[key] || ''
}

function riskBadgeClass(level) {
  const map = {
    critical: 'bg-red-900 text-red-400',
    high: 'bg-orange-900 text-orange-400',
    medium: 'bg-yellow-900 text-yellow-400',
    low: 'bg-green-900 text-green-400',
    info: 'bg-blue-900 text-blue-400',
  }
  return map[(level || '').toLowerCase()] || 'bg-cyber-border text-cyber-muted'
}

function scanProgress(s) {
  if (s.progress != null) return Math.min(Math.round(s.progress * 100), 100)
  return Math.min(Math.floor(Math.random() * 40) + 30, 95)
}

function progressBarClass(s) {
  const p = scanProgress(s)
  if (p >= 80) return 'bg-cyber-success'
  if (p >= 40) return 'bg-cyber-accent'
  return 'bg-cyber-warning'
}

function viewScan(s) {
  router.push('/scan/' + (s.session_id || s.id))
}

async function abortScan(s) {
  const sid = s.session_id || s.id
  if (!sid) return
  if (!confirm('Abort this scan?')) return
  try {
    await store.cancelScan(sid)
  } catch (e) {
    console.error('Failed to abort scan:', e)
  }
}

function openNewScan() {
  activeNav.value = 'dashboard'
  showPanel.value = true
}

async function expandScanners() {
  if (!scannersLoaded.value && scannerManifests.value.length === 0) {
    try {
      const resp = await axios.get(`${API}/api/scanners`)
      scannerManifests.value = resp.data
      if (newForm.enabled_scanners.length === 0) {
        newForm.enabled_scanners = scannerManifests.value.map(m => m.name)
      }
      scannersLoaded.value = true
    } catch (e) {
      console.error('Failed to load scanners', e)
    }
  }
}

function selectAllScanners() {
  newForm.enabled_scanners = scannerManifests.value.map(m => m.name)
}

function deselectAllScanners() {
  newForm.enabled_scanners = []
}

async function handleStartScan() {
  if (!newForm.url) return
  submitting.value = true
  try {
    const payload = { ...newForm }
    delete payload.rate_limit
    delete payload.schedule
    const result = await store.startScan(payload)
    showPanel.value = false
    if (result.session_id) {
      router.push('/scan/' + result.session_id)
    } else if (result.campaign_id) {
      router.push('/campaign/' + result.campaign_id)
    }
  } catch (e) {
    console.error('Failed to start scan:', e)
  } finally {
    submitting.value = false
  }
}

onMounted(() => {
  store.fetchCampaigns()
  loadTemplates()
})
</script>

<style scoped>
.panel-slide-enter-active,
.panel-slide-leave-active {
  transition: all 0.3s ease;
}
.panel-slide-enter-active > div:last-child,
.panel-slide-leave-active > div:last-child {
  transition: transform 0.3s ease;
}
.panel-slide-enter > div:last-child,
.panel-slide-leave-to > div:last-child {
  transform: translateX(100%);
}
.panel-slide-enter > div:first-child,
.panel-slide-leave-to > div:first-child {
  opacity: 0;
}
</style>
