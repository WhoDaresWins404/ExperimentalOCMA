<template>
  <form @submit.prevent="handleSubmit" class="max-w-[700px] mx-auto space-y-4">
    <div>
      <label for="url" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Target URL</label>
      <input id="url" v-model="form.url" type="text" placeholder="https://example.com" required
        class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
    </div>

    <div class="flex gap-4">
      <div class="flex-1">
        <label for="campaign_name" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Campaign Name</label>
        <input id="campaign_name" v-model="form.campaign_name" type="text" placeholder="Pentest Week 2024"
          class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
      </div>
      <div class="flex-1">
        <label for="campaign_desc" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Campaign Description</label>
        <input id="campaign_desc" v-model="form.campaign_description" type="text" placeholder="Optional description"
          class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
      </div>
    </div>

    <div class="grid grid-cols-4 gap-2.5">
      <label v-for="p in profileDefs" :key="p.key"
        :class="['flex flex-col items-center gap-1 bg-cyber-surface border-2 rounded-lg p-3.5 text-center cursor-pointer transition-all relative', scanProfile === p.key ? 'border-cyber-accent bg-cyber-surface-2' : 'border-cyber-border hover:border-cyber-accent']">
        <input type="radio" v-model="scanProfile" :value="p.key" class="absolute opacity-0 pointer-events-none" />
        <div class="text-cyber-text font-bold text-sm">{{ p.title }}</div>
        <div class="text-cyber-muted-2 text-xs leading-tight">{{ p.desc }}</div>
        <div class="text-[0.6rem] uppercase tracking-wider px-2 py-0.5 rounded mt-1" :class="badgeClass(p.key)">{{ p.badge }}</div>
      </label>
    </div>

    <template v-if="scanProfile !== 'custom'">
      <details class="bg-cyber-surface border border-cyber-border rounded-lg p-4 group">
        <summary class="text-cyber-accent font-bold text-sm cursor-pointer outline-none select-none">View Preset Settings</summary>
        <div class="mt-4 pt-3 border-t border-cyber-border">
          <div class="grid grid-cols-2 gap-2">
            <div class="flex justify-between items-center bg-cyber-bg rounded px-2.5 py-1.5">
              <span class="text-cyber-muted-2 text-xs">Scan Mode</span>
              <span class="text-cyber-text text-xs font-bold">{{ form.scan_mode === 'full' ? 'Full' : form.scan_mode === 'light' ? 'Light' : 'WAF Only' }}</span>
            </div>
            <div class="flex justify-between items-center bg-cyber-bg rounded px-2.5 py-1.5">
              <span class="text-cyber-muted-2 text-xs">Threads</span>
              <span class="text-cyber-text text-xs font-bold">{{ form.threads }}</span>
            </div>
            <div class="flex justify-between items-center bg-cyber-bg rounded px-2.5 py-1.5">
              <span class="text-cyber-muted-2 text-xs">Crawl Depth</span>
              <span class="text-cyber-text text-xs font-bold">{{ form.crawl_depth }}</span>
            </div>
            <div class="flex justify-between items-center bg-cyber-bg rounded px-2.5 py-1.5">
              <span class="text-cyber-muted-2 text-xs">XSS Mode</span>
              <span class="text-cyber-text text-xs font-bold">{{ form.xss_mode === 'probe' ? 'Probe' : 'Exploit' }}</span>
            </div>
            <div class="flex justify-between items-center bg-cyber-bg rounded px-2.5 py-1.5">
              <span class="text-cyber-muted-2 text-xs">LLM Analysis</span>
              <span class="text-cyber-text text-xs font-bold">{{ form.enable_llm ? 'On' : 'Off' }}</span>
            </div>
            <div class="flex justify-between items-center bg-cyber-bg rounded px-2.5 py-1.5">
              <span class="text-cyber-muted-2 text-xs">LLM Payloads</span>
              <span class="text-cyber-text text-xs font-bold">{{ form.enable_llm_payloads ? 'On' : 'Off' }}</span>
            </div>
          </div>
        </div>
      </details>

      <div class="flex items-center gap-2 flex-wrap">
        <label class="flex items-center gap-1.5 cursor-pointer bg-cyber-surface border border-cyber-border rounded px-3.5 py-2 hover:border-cyber-accent transition-colors">
          <input type="checkbox" v-model="form.enable_proxy" class="accent-cyber-accent" />
          <span class="text-cyber-text text-sm">Enable Proxy Chain</span>
        </label>
      </div>

      <div class="text-cyber-muted-2 text-xs uppercase tracking-wider mt-4 mb-2">Authentication</div>
      <div class="w-48">
        <select v-model="form.auth_type"
          class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3 py-2 rounded text-sm outline-none focus:border-cyber-accent transition-colors cursor-pointer">
          <option value="none">None</option>
          <option value="cookie">Cookie</option>
          <option value="bearer">Bearer Token</option>
          <option value="header">Custom Header</option>
          <option value="basic">Basic Auth</option>
        </select>
      </div>

      <div v-if="form.auth_type === 'cookie'" class="flex gap-4">
        <div class="flex-1">
          <label for="auth_cookie" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Cookie String</label>
          <input id="auth_cookie" v-model="form.auth_cookie_string" type="text" placeholder="session=abc123; token=xyz"
            class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
        </div>
      </div>
      <div v-if="form.auth_type === 'bearer'" class="flex gap-4">
        <div class="flex-1">
          <label for="auth_bearer" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Bearer Token</label>
          <input id="auth_bearer" v-model="form.auth_bearer_token" type="text" placeholder="eyJhbGci..."
            class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
        </div>
      </div>
      <div v-if="form.auth_type === 'header'" class="flex gap-4">
        <div class="flex-1">
          <label for="auth_hdr_key" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Header Key</label>
          <input id="auth_hdr_key" v-model="form.auth_header_key" type="text" placeholder="X-API-Key"
            class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
        </div>
        <div class="flex-1">
          <label for="auth_hdr_val" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Header Value</label>
          <input id="auth_hdr_val" v-model="form.auth_header_value" type="text" placeholder="YourValue123"
            class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
        </div>
      </div>
      <div v-if="form.auth_type === 'basic'" class="flex gap-4">
        <div class="flex-1">
          <label for="auth_basic_user" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Username</label>
          <input id="auth_basic_user" v-model="form.auth_basic_username" type="text" placeholder="admin"
            class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
        </div>
        <div class="flex-1">
          <label for="auth_basic_pass" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Password</label>
          <input id="auth_basic_pass" v-model="form.auth_basic_password" type="password" placeholder="********"
            class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
        </div>
      </div>
    </template>

    <template v-else>
      <details open class="bg-cyber-surface border border-cyber-border rounded-lg p-4 group">
        <summary class="text-cyber-accent font-bold text-sm cursor-pointer outline-none select-none">All Settings</summary>
        <div class="mt-4 pt-3 border-t border-cyber-border space-y-4">
          <div class="flex items-center gap-3 flex-wrap">
            <label class="flex items-center gap-1.5 cursor-pointer bg-cyber-surface-2 border border-cyber-border rounded px-3.5 py-2 hover:border-cyber-accent transition-colors">
              <input type="checkbox" v-model="form.enable_proxy" class="accent-cyber-accent" />
              <span class="text-cyber-text text-sm">Enable Proxy Chain</span>
            </label>
            <label class="flex items-center gap-1.5 cursor-pointer bg-cyber-surface-2 border border-cyber-border rounded px-3.5 py-2 hover:border-cyber-accent transition-colors">
              <input type="checkbox" v-model="form.enable_llm" class="accent-cyber-accent" />
              <span class="text-cyber-text text-sm">Enable LLM Analysis</span>
            </label>
            <button type="button" :disabled="llmTesting" @click="testLlm"
              class="bg-cyber-surface-2 border border-cyber-border text-cyber-text px-3.5 py-2 rounded text-xs cursor-pointer hover:bg-cyber-surface hover:text-cyber-accent transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
              {{ llmTesting ? 'Testing...' : 'Test LLM' }}
            </button>
            <span v-if="llmResult"
              :class="['text-xs px-2.5 py-1 rounded', llmResult.reachable && llmResult.model_found ? 'bg-green-900 text-green-400' : llmResult.reachable ? 'bg-yellow-900 text-yellow-400' : 'bg-red-900 text-red-400']"
              :title="llmResult.error || ''">
              {{ llmResult.reachable && llmResult.model_found ? `LLM OK (${llmResult.model})` : (llmResult.error ? 'LLM: ' + llmResult.error : 'LLM unreachable') }}
            </span>
          </div>

          <div class="flex gap-4">
            <div class="w-28">
              <label for="threads" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Threads</label>
              <input id="threads" v-model.number="form.threads" type="number" min="1" max="100"
                class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3 py-2 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
            </div>
            <div class="w-28">
              <label for="timeout" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Timeout (s)</label>
              <input id="timeout" v-model.number="form.timeout" type="number" min="5" max="120"
                class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3 py-2 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
            </div>
            <div class="w-36">
              <label for="detection_mode" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Detection Mode</label>
              <select id="detection_mode" v-model="form.detection_mode"
                class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3 py-2 rounded text-sm outline-none focus:border-cyber-accent transition-colors cursor-pointer">
                <option value="detect">Detection</option>
                <option value="confirm">Confirmation</option>
              </select>
            </div>
          </div>

          <div class="text-cyber-muted-2 text-xs uppercase tracking-wider">Scan Mode</div>
          <div class="flex gap-2.5">
            <label v-for="m in scanModeOptions" :key="m.value"
              class="flex-1 flex flex-col gap-0.5 bg-cyber-surface-2 border border-cyber-border rounded px-3 py-2 cursor-pointer hover:border-cyber-accent transition-colors">
              <input type="radio" v-model="form.scan_mode" :value="m.value" class="accent-cyber-accent" />
              <span class="text-cyber-text text-sm font-bold">{{ m.label }}</span>
              <span class="text-cyber-muted-2 text-xs">{{ m.desc }}</span>
            </label>
          </div>

          <div class="text-cyber-muted-2 text-xs uppercase tracking-wider">Authentication</div>
          <div class="w-48">
            <select v-model="form.auth_type"
              class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3 py-2 rounded text-sm outline-none focus:border-cyber-accent transition-colors cursor-pointer">
              <option value="none">None</option>
              <option value="cookie">Cookie</option>
              <option value="bearer">Bearer Token</option>
              <option value="header">Custom Header</option>
              <option value="basic">Basic Auth</option>
            </select>
          </div>

          <div v-if="form.auth_type === 'cookie'" class="flex gap-4">
            <div class="flex-1">
              <label for="auth_cookie_c" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Cookie String</label>
              <input id="auth_cookie_c" v-model="form.auth_cookie_string" type="text" placeholder="session=abc123; token=xyz"
                class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
            </div>
          </div>
          <div v-if="form.auth_type === 'bearer'" class="flex gap-4">
            <div class="flex-1">
              <label for="auth_bearer_c" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Bearer Token</label>
              <input id="auth_bearer_c" v-model="form.auth_bearer_token" type="text" placeholder="eyJhbGci..."
                class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
            </div>
          </div>
          <div v-if="form.auth_type === 'header'" class="flex gap-4">
            <div class="flex-1">
              <label for="auth_hdr_key_c" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Header Key</label>
              <input id="auth_hdr_key_c" v-model="form.auth_header_key" type="text" placeholder="X-API-Key"
                class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
            </div>
            <div class="flex-1">
              <label for="auth_hdr_val_c" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Header Value</label>
              <input id="auth_hdr_val_c" v-model="form.auth_header_value" type="text" placeholder="YourValue123"
                class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
            </div>
          </div>
          <div v-if="form.auth_type === 'basic'" class="flex gap-4">
            <div class="flex-1">
              <label for="auth_basic_user_c" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Username</label>
              <input id="auth_basic_user_c" v-model="form.auth_basic_username" type="text" placeholder="admin"
                class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
            </div>
            <div class="flex-1">
              <label for="auth_basic_pass_c" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Password</label>
              <input id="auth_basic_pass_c" v-model="form.auth_basic_password" type="password" placeholder="********"
                class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
            </div>
          </div>

          <div class="text-cyber-muted-2 text-xs uppercase tracking-wider">Crawling &amp; XSS Detection</div>
          <div class="flex gap-4">
            <div class="w-28">
              <label for="crawl_depth" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Crawl Depth</label>
              <input id="crawl_depth" v-model.number="form.crawl_depth" type="number" min="0" max="5"
                class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3 py-2 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
            </div>
            <div class="w-52">
              <label for="xss_mode" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">XSS Mode</label>
              <select id="xss_mode" v-model="form.xss_mode"
                class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3 py-2 rounded text-sm outline-none focus:border-cyber-accent transition-colors cursor-pointer">
                <option value="probe">Probe Only (safe)</option>
                <option value="exploit">Exploit (LLM payloads)</option>
              </select>
            </div>
          </div>
          <div v-if="form.xss_mode === 'exploit'" class="flex items-center gap-2">
            <label class="flex items-center gap-1.5 cursor-pointer">
              <input type="checkbox" v-model="form.enable_llm_payloads" class="accent-cyber-accent" />
              <span class="text-cyber-text text-sm">Enable LLM Payload Generation (opt-in, 120s timeout)</span>
            </label>
          </div>
        </div>
      </details>
    </template>

    <button type="submit" :disabled="submitting"
      class="w-full bg-cyber-accent text-cyber-bg font-bold py-3.5 rounded text-base cursor-pointer hover:bg-[#00b8d4] transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
      {{ submitting ? 'Starting Scan...' : 'Start Scan' }}
    </button>
  </form>
</template>

<script setup>
import { ref, reactive, watch } from 'vue'

const emit = defineEmits(['start'])
const props = defineProps({ campaignId: String })
const submitting = ref(false)
const llmTesting = ref(false)
const llmResult = ref(null)

const API = ''

const PROFILES = {
  quick:   { scan_mode: 'light',   crawl_depth: 0, threads: 10, timeout: 30,   xss_mode: 'probe',  enable_llm: false, enable_llm_payloads: false, detection_mode: 'detect' },
  standard:{ scan_mode: 'full',    crawl_depth: 1, threads: 25, timeout: 30,   xss_mode: 'probe',  enable_llm: true,  enable_llm_payloads: false, detection_mode: 'detect' },
  deep:    { scan_mode: 'full',    crawl_depth: 2, threads: 50, timeout: 60,   xss_mode: 'exploit', enable_llm: true,  enable_llm_payloads: true,  detection_mode: 'confirm' },
}

const profileDefs = [
  { key: 'quick',    title: 'Quick',     desc: 'Light scan, no crawl, ~5 min',      badge: 'fast' },
  { key: 'standard', title: 'Standard',  desc: 'Full scan, depth 1, LLM critical+',  badge: 'balanced' },
  { key: 'deep',     title: 'Deep',      desc: 'Full scan, depth 2, LLM exploit',    badge: 'thorough' },
  { key: 'custom',   title: 'Custom',    desc: 'Fine-tune every setting',             badge: 'manual' },
]

const scanModeOptions = [
  { label: 'Full Scan', value: 'full', desc: 'All scanners, maximum coverage' },
  { label: 'Light Scan', value: 'light', desc: 'Directory + misconfig + crawl' },
  { label: 'WAF Only', value: 'waf_only', desc: 'Detect WAF, skip all other scans' },
]

const scanProfile = ref('standard')

const form = reactive({
  url: '',
  campaign_name: props.campaignId ? '' : 'default',
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
})

watch(scanProfile, (profile) => {
  if (profile !== 'custom') {
    const p = PROFILES[profile]
    if (p) Object.assign(form, p)
  }
})

function badgeClass(key) {
  return {
    quick: 'bg-green-900 text-green-400',
    standard: 'bg-cyan-900 text-cyber-accent',
    deep: 'bg-red-900 text-red-400',
    custom: 'bg-purple-900 text-purple-300',
  }[key] || ''
}

async function testLlm() {
  llmTesting.value = true
  llmResult.value = null
  try {
    const res = await fetch(`${API}/api/llm/check`)
    const data = await res.json()
    llmResult.value = data
  } catch (e) {
    llmResult.value = { reachable: false, error: e.message }
  } finally {
    llmTesting.value = false
  }
}

async function handleSubmit() {
  submitting.value = true
  try {
    emit('start', { ...form })
  } finally {
    submitting.value = false
  }
}
</script>
