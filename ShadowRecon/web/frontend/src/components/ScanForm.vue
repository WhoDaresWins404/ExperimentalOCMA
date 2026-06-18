<template>
  <form @submit.prevent="handleSubmit" class="scan-form">
    <div class="form-row">
      <div class="form-group">
        <label>Target URL</label>
        <input v-model="form.url" type="text" placeholder="https://example.com" required class="form-input" />
      </div>
    </div>

    <div class="form-row">
      <div class="form-group">
        <label>Campaign Name</label>
        <input v-model="form.campaign_name" type="text" placeholder="Pentest Week 2024" class="form-input" />
      </div>
      <div class="form-group">
        <label>Campaign Description</label>
        <input v-model="form.campaign_description" type="text" placeholder="Optional description" class="form-input" />
      </div>
    </div>

    <div class="profile-row">
      <label class="profile-card" :class="{ active: scanProfile === 'quick' }">
        <input type="radio" v-model="scanProfile" value="quick" />
        <div class="profile-title">Quick</div>
        <div class="profile-desc">Light scan, no crawl, &sim;5 min</div>
        <div class="profile-badge">fast</div>
      </label>
      <label class="profile-card" :class="{ active: scanProfile === 'standard' }">
        <input type="radio" v-model="scanProfile" value="standard" />
        <div class="profile-title">Standard</div>
        <div class="profile-desc">Full scan, depth 1, LLM critical+</div>
        <div class="profile-badge">balanced</div>
      </label>
      <label class="profile-card" :class="{ active: scanProfile === 'deep' }">
        <input type="radio" v-model="scanProfile" value="deep" />
        <div class="profile-title">Deep</div>
        <div class="profile-desc">Full scan, depth 2, LLM exploit, 50 threads</div>
        <div class="profile-badge">thorough</div>
      </label>
      <label class="profile-card" :class="{ active: scanProfile === 'custom' }">
        <input type="radio" v-model="scanProfile" value="custom" />
        <div class="profile-title">Custom</div>
        <div class="profile-desc">Fine-tune every setting</div>
        <div class="profile-badge">manual</div>
      </label>
    </div>

    <template v-if="scanProfile !== 'custom'">
      <details class="advanced-section">
        <summary class="advanced-summary">View Preset Settings</summary>
        <div class="preset-summary">
          <div class="summary-grid">
            <div class="summary-item"><span class="si-label">Scan Mode</span><span class="si-val">{{ form.scan_mode === 'full' ? 'Full' : form.scan_mode === 'light' ? 'Light' : 'WAF Only' }}</span></div>
            <div class="summary-item"><span class="si-label">Threads</span><span class="si-val">{{ form.threads }}</span></div>
            <div class="summary-item"><span class="si-label">Crawl Depth</span><span class="si-val">{{ form.crawl_depth }}</span></div>
            <div class="summary-item"><span class="si-label">XSS Mode</span><span class="si-val">{{ form.xss_mode === 'probe' ? 'Probe' : 'Exploit' }}</span></div>
            <div class="summary-item"><span class="si-label">LLM Analysis</span><span class="si-val">{{ form.enable_llm ? 'On' : 'Off' }}</span></div>
            <div class="summary-item"><span class="si-label">LLM Payloads</span><span class="si-val">{{ form.enable_llm_payloads ? 'On' : 'Off' }}</span></div>
          </div>
        </div>
      </details>

      <div class="form-row options-row">
        <label class="checkbox-label">
          <input v-model="form.enable_proxy" type="checkbox" />
          <span>Enable Proxy Chain</span>
        </label>
      </div>

      <div class="form-section-title">Authentication</div>
      <div class="form-row options-row">
        <div class="form-group small">
          <label>Auth Type</label>
          <select v-model="form.auth_type" class="form-input">
            <option value="none">None</option>
            <option value="cookie">Cookie</option>
            <option value="bearer">Bearer Token</option>
            <option value="header">Custom Header</option>
            <option value="basic">Basic Auth</option>
          </select>
        </div>
      </div>

      <div v-if="form.auth_type === 'cookie'" class="form-row">
        <div class="form-group">
          <label>Cookie String</label>
          <input v-model="form.auth_cookie_string" type="text" placeholder="session=abc123; token=xyz" class="form-input" />
        </div>
      </div>
      <div v-if="form.auth_type === 'bearer'" class="form-row">
        <div class="form-group">
          <label>Bearer Token</label>
          <input v-model="form.auth_bearer_token" type="text" placeholder="eyJhbGci..." class="form-input" />
        </div>
      </div>
      <div v-if="form.auth_type === 'header'" class="form-row">
        <div class="form-group small">
          <label>Header Key</label>
          <input v-model="form.auth_header_key" type="text" placeholder="X-API-Key" class="form-input" />
        </div>
        <div class="form-group small">
          <label>Header Value</label>
          <input v-model="form.auth_header_value" type="text" placeholder="YourValue123" class="form-input" />
        </div>
      </div>
      <div v-if="form.auth_type === 'basic'" class="form-row">
        <div class="form-group small">
          <label>Username</label>
          <input v-model="form.auth_basic_username" type="text" placeholder="admin" class="form-input" />
        </div>
        <div class="form-group small">
          <label>Password</label>
          <input v-model="form.auth_basic_password" type="password" placeholder="********" class="form-input" />
        </div>
      </div>
    </template>

    <template v-else>
      <details class="advanced-section" open>
        <summary class="advanced-summary">All Settings</summary>

        <div class="form-row options-row">
          <label class="checkbox-label">
            <input v-model="form.enable_proxy" type="checkbox" />
            <span>Enable Proxy Chain</span>
          </label>
          <label class="checkbox-label">
            <input v-model="form.enable_llm" type="checkbox" />
            <span>Enable LLM Analysis</span>
          </label>
          <button type="button" class="test-btn" :disabled="llmTesting" @click="testLlm">
            {{ llmTesting ? 'Testing...' : 'Test LLM' }}
          </button>
          <span v-if="llmResult" :class="['llm-status', llmResult.reachable ? (llmResult.model_found ? 'ok' : 'warn') : 'err']" :title="llmResult.error || ''">
            {{ llmResult.reachable && llmResult.model_found ? `LLM OK (${llmResult.model})` : (llmResult.error ? 'LLM: ' + llmResult.error : 'LLM unreachable') }}
          </span>
        </div>

        <div class="form-row options-row">
          <div class="form-group small">
            <label>Threads</label>
            <input v-model.number="form.threads" type="number" min="1" max="100" class="form-input" />
          </div>
          <div class="form-group small">
            <label>Timeout (s)</label>
            <input v-model.number="form.timeout" type="number" min="5" max="120" class="form-input" />
          </div>
          <div class="form-group small">
            <label>Detection Mode</label>
            <select v-model="form.detection_mode" class="form-input">
              <option value="detect">Detection</option>
              <option value="confirm">Confirmation</option>
            </select>
          </div>
        </div>

        <div class="form-section-title">Scan Mode</div>
        <div class="form-row options-row">
          <label class="radio-label">
            <input type="radio" v-model="form.scan_mode" value="full" />
            <span class="radio-title">Full Scan</span>
            <span class="radio-desc">All scanners, maximum coverage</span>
          </label>
          <label class="radio-label">
            <input type="radio" v-model="form.scan_mode" value="light" />
            <span class="radio-title">Light Scan</span>
            <span class="radio-desc">Directory + misconfig + crawl</span>
          </label>
          <label class="radio-label">
            <input type="radio" v-model="form.scan_mode" value="waf_only" />
            <span class="radio-title">WAF Only</span>
            <span class="radio-desc">Detect WAF, skip all other scans</span>
          </label>
        </div>

        <div class="form-section-title">Authentication</div>
        <div class="form-row options-row">
          <div class="form-group small">
            <label>Auth Type</label>
            <select v-model="form.auth_type" class="form-input">
              <option value="none">None</option>
              <option value="cookie">Cookie</option>
              <option value="bearer">Bearer Token</option>
              <option value="header">Custom Header</option>
              <option value="basic">Basic Auth</option>
            </select>
          </div>
        </div>

        <div v-if="form.auth_type === 'cookie'" class="form-row">
          <div class="form-group">
            <label>Cookie String</label>
            <input v-model="form.auth_cookie_string" type="text" placeholder="session=abc123; token=xyz" class="form-input" />
          </div>
        </div>
        <div v-if="form.auth_type === 'bearer'" class="form-row">
          <div class="form-group">
            <label>Bearer Token</label>
            <input v-model="form.auth_bearer_token" type="text" placeholder="eyJhbGci..." class="form-input" />
          </div>
        </div>
        <div v-if="form.auth_type === 'header'" class="form-row">
          <div class="form-group small">
            <label>Header Key</label>
            <input v-model="form.auth_header_key" type="text" placeholder="X-API-Key" class="form-input" />
          </div>
          <div class="form-group small">
            <label>Header Value</label>
            <input v-model="form.auth_header_value" type="text" placeholder="YourValue123" class="form-input" />
          </div>
        </div>
        <div v-if="form.auth_type === 'basic'" class="form-row">
          <div class="form-group small">
            <label>Username</label>
            <input v-model="form.auth_basic_username" type="text" placeholder="admin" class="form-input" />
          </div>
          <div class="form-group small">
            <label>Password</label>
            <input v-model="form.auth_basic_password" type="password" placeholder="********" class="form-input" />
          </div>
        </div>

        <div class="form-section-title">Crawling & XSS Detection</div>
        <div class="form-row options-row">
          <div class="form-group small">
            <label>Crawl Depth</label>
            <input v-model.number="form.crawl_depth" type="number" min="0" max="5" class="form-input" />
          </div>
          <div class="form-group small">
            <label>XSS Mode</label>
            <select v-model="form.xss_mode" class="form-input">
              <option value="probe">Probe Only (safe)</option>
              <option value="exploit">Exploit (LLM payloads)</option>
            </select>
          </div>
        </div>
        <div class="form-row options-row">
          <label class="checkbox-label" v-if="form.xss_mode === 'exploit'">
            <input v-model="form.enable_llm_payloads" type="checkbox" />
            <span>Enable LLM Payload Generation (opt-in, 120s timeout)</span>
          </label>
        </div>
      </details>
    </template>

    <button type="submit" class="submit-btn" :disabled="submitting">
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

<style scoped>
.scan-form { max-width: 700px; margin: 0 auto; }
.form-row { display: flex; gap: 15px; margin-bottom: 15px; }
.form-group { flex: 1; display: flex; flex-direction: column; }
.form-group.small { flex: 0 0 auto; min-width: 120px; }
.form-group label { color: #8899aa; font-size: 0.8em; margin-bottom: 5px; text-transform: uppercase; letter-spacing: 0.5px; }
.form-input {
  background: #0a0e17; border: 1px solid #1e3a5f; color: #e0e0e0;
  padding: 10px 14px; border-radius: 5px; font-size: 0.9em; width: 100%; box-sizing: border-box;
}
.form-input:focus { outline: none; border-color: #00e5ff; }
select.form-input { cursor: pointer; appearance: auto; }

.options-row { flex-wrap: wrap; align-items: center; }

.profile-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 20px; }
.profile-card {
  display: flex; flex-direction: column; align-items: center; gap: 4px;
  background: #111927; border: 2px solid #1e3a5f; border-radius: 8px;
  padding: 14px 10px; cursor: pointer; transition: all 0.2s; text-align: center;
  position: relative;
}
.profile-card:hover { border-color: #00e5ff; }
.profile-card.active { border-color: #00e5ff; background: #0a1a2a; }
.profile-card input { position: absolute; opacity: 0; pointer-events: none; }
.profile-title { color: #e0e0e0; font-weight: bold; font-size: 0.95em; }
.profile-desc { color: #556677; font-size: 0.7em; line-height: 1.3; }
.profile-badge {
  font-size: 0.6em; text-transform: uppercase; letter-spacing: 1px;
  padding: 2px 8px; border-radius: 4px; margin-top: 4px;
}
.profile-card:nth-child(1) .profile-badge { background: #1a3a1a; color: #69f0ae; }
.profile-card:nth-child(2) .profile-badge { background: #1a2a3a; color: #00e5ff; }
.profile-card:nth-child(3) .profile-badge { background: #3a1a1a; color: #ff5252; }
.profile-card:nth-child(4) .profile-badge { background: #2a1a3a; color: #b388ff; }

.preset-summary { padding: 5px 0; }
.summary-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.summary-item { display: flex; justify-content: space-between; padding: 6px 10px; background: #0a0e17; border-radius: 4px; }
.si-label { color: #556677; font-size: 0.8em; }
.si-val { color: #e0e0e0; font-size: 0.85em; font-weight: bold; }

.checkbox-label, .radio-label {
  display: flex; align-items: center; gap: 6px; cursor: pointer;
  background: #111927; border: 1px solid #1e3a5f; border-radius: 5px;
  padding: 8px 14px; transition: all 0.2s;
}
.checkbox-label:hover, .radio-label:hover { border-color: #00e5ff; }
.checkbox-label input, .radio-label input { accent-color: #00e5ff; }
.checkbox-label span { color: #e0e0e0; font-size: 0.85em; }
.radio-label { flex-direction: column; align-items: flex-start; gap: 2px; flex: 1; }
.radio-title { color: #e0e0e0; font-size: 0.85em; font-weight: bold; }
.radio-desc { color: #556677; font-size: 0.75em; }

.test-btn {
  background: #1e3a5f; border: none; color: #e0e0e0;
  padding: 8px 16px; border-radius: 5px; cursor: pointer; font-size: 0.8em;
}
.test-btn:hover { background: #2a4a7f; color: #00e5ff; }
.test-btn:disabled { opacity: 0.5; cursor: not-allowed; }
.llm-status { font-size: 0.8em; padding: 4px 10px; border-radius: 4px; }
.llm-status.ok { color: #00c853; background: #0a1f0a; }
.llm-status.warn { color: #ff9100; background: #1f170a; }
.llm-status.err { color: #ff1744; background: #1f0a0a; }

.submit-btn {
  background: #00e5ff; color: #0a0e17; border: none;
  padding: 14px 40px; border-radius: 5px; font-size: 1em; font-weight: bold;
  cursor: pointer; width: 100%; margin-top: 10px;
}
.submit-btn:hover { background: #00b8d4; }
.submit-btn:disabled { opacity: 0.5; cursor: not-allowed; }

.advanced-section {
  background: #111927; border: 1px solid #1e3a5f; border-radius: 8px;
  padding: 15px; margin-bottom: 15px;
}
.advanced-summary {
  color: #00e5ff; cursor: pointer; font-size: 0.9em; font-weight: bold;
  padding: 5px 0; outline: none;
}
.advanced-summary::-webkit-details-marker { color: #00e5ff; }
.advanced-section[open] > .advanced-summary { margin-bottom: 15px; padding-bottom: 10px; border-bottom: 1px solid #1e3a5f; }
.form-section-title { color: #556677; font-size: 0.75em; text-transform: uppercase; letter-spacing: 1px; margin: 15px 0 8px 0; }
</style>
