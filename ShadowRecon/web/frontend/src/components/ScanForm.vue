<template>
  <form @submit.prevent="handleSubmit" class="scan-form">
    <div class="form-row">
      <div class="form-group">
        <label for="url">Target URL</label>
        <InputText id="url" v-model="form.url" placeholder="https://example.com" required fluid />
      </div>
    </div>

    <div class="form-row">
      <div class="form-group">
        <label for="campaign_name">Campaign Name</label>
        <InputText id="campaign_name" v-model="form.campaign_name" placeholder="Pentest Week 2024" fluid />
      </div>
      <div class="form-group">
        <label for="campaign_desc">Campaign Description</label>
        <InputText id="campaign_desc" v-model="form.campaign_description" placeholder="Optional description" fluid />
      </div>
    </div>

    <div class="profile-row">
      <label v-for="p in profileDefs" :key="p.key"
        :class="['profile-card', { active: scanProfile === p.key }]">
        <input type="radio" v-model="scanProfile" :value="p.key" class="profile-radio" />
        <div class="profile-title">{{ p.title }}</div>
        <div class="profile-desc">{{ p.desc }}</div>
        <div class="profile-badge" :class="'badge-' + p.key">{{ p.badge }}</div>
      </label>
    </div>

    <template v-if="scanProfile !== 'custom'">
      <Accordion class="settings-accordion">
        <AccordionPanel value="0">
          <AccordionHeader>View Preset Settings</AccordionHeader>
          <AccordionContent>
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
          </AccordionContent>
        </AccordionPanel>
      </Accordion>

      <div class="form-row options-row">
        <div class="flex align-items-center gap-2">
          <Checkbox v-model="form.enable_proxy" :binary="true" input-id="enable_proxy" />
          <label for="enable_proxy">Enable Proxy Chain</label>
        </div>
      </div>

      <div class="form-section-title">Authentication</div>
      <div class="form-row">
        <div class="form-group small">
          <label for="auth_type">Auth Type</label>
          <Select id="auth_type" v-model="form.auth_type" :options="authOptions" option-value="value" option-label="label" fluid />
        </div>
      </div>

      <div v-if="form.auth_type === 'cookie'" class="form-row">
        <div class="form-group">
          <label for="auth_cookie">Cookie String</label>
          <InputText id="auth_cookie" v-model="form.auth_cookie_string" placeholder="session=abc123; token=xyz" fluid />
        </div>
      </div>
      <div v-if="form.auth_type === 'bearer'" class="form-row">
        <div class="form-group">
          <label for="auth_bearer">Bearer Token</label>
          <InputText id="auth_bearer" v-model="form.auth_bearer_token" placeholder="eyJhbGci..." fluid />
        </div>
      </div>
      <div v-if="form.auth_type === 'header'" class="form-row">
        <div class="form-group small">
          <label for="auth_hdr_key">Header Key</label>
          <InputText id="auth_hdr_key" v-model="form.auth_header_key" placeholder="X-API-Key" fluid />
        </div>
        <div class="form-group small">
          <label for="auth_hdr_val">Header Value</label>
          <InputText id="auth_hdr_val" v-model="form.auth_header_value" placeholder="YourValue123" fluid />
        </div>
      </div>
      <div v-if="form.auth_type === 'basic'" class="form-row">
        <div class="form-group small">
          <label for="auth_basic_user">Username</label>
          <InputText id="auth_basic_user" v-model="form.auth_basic_username" placeholder="admin" fluid />
        </div>
        <div class="form-group small">
          <label for="auth_basic_pass">Password</label>
          <InputText id="auth_basic_pass" v-model="form.auth_basic_password" type="password" placeholder="********" fluid />
        </div>
      </div>
    </template>

    <template v-else>
      <Accordion :value="['0']" class="settings-accordion">
        <AccordionPanel value="0">
          <AccordionHeader>All Settings</AccordionHeader>
          <AccordionContent>
            <div class="form-row options-row">
              <div class="flex align-items-center gap-3">
                <div class="flex align-items-center gap-2">
                  <Checkbox v-model="form.enable_proxy" :binary="true" input-id="enable_proxy_c" />
                  <label for="enable_proxy_c">Enable Proxy Chain</label>
                </div>
                <div class="flex align-items-center gap-2">
                  <Checkbox v-model="form.enable_llm" :binary="true" input-id="enable_llm_c" />
                  <label for="enable_llm_c">Enable LLM Analysis</label>
                </div>
                <Button :label="llmTesting ? 'Testing...' : 'Test LLM'" severity="secondary" size="small" :loading="llmTesting" @click="testLlm" />
                <Tag v-if="llmResult" :severity="llmSeverity" :value="llmStatusText" :title="llmResult.error || ''" />
              </div>
            </div>

            <div class="form-row">
              <div class="form-group small">
                <label for="threads">Threads</label>
                <InputNumber id="threads" v-model="form.threads" :min="1" :max="100" fluid />
              </div>
              <div class="form-group small">
                <label for="timeout">Timeout (s)</label>
                <InputNumber id="timeout" v-model="form.timeout" :min="5" :max="120" fluid />
              </div>
              <div class="form-group small">
                <label for="detection_mode">Detection Mode</label>
                <Select id="detection_mode" v-model="form.detection_mode" :options="detectionModeOptions" option-value="value" option-label="label" fluid />
              </div>
            </div>

            <div class="form-section-title">Scan Mode</div>
            <div class="form-row scan-mode-row">
              <div v-for="m in scanModeOptions" :key="m.value" class="flex align-items-center gap-2 scan-mode-item">
                <RadioButton v-model="form.scan_mode" :value="m.value" :input-id="'sm_' + m.value" />
                <label :for="'sm_' + m.value">
                  <span class="radio-title">{{ m.label }}</span>
                  <span class="radio-desc">{{ m.desc }}</span>
                </label>
              </div>
            </div>

            <div class="form-section-title">Authentication</div>
            <div class="form-row">
              <div class="form-group small">
                <label for="auth_type_c">Auth Type</label>
                <Select id="auth_type_c" v-model="form.auth_type" :options="authOptions" option-value="value" option-label="label" fluid />
              </div>
            </div>

            <div v-if="form.auth_type === 'cookie'" class="form-row">
              <div class="form-group">
                <label for="auth_cookie_c">Cookie String</label>
                <InputText id="auth_cookie_c" v-model="form.auth_cookie_string" placeholder="session=abc123; token=xyz" fluid />
              </div>
            </div>
            <div v-if="form.auth_type === 'bearer'" class="form-row">
              <div class="form-group">
                <label for="auth_bearer_c">Bearer Token</label>
                <InputText id="auth_bearer_c" v-model="form.auth_bearer_token" placeholder="eyJhbGci..." fluid />
              </div>
            </div>
            <div v-if="form.auth_type === 'header'" class="form-row">
              <div class="form-group small">
                <label for="auth_hdr_key_c">Header Key</label>
                <InputText id="auth_hdr_key_c" v-model="form.auth_header_key" placeholder="X-API-Key" fluid />
              </div>
              <div class="form-group small">
                <label for="auth_hdr_val_c">Header Value</label>
                <InputText id="auth_hdr_val_c" v-model="form.auth_header_value" placeholder="YourValue123" fluid />
              </div>
            </div>
            <div v-if="form.auth_type === 'basic'" class="form-row">
              <div class="form-group small">
                <label for="auth_basic_user_c">Username</label>
                <InputText id="auth_basic_user_c" v-model="form.auth_basic_username" placeholder="admin" fluid />
              </div>
              <div class="form-group small">
                <label for="auth_basic_pass_c">Password</label>
                <InputText id="auth_basic_pass_c" v-model="form.auth_basic_password" type="password" placeholder="********" fluid />
              </div>
            </div>

            <div class="form-section-title">Crawling & XSS Detection</div>
            <div class="form-row">
              <div class="form-group small">
                <label for="crawl_depth">Crawl Depth</label>
                <InputNumber id="crawl_depth" v-model="form.crawl_depth" :min="0" :max="5" fluid />
              </div>
              <div class="form-group small">
                <label for="xss_mode">XSS Mode</label>
                <Select id="xss_mode" v-model="form.xss_mode" :options="xssModeOptions" option-value="value" option-label="label" fluid />
              </div>
            </div>
            <div class="form-row" v-if="form.xss_mode === 'exploit'">
              <div class="flex align-items-center gap-2">
                <Checkbox v-model="form.enable_llm_payloads" :binary="true" input-id="enable_llm_payloads" />
                <label for="enable_llm_payloads">Enable LLM Payload Generation (opt-in, 120s timeout)</label>
              </div>
            </div>
          </AccordionContent>
        </AccordionPanel>
      </Accordion>
    </template>

    <Button type="submit" :loading="submitting" label="Start Scan" class="submit-btn" />
  </form>
</template>

<script setup>
import { ref, reactive, watch, computed } from 'vue'
import InputText from 'primevue/inputtext'
import InputNumber from 'primevue/inputnumber'
import Select from 'primevue/select'
import Checkbox from 'primevue/checkbox'
import RadioButton from 'primevue/radiobutton'
import Button from 'primevue/button'
import Tag from 'primevue/tag'
import Accordion from 'primevue/accordion'
import AccordionPanel from 'primevue/accordionpanel'
import AccordionHeader from 'primevue/accordionheader'
import AccordionContent from 'primevue/accordioncontent'

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

const authOptions = [
  { label: 'None', value: 'none' },
  { label: 'Cookie', value: 'cookie' },
  { label: 'Bearer Token', value: 'bearer' },
  { label: 'Custom Header', value: 'header' },
  { label: 'Basic Auth', value: 'basic' },
]

const scanModeOptions = [
  { label: 'Full Scan', value: 'full', desc: 'All scanners, maximum coverage' },
  { label: 'Light Scan', value: 'light', desc: 'Directory + misconfig + crawl' },
  { label: 'WAF Only', value: 'waf_only', desc: 'Detect WAF, skip all other scans' },
]

const detectionModeOptions = [
  { label: 'Detection', value: 'detect' },
  { label: 'Confirmation', value: 'confirm' },
]

const xssModeOptions = [
  { label: 'Probe Only (safe)', value: 'probe' },
  { label: 'Exploit (LLM payloads)', value: 'exploit' },
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

const llmSeverity = computed(() => {
  if (!llmResult.value) return null
  if (llmResult.value.reachable && llmResult.value.model_found) return 'success'
  if (llmResult.value.reachable) return 'warn'
  return 'danger'
})

const llmStatusText = computed(() => {
  if (!llmResult.value) return ''
  if (llmResult.value.reachable && llmResult.value.model_found) return `LLM OK (${llmResult.value.model})`
  if (llmResult.value.error) return `LLM: ${llmResult.value.error}`
  return 'LLM unreachable'
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
.form-row { display: flex; gap: 0.9375rem; margin-bottom: 0.9375rem; }
.form-group { flex: 1; display: flex; flex-direction: column; gap: 0.3125rem; }
.form-group.small { flex: 0 0 auto; min-width: 120px; }
.form-group label { color: var(--p-surface-300); font-size: 0.8em; text-transform: uppercase; letter-spacing: 0.5px; }

.options-row { flex-wrap: wrap; align-items: center; }

.profile-row { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.625rem; margin-bottom: 1.25rem; }
.profile-card {
  display: flex; flex-direction: column; align-items: center; gap: 0.25rem;
  background: var(--p-surface-600); border: 2px solid var(--p-surface-500); border-radius: 8px;
  padding: 0.875rem 0.625rem; cursor: pointer; transition: all 0.2s; text-align: center;
  position: relative;
}
.profile-card:hover { border-color: var(--p-primary-color); }
.profile-card.active { border-color: var(--p-primary-color); background: var(--p-surface-700); }
.profile-radio { position: absolute; opacity: 0; pointer-events: none; }
.profile-title { color: var(--p-surface-100); font-weight: bold; font-size: 0.95em; }
.profile-desc { color: var(--p-surface-400); font-size: 0.7em; line-height: 1.3; }
.profile-badge {
  font-size: 0.6em; text-transform: uppercase; letter-spacing: 1px;
  padding: 2px 8px; border-radius: 4px; margin-top: 4px;
}
.badge-quick { background: #1a3a1a; color: #69f0ae; }
.badge-standard { background: #1a2a3a; color: var(--p-primary-color); }
.badge-deep { background: #3a1a1a; color: #ff5252; }
.badge-custom { background: #2a1a3a; color: #b388ff; }

.settings-accordion { margin-bottom: 0.9375rem; }

.preset-summary { padding: 0.3125rem 0; }
.summary-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; }
.summary-item { display: flex; justify-content: space-between; padding: 0.375rem 0.625rem; background: var(--p-surface-800); border-radius: 4px; }
.si-label { color: var(--p-surface-400); font-size: 0.8em; }
.si-val { color: var(--p-surface-100); font-size: 0.85em; font-weight: bold; }

.scan-mode-row { display: flex; gap: 0.625rem; }
.scan-mode-item {
  flex: 1; background: var(--p-surface-600); border: 1px solid var(--p-surface-500);
  border-radius: 5px; padding: 0.5rem 0.75rem; cursor: pointer;
}
.scan-mode-item:hover { border-color: var(--p-primary-color); }
.radio-title { color: var(--p-surface-100); font-size: 0.85em; font-weight: 600; display: block; }
.radio-desc { color: var(--p-surface-400); font-size: 0.75em; }

.form-section-title { color: var(--p-surface-400); font-size: 0.75em; text-transform: uppercase; letter-spacing: 1px; margin: 0.9375rem 0 0.5rem 0; }

.submit-btn { width: 100%; margin-top: 0.625rem; }

.flex { display: flex; }
.align-items-center { align-items: center; }
.gap-2 { gap: 0.5rem; }
.gap-3 { gap: 0.75rem; }
</style>
