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
        {{ llmResult.reachable && llmResult.model_found
          ? `LLM OK (${llmResult.model})`
          : (llmResult.error ? 'LLM: ' + llmResult.error : 'LLM unreachable') }}
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

    <div class="form-row options-row">
      <label class="radio-label">
        <input type="radio" v-model="form.scan_mode" value="full" />
        <span class="radio-title">Full Scan</span>
        <span class="radio-desc">All scanners, maximum coverage</span>
      </label>
      <label class="radio-label">
        <input type="radio" v-model="form.scan_mode" value="light" />
        <span class="radio-title">Light Scan</span>
        <span class="radio-desc">Directory + misconfig scanners only</span>
      </label>
      <label class="radio-label">
        <input type="radio" v-model="form.scan_mode" value="waf_only" />
        <span class="radio-title">WAF Only</span>
        <span class="radio-desc">Detect WAF, skip all other scans</span>
      </label>
    </div>

    <button type="submit" class="submit-btn" :disabled="submitting">
      {{ submitting ? 'Starting Scan...' : 'Start Scan' }}
    </button>
  </form>
</template>

<script setup>
import { ref, reactive } from 'vue'

const emit = defineEmits(['start'])
const props = defineProps({ campaignId: String })
const submitting = ref(false)
const llmTesting = ref(false)
const llmResult = ref(null)

const API = ''

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
})

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
.scan-form { display: flex; flex-direction: column; gap: 15px; }
.form-row { display: flex; gap: 15px; flex-wrap: wrap; }
.form-group { flex: 1; min-width: 200px; }
.form-group.small { flex: 0 0 120px; }
.form-group label { display: block; color: #8899aa; font-size: 0.85em; margin-bottom: 5px; }
.form-input {
  width: 100%; background: #0a0e17; border: 1px solid #1e3a5f;
  color: #e0e0e0; padding: 10px 12px; border-radius: 5px;
  font-size: 0.95em; outline: none; transition: border-color 0.2s;
}
.form-input:focus { border-color: #00e5ff; }
select.form-input { cursor: pointer; }
.options-row { display: flex; gap: 20px; align-items: center; flex-wrap: wrap; }
.checkbox-label { display: flex; align-items: center; gap: 8px; color: #8899aa; cursor: pointer; }
.checkbox-label input[type="checkbox"] { accent-color: #00e5ff; width: 16px; height: 16px; }
.radio-label {
  display: flex; flex-direction: column; gap: 2px;
  background: #0a0e17; border: 1px solid #1e3a5f;
  border-radius: 6px; padding: 8px 14px; cursor: pointer;
  transition: all 0.2s; min-width: 140px;
}
.radio-label:hover { border-color: #00e5ff; }
.radio-label input[type="radio"] { accent-color: #00e5ff; margin-bottom: 4px; }
.radio-title { font-weight: bold; color: #e0e0e0; font-size: 0.9em; }
.radio-desc { font-size: 0.75em; color: #667788; }
.submit-btn {
  background: #00e5ff; color: #0a0e17; border: none;
  padding: 12px 30px; border-radius: 5px; font-weight: bold;
  font-size: 1em; cursor: pointer; transition: all 0.2s;
  align-self: flex-start;
}
.submit-btn:hover { background: #00b8d4; }
.submit-btn:disabled { background: #1e3a5f; color: #556677; cursor: not-allowed; }
.test-btn {
  background: #1a2a4a; color: #00e5ff; border: 1px solid #00e5ff;
  padding: 6px 14px; border-radius: 4px; font-size: 0.85em;
  cursor: pointer; transition: all 0.2s;
}
.test-btn:hover { background: #00e5ff; color: #0a0e17; }
.test-btn:disabled { opacity: 0.5; cursor: wait; }
.llm-status { font-size: 0.85em; font-weight: bold; }
.llm-status.ok { color: #4caf50; }
.llm-status.warn { color: #ff9800; }
.llm-status.err { color: #f44336; }
</style>
