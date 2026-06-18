<template>
  <div class="findings-feed">
    <div v-if="findings.length === 0" class="empty">No findings yet.</div>
    <div v-for="f in sortedFindings" :key="f.id" class="finding-card">
      <div class="finding-header">
        <RiskBadge :severity="f.severity" :score="f.cvss_score" />
        <span class="finding-title">{{ f.title }}</span>
      </div>
      <div class="finding-meta">
        Scanner: {{ f.scanner_name }} &middot;
        Confidence: {{ (f.confidence * 100).toFixed(0) }}%
        <span v-if="f.is_llm_enhanced" class="llm-badge">LLM</span>
      </div>
      <div class="finding-desc">{{ f.description }}</div>
      <div v-if="f.remediation" class="finding-remediation">
        <strong>Remediation:</strong> {{ f.remediation }}
      </div>
      <div v-if="expanded === f.id" class="finding-evidence">
        <EvidenceViewer :evidence="f.evidence" :scanner-name="f.scanner_name" />
      </div>
      <div class="finding-actions">
        <button v-if="hasEvidence(f)" class="expand-btn" @click="toggleExpand(f.id)">
          {{ expanded === f.id ? 'Hide' : 'Show' }} Evidence
        </button>
        <button class="llm-btn" :disabled="llmLoading === f.id" @click="runLlmAnalysis(f.id)">
          {{ llmLoading === f.id ? 'Analyzing...' : 'LLM Analyze' }}
        </button>
      </div>
      <div v-if="llmResults[f.id]" class="llm-analysis-block">
        <div class="llm-section" v-if="llmResults[f.id].technical_impact">
          <div class="llm-section-title">Technical Impact</div>
          <div class="llm-section-body">{{ llmResults[f.id].technical_impact }}</div>
        </div>
        <div class="llm-section" v-if="llmResults[f.id].exploitation_path">
          <div class="llm-section-title">Exploitation Path</div>
          <div class="llm-section-body">{{ llmResults[f.id].exploitation_path }}</div>
        </div>
        <div class="llm-section" v-if="llmResults[f.id].remediation">
          <div class="llm-section-title">Remediation</div>
          <div class="llm-section-body">{{ llmResults[f.id].remediation }}</div>
        </div>
        <div class="llm-section" v-if="llmResults[f.id].chaining_potential">
          <div class="llm-section-title">Chaining Potential</div>
          <div class="llm-section-body">{{ llmResults[f.id].chaining_potential }}</div>
        </div>
        <div class="llm-section" v-if="llmResults[f.id].analyst_confidence">
          <div class="llm-section-title">Analyst Confidence</div>
          <div class="llm-section-body">{{ llmResults[f.id].analyst_confidence }}</div>
        </div>
        <div v-if="llmResults[f.id].error" class="llm-error">{{ llmResults[f.id].error }}</div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, reactive } from 'vue'
import { useScanStore } from '../store/scanStore'
import RiskBadge from './RiskBadge.vue'
import EvidenceViewer from './EvidenceViewer.vue'

const props = defineProps({ findings: { type: Array, default: () => [] } })
const store = useScanStore()
const expanded = ref(null)
const llmLoading = ref(null)
const llmResults = reactive({})

const sortedFindings = computed(() => {
  return [...props.findings].sort((a, b) => (b.cvss_score || 0) - (a.cvss_score || 0))
})

function hasEvidence(f) { return f.evidence && Object.keys(f.evidence).length > 0 }
function toggleExpand(id) { expanded.value = expanded.value === id ? null : id }

async function runLlmAnalysis(findingId) {
  llmLoading.value = findingId
  llmResults[findingId] = null
  try {
    const sessionId = props.findings[0]?.session_id
    if (!sessionId) throw new Error('No session ID')
    const result = await store.analyzeFinding(sessionId, findingId)
    llmResults[findingId] = result
  } catch (e) {
    llmResults[findingId] = { error: e.message }
  } finally {
    llmLoading.value = null
  }
}
</script>

<style scoped>
.findings-feed { display: flex; flex-direction: column; gap: 12px; }
.empty { color: #556677; text-align: center; padding: 20px; }
.finding-card {
  background: #0f1a2e; border-radius: 6px; padding: 15px;
  border-left: 4px solid #1e3a5f;
}
.finding-header { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
.finding-title { color: #e0e0e0; font-weight: bold; font-size: 0.95em; }
.finding-meta { color: #8899aa; font-size: 0.8em; margin-bottom: 8px; }
.llm-badge { background: #7c4dff; color: #fff; padding: 1px 8px; border-radius: 8px; font-size: 0.8em; margin-left: 5px; }
.finding-desc { color: #b0b0b0; font-size: 0.85em; line-height: 1.5; }
.finding-remediation { color: #00e5ff; font-size: 0.85em; margin-top: 8px; }
.finding-evidence { margin-top: 10px; }
.finding-actions { display: flex; gap: 8px; margin-top: 8px; }
.expand-btn, .llm-btn {
  background: none; border: 1px solid #1e3a5f; color: #8899aa;
  padding: 4px 12px; border-radius: 4px; font-size: 0.8em; cursor: pointer;
}
.expand-btn:hover { color: #00e5ff; border-color: #00e5ff; }
.llm-btn { border-color: #7c4dff; color: #b388ff; }
.llm-btn:hover { background: #7c4dff; color: #fff; }
.llm-btn:disabled { opacity: 0.5; cursor: not-allowed; }
.llm-analysis-block {
  margin-top: 10px; background: #0a0e17; border: 1px solid #7c4dff;
  border-radius: 6px; padding: 12px; display: flex; flex-direction: column; gap: 10px;
}
.llm-section { }
.llm-section-title { color: #b388ff; font-size: 0.75em; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 4px; font-weight: bold; }
.llm-section-body { color: #b0b0b0; font-size: 0.82em; line-height: 1.6; white-space: pre-wrap; }
.llm-error { color: #ff1744; font-size: 0.85em; }
</style>
