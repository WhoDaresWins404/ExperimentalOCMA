<template>
  <div class="flex flex-col gap-3">
    <div v-if="findings.length === 0" class="text-cyber-muted-2 text-center py-5">No findings yet.</div>
    <div v-for="f in sortedFindings" :key="f.id" class="bg-cyber-surface-2 rounded-lg p-4 border-l-4" :class="severityBorder(f.severity)">
      <div class="flex items-center gap-2.5 mb-2">
        <RiskBadge :severity="f.severity" :score="f.cvss_score" />
        <span class="text-cyber-text font-bold text-sm">{{ f.title }}</span>
      </div>
      <div class="text-cyber-muted text-xs mb-2 flex items-center gap-1.5">
        Scanner: {{ f.scanner_name }} &middot; Confidence: {{ (f.confidence * 100).toFixed(0) }}%
        <span v-if="f.is_llm_enhanced" class="bg-cyber-llm text-white px-2 py-0.5 rounded text-xs">LLM</span>
      </div>
      <div class="text-cyber-text text-sm leading-relaxed opacity-80">{{ f.description }}</div>
      <div v-if="f.remediation" class="text-cyber-accent text-sm mt-2">
        <strong>Remediation:</strong> {{ f.remediation }}
      </div>
      <div v-if="expanded === f.id" class="mt-2.5">
        <EvidenceViewer :evidence="f.evidence" :scanner-name="f.scanner_name" />
      </div>
      <div class="flex gap-2 mt-2">
        <button v-if="hasEvidence(f)" @click="toggleExpand(f.id)"
          class="bg-transparent border border-cyber-border text-cyber-muted px-3 py-1 rounded text-xs cursor-pointer hover:text-cyber-accent hover:border-cyber-accent transition-colors">
          {{ expanded === f.id ? 'Hide' : 'Show' }} Evidence
        </button>
        <button :disabled="llmLoading === f.id" @click="runLlmAnalysis(f.id)"
          class="bg-transparent border border-cyber-llm text-cyber-llm-light px-3 py-1 rounded text-xs cursor-pointer hover:bg-cyber-llm hover:text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
          {{ llmLoading === f.id ? 'Analyzing...' : 'LLM Analyze' }}
        </button>
      </div>
      <div v-if="llmResults[f.id]" class="mt-2.5 bg-cyber-bg border border-cyber-llm rounded-lg p-3 flex flex-col gap-2.5">
        <div v-if="llmResults[f.id].technical_impact">
          <div class="text-cyber-llm-light text-xs uppercase tracking-wider font-bold mb-1">Technical Impact</div>
          <div class="text-cyber-text text-xs leading-relaxed whitespace-pre-wrap">{{ llmResults[f.id].technical_impact }}</div>
        </div>
        <div v-if="llmResults[f.id].exploitation_path">
          <div class="text-cyber-llm-light text-xs uppercase tracking-wider font-bold mb-1">Exploitation Path</div>
          <div class="text-cyber-text text-xs leading-relaxed whitespace-pre-wrap">{{ llmResults[f.id].exploitation_path }}</div>
        </div>
        <div v-if="llmResults[f.id].remediation">
          <div class="text-cyber-llm-light text-xs uppercase tracking-wider font-bold mb-1">Remediation</div>
          <div class="text-cyber-text text-xs leading-relaxed whitespace-pre-wrap">{{ llmResults[f.id].remediation }}</div>
        </div>
        <div v-if="llmResults[f.id].chaining_potential">
          <div class="text-cyber-llm-light text-xs uppercase tracking-wider font-bold mb-1">Chaining Potential</div>
          <div class="text-cyber-text text-xs leading-relaxed whitespace-pre-wrap">{{ llmResults[f.id].chaining_potential }}</div>
        </div>
        <div v-if="llmResults[f.id].analyst_confidence">
          <div class="text-cyber-llm-light text-xs uppercase tracking-wider font-bold mb-1">Analyst Confidence</div>
          <div class="text-cyber-text text-xs leading-relaxed whitespace-pre-wrap">{{ llmResults[f.id].analyst_confidence }}</div>
        </div>
        <div v-if="llmResults[f.id].error" class="text-cyber-danger text-xs">{{ llmResults[f.id].error }}</div>
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

function severityBorder(severity) {
  return {
    critical: 'border-cyber-danger',
    high: 'border-cyber-warning',
    medium: 'border-cyber-medium',
    low: 'border-cyber-accent',
  }[severity?.toLowerCase()] || 'border-cyber-border'
}

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
