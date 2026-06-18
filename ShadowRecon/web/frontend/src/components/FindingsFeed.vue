<template>
  <div class="findings-feed">
    <div v-if="findings.length === 0" class="empty">No findings yet.</div>
    <Card v-for="f in sortedFindings" :key="f.id" class="finding-card">
      <template #title>
        <div class="finding-header">
          <RiskBadge :severity="f.severity" :score="f.cvss_score" />
          <span class="finding-title">{{ f.title }}</span>
        </div>
      </template>
      <template #subtitle>
        <div class="finding-meta">
          Scanner: {{ f.scanner_name }} &middot;
          Confidence: {{ (f.confidence * 100).toFixed(0) }}%
          <Tag v-if="f.is_llm_enhanced" value="LLM" severity="info" class="llm-badge" />
        </div>
      </template>
      <template #content>
        <div class="finding-desc">{{ f.description }}</div>
        <div v-if="f.remediation" class="finding-remediation">
          <strong>Remediation:</strong> {{ f.remediation }}
        </div>
        <div v-if="expanded === f.id" class="finding-evidence">
          <EvidenceViewer :evidence="f.evidence" :scanner-name="f.scanner_name" />
        </div>
      </template>
      <template #footer>
        <div class="finding-actions">
          <Button v-if="hasEvidence(f)" :label="expanded === f.id ? 'Hide Evidence' : 'Show Evidence'" severity="secondary" size="small" @click="toggleExpand(f.id)" />
          <Button :label="llmLoading === f.id ? 'Analyzing...' : 'LLM Analyze'" severity="help" size="small" :loading="llmLoading === f.id" @click="runLlmAnalysis(f.id)" />
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
          <Message v-if="llmResults[f.id].error" severity="error" :closable="false">{{ llmResults[f.id].error }}</Message>
        </div>
      </template>
    </Card>
  </div>
</template>

<script setup>
import { ref, computed, reactive } from 'vue'
import { useScanStore } from '../store/scanStore'
import Card from 'primevue/card'
import Button from 'primevue/button'
import Tag from 'primevue/tag'
import Message from 'primevue/message'
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
.findings-feed { display: flex; flex-direction: column; gap: 0.75rem; }
.empty { color: var(--p-surface-400); text-align: center; padding: 1.25rem; }
.finding-card :deep(.p-card-title) { margin-bottom: 0.25rem; }
.finding-header { display: flex; align-items: center; gap: 0.5rem; }
.finding-title { color: var(--p-surface-100); font-weight: 600; font-size: 0.95rem; }
.finding-meta { display: flex; align-items: center; gap: 0.5rem; color: var(--p-surface-300); font-size: 0.8rem; }
.llm-badge { margin-left: 0.25rem; }
.finding-desc { color: var(--p-surface-200); font-size: 0.85rem; line-height: 1.5; }
.finding-remediation { color: var(--p-primary-color); font-size: 0.85rem; margin-top: 0.5rem; }
.finding-evidence { margin-top: 0.5rem; }
.finding-actions { display: flex; gap: 0.5rem; }
.llm-analysis-block {
  margin-top: 0.75rem; background: var(--p-surface-800); border: 1px solid var(--p-primary-400);
  border-radius: 6px; padding: 0.75rem; display: flex; flex-direction: column; gap: 0.625rem;
}
.llm-section-title { color: var(--p-primary-300); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 0.25rem; font-weight: 700; }
.llm-section-body { color: var(--p-surface-200); font-size: 0.82rem; line-height: 1.6; white-space: pre-wrap; }
</style>
