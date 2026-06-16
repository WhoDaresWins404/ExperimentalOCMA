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
        <pre>{{ JSON.stringify(f.evidence, null, 2) }}</pre>
      </div>
      <button v-if="hasEvidence(f)" class="expand-btn" @click="toggleExpand(f.id)">
        {{ expanded === f.id ? 'Hide' : 'Show' }} Evidence
      </button>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'
import RiskBadge from './RiskBadge.vue'

const props = defineProps({ findings: { type: Array, default: () => [] } })
const expanded = ref(null)

const sortedFindings = computed(() => {
  return [...props.findings].sort((a, b) => (b.cvss_score || 0) - (a.cvss_score || 0))
})

function hasEvidence(f) { return f.evidence && Object.keys(f.evidence).length > 0 }
function toggleExpand(id) { expanded.value = expanded.value === id ? null : id }
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
.finding-evidence pre {
  background: #0a0e17; padding: 12px; border-radius: 4px;
  font-size: 0.8em; overflow-x: auto; max-height: 200px; overflow-y: auto;
  color: #b0b0b0; white-space: pre-wrap;
}
.expand-btn {
  background: none; border: 1px solid #1e3a5f; color: #8899aa;
  padding: 4px 12px; border-radius: 4px; font-size: 0.8em;
  cursor: pointer; margin-top: 8px;
}
.expand-btn:hover { color: #00e5ff; border-color: #00e5ff; }
</style>
