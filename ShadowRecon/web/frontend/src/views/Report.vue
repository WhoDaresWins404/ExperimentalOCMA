<template>
  <div class="report-view">
    <button class="back-btn" @click="$router.push('/dashboard')">&larr; Back</button>
    <h1>Scan Report</h1>
    <div v-if="loading" class="loading">Loading report...</div>
    <div v-else-if="error" class="error">{{ error }}</div>
    <div v-else class="report-content">
      <div class="summary-grid">
        <div class="summary-card"><div class="number critical">{{ summary.critical_count }}</div><div class="label">Critical</div></div>
        <div class="summary-card"><div class="number high">{{ summary.high_count }}</div><div class="label">High</div></div>
        <div class="summary-card"><div class="number medium">{{ summary.medium_count }}</div><div class="label">Medium</div></div>
        <div class="summary-card"><div class="number low">{{ summary.low_count }}</div><div class="label">Low</div></div>
        <div class="summary-card"><div class="number">{{ summary.total_endpoints }}</div><div class="label">Endpoints</div></div>
        <div class="summary-card"><div class="number">{{ summary.total_findings }}</div><div class="label">Findings</div></div>
      </div>

      <div class="actions">
        <a :href="`/api/scan/${sessionId}/report?format=html`" class="btn" download>Download HTML</a>
        <a :href="`/api/scan/${sessionId}/report?format=json`" class="btn" download>Download JSON</a>
        <button @click="$router.push(`/map/${sessionId}`)" class="btn">View Map</button>
      </div>

      <div class="section" v-if="summary.llm_summary">
        <h2>LLM Executive Summary</h2>
        <p>{{ summary.llm_summary }}</p>
      </div>

      <div class="section">
        <h2>Findings ({{ findings.length }})</h2>
        <FindingsFeed :findings="findings" />
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { useScanStore } from '../store/scanStore'
import FindingsFeed from '../components/FindingsFeed.vue'

const props = defineProps({ id: String })
const route = useRoute()
const store = useScanStore()
const sessionId = props.id || route.params.id
const loading = ref(true)
const error = ref(null)
const findings = ref([])
const summary = ref({})

onMounted(async () => {
  try {
    const result = await store.getScanResults(sessionId)
    findings.value = result.findings || []
    summary.value = result.session?.stats || result.session || {}
    if (Array.isArray(findings.value)) {
    } else { findings.value = [] }
  } catch (e) {
    error.value = 'Failed to load report: ' + e.message
  } finally {
    loading.value = false
  }
})
</script>

<style scoped>
.report-view { padding: 20px 0; }
.back-btn { background: none; border: 1px solid #1e3a5f; color: #8899aa; padding: 8px 16px; border-radius: 5px; cursor: pointer; margin-bottom: 20px; }
.back-btn:hover { color: #00e5ff; border-color: #00e5ff; }
h1 { color: #00e5ff; margin-bottom: 20px; }
.loading, .error { text-align: center; padding: 40px; color: #8899aa; }
.error { color: #ff1744; }
.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 25px; }
.summary-card { background: #111927; border-radius: 8px; padding: 20px; border: 1px solid #1e3a5f; text-align: center; }
.summary-card .number { font-size: 2em; font-weight: bold; }
.summary-card .label { color: #8899aa; font-size: 0.8em; text-transform: uppercase; margin-top: 5px; }
.actions { display: flex; gap: 10px; margin-bottom: 25px; }
.btn {
  background: #1e3a5f; color: #e0e0e0; border: none;
  padding: 10px 20px; border-radius: 5px; cursor: pointer; text-decoration: none;
}
.btn:hover { background: #2a4a7f; color: #00e5ff; }
.section { background: #111927; border: 1px solid #1e3a5f; border-radius: 8px; padding: 25px; margin-bottom: 20px; }
.section h2 { color: #00e5ff; margin-bottom: 15px; }
</style>
