<template>
  <div class="report-view">
    <Button icon="pi pi-arrow-left" label="Back" severity="secondary" text @click="$router.push('/dashboard')" class="back-btn" />
    <h1>Scan Report</h1>

    <div v-if="loading" class="loading-state">
      <ProgressSpinner />
      <p>Loading report...</p>
    </div>

    <Message v-else-if="error" severity="error" :closable="false">{{ error }}</Message>

    <div v-else class="report-content">
      <div class="summary-grid">
        <Card class="summary-card"><template #content><div class="number critical">{{ summary.critical_count }}</div><div class="label">Critical</div></template></Card>
        <Card class="summary-card"><template #content><div class="number high">{{ summary.high_count }}</div><div class="label">High</div></template></Card>
        <Card class="summary-card"><template #content><div class="number medium">{{ summary.medium_count }}</div><div class="label">Medium</div></template></Card>
        <Card class="summary-card"><template #content><div class="number low">{{ summary.low_count }}</div><div class="label">Low</div></template></Card>
        <Card class="summary-card"><template #content><div class="number">{{ summary.total_endpoints }}</div><div class="label">Endpoints</div></template></Card>
        <Card class="summary-card"><template #content><div class="number">{{ summary.total_findings }}</div><div class="label">Findings</div></template></Card>
      </div>

      <div class="actions">
        <Button label="Download HTML" icon="pi pi-download" severity="secondary" @click="downloadReport('html')" />
        <Button label="Download JSON" icon="pi pi-download" severity="secondary" @click="downloadReport('json')" />
        <Button label="View Map" icon="pi pi-sitemap" severity="info" @click="$router.push(`/map/${sessionId}`)" />
        <Button v-if="findings.length > 0" :label="llmLoading ? 'Analyzing...' : 'Generate Comprehensive LLM Analysis'" icon="pi pi-magic" severity="help" :loading="llmLoading" @click="runComprehensive" />
      </div>

      <Card class="section" v-if="summary.llm_summary && !comprehensiveResult">
        <template #title>LLM Comprehensive Analysis</template>
        <template #content>
          <LlmSummaryBlock :text="summary.llm_summary" />
        </template>
      </Card>

      <Card class="section" v-if="comprehensiveResult">
        <template #title>LLM Comprehensive Analysis</template>
        <template #content>
          <LlmSummaryBlock :text="comprehensiveResult" />
        </template>
      </Card>

      <Message v-if="comprehensiveError" severity="error" :closable="false">{{ comprehensiveError }}</Message>

      <Card class="section">
        <template #title>Findings ({{ findings.length }})</template>
        <template #content>
          <FindingsFeed :findings="findings" />
        </template>
      </Card>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { useScanStore } from '../store/scanStore'
import Button from 'primevue/button'
import Card from 'primevue/card'
import Message from 'primevue/message'
import ProgressSpinner from 'primevue/progressspinner'
import FindingsFeed from '../components/FindingsFeed.vue'
import LlmSummaryBlock from '../components/LlmSummaryBlock.vue'

const props = defineProps({ id: String })
const route = useRoute()
const store = useScanStore()
const sessionId = props.id || route.params.id
const loading = ref(true)
const error = ref(null)
const findings = ref([])
const summary = ref({})
const llmLoading = ref(false)
const comprehensiveResult = ref('')
const comprehensiveError = ref('')

onMounted(async () => {
  try {
    const result = await store.getScanResults(sessionId)
    findings.value = result.findings || []
    summary.value = result.session?.stats || result.session || {}
    if (!Array.isArray(findings.value)) findings.value = []
  } catch (e) {
    error.value = 'Failed to load report: ' + e.message
  } finally {
    loading.value = false
  }
})

function downloadReport(format) {
  window.open(`/api/scan/${sessionId}/report?format=${format}`, '_blank')
}

async function runComprehensive() {
  llmLoading.value = true
  comprehensiveError.value = ''
  comprehensiveResult.value = ''
  try {
    const result = await store.analyzeScan(sessionId)
    if (result.error) {
      comprehensiveError.value = result.error
    } else if (result.summary) {
      comprehensiveResult.value = result.summary
    }
  } catch (e) {
    comprehensiveError.value = e.message
  } finally {
    llmLoading.value = false
  }
}
</script>

<style scoped>
.report-view { padding: 1.25rem 0; }
.back-btn { margin-bottom: 1.25rem; }
h1 { color: var(--p-primary-color); margin-bottom: 1.25rem; }
.loading-state { text-align: center; padding: 2.5rem; color: var(--p-surface-300); display: flex; flex-direction: column; align-items: center; gap: 1rem; }
.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 0.9375rem; margin-bottom: 1.5625rem; }
.summary-card { text-align: center; }
.number { font-size: 2rem; font-weight: bold; }
.label { color: var(--p-surface-300); font-size: 0.8rem; text-transform: uppercase; margin-top: 0.3125rem; }
.actions { display: flex; gap: 0.625rem; margin-bottom: 1.5625rem; flex-wrap: wrap; }
.section { margin-bottom: 1.25rem; }
</style>
