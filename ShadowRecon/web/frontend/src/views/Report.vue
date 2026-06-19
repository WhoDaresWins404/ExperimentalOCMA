<template>
  <div class="py-5">
    <button @click="$router.push('/dashboard')"
      class="bg-transparent border border-cyber-border text-cyber-muted px-4 py-2 rounded cursor-pointer mb-5 hover:text-cyber-accent hover:border-cyber-accent transition-colors">
      &larr; Back
    </button>
    <h1 class="text-cyber-accent text-2xl font-bold mb-5">Scan Report</h1>

    <div v-if="loading" class="text-center py-10 text-cyber-muted">Loading report...</div>
    <div v-else-if="error" class="bg-red-900 border border-cyber-danger rounded-lg p-4 text-cyber-danger mb-5">{{ error }}</div>

    <div v-else>
      <div v-if="targetUrl" class="bg-cyber-surface border border-cyber-border rounded-lg p-4 mb-6">
        <div class="text-cyber-muted-2 text-xs uppercase tracking-wider mb-0.5">Target</div>
        <div class="text-cyber-text font-mono text-base break-all">{{ targetUrl }}</div>
      </div>

      <div class="grid grid-cols-[repeat(auto-fit,minmax(150px,1fr))] gap-4 mb-6">
        <div v-for="card in summaryCards" :key="card.key" class="bg-cyber-surface border border-cyber-border rounded-lg p-5 text-center">
          <div class="text-2xl font-bold" :class="card.color">{{ card.value }}</div>
          <div class="text-cyber-muted text-xs uppercase mt-1">{{ card.label }}</div>
        </div>
      </div>

      <div class="flex gap-2.5 mb-6 flex-wrap">
        <a :href="`/api/scan/${sessionId}/report?format=html`"
          class="bg-cyber-surface border border-cyber-border text-cyber-text px-5 py-2.5 rounded text-sm cursor-pointer no-underline hover:bg-cyber-surface-2 hover:text-cyber-accent transition-colors">Download HTML</a>
        <a :href="`/api/scan/${sessionId}/report?format=json`"
          class="bg-cyber-surface border border-cyber-border text-cyber-text px-5 py-2.5 rounded text-sm cursor-pointer no-underline hover:bg-cyber-surface-2 hover:text-cyber-accent transition-colors">Download JSON</a>
        <button @click="$router.push(`/map/${sessionId}`)"
          class="bg-cyber-surface border border-cyber-border text-cyber-text px-5 py-2.5 rounded text-sm cursor-pointer hover:bg-cyber-surface-2 hover:text-cyber-accent transition-colors">View Map</button>
        <button v-if="findings.length > 0" :disabled="llmLoading" @click="runComprehensive"
          class="bg-purple-900 border border-cyber-llm text-cyber-llm-light px-5 py-2.5 rounded text-sm cursor-pointer hover:bg-cyber-llm hover:text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
          {{ llmLoading ? 'Analyzing...' : 'Generate Comprehensive LLM Analysis' }}
        </button>
      </div>

      <div v-if="summary.llm_summary && !comprehensiveResult" class="bg-cyber-surface border border-cyber-border rounded-lg p-6 mb-5">
        <h2 class="text-cyber-accent font-bold mb-4">LLM Comprehensive Analysis</h2>
        <LlmSummaryBlock :text="summary.llm_summary" />
      </div>

      <div v-if="comprehensiveResult" class="bg-cyber-surface border border-cyber-border rounded-lg p-6 mb-5">
        <h2 class="text-cyber-accent font-bold mb-4">LLM Comprehensive Analysis</h2>
        <LlmSummaryBlock :text="comprehensiveResult" />
      </div>

      <div v-if="comprehensiveError" class="bg-red-900 border border-cyber-danger rounded-lg p-4 mb-5 text-cyber-danger">{{ comprehensiveError }}</div>

      <div class="bg-cyber-surface border border-cyber-border rounded-lg p-6">
        <h2 class="text-cyber-accent font-bold mb-4">Findings ({{ findings.length }})</h2>
        <FindingsFeed :findings="findings" />
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { useScanStore } from '../store/scanStore'
import FindingsFeed from '../components/FindingsFeed.vue'
import LlmSummaryBlock from '../components/LlmSummaryBlock.vue'

const props = defineProps({ id: String })
const route = useRoute()
const store = useScanStore()
const sessionId = props.id || route.params.id
const loading = ref(true)
const error = ref(null)
const targetUrl = ref('')
const findings = ref([])
const summary = ref({})
const llmLoading = ref(false)
const comprehensiveResult = ref('')
const comprehensiveError = ref('')

const summaryCards = computed(() => [
  { key: 'critical', value: summary.value.critical_count || 0, label: 'Critical', color: 'text-cyber-danger' },
  { key: 'high', value: summary.value.high_count || 0, label: 'High', color: 'text-cyber-warning' },
  { key: 'medium', value: summary.value.medium_count || 0, label: 'Medium', color: 'text-cyber-medium' },
  { key: 'low', value: summary.value.low_count || 0, label: 'Low', color: 'text-cyber-accent' },
  { key: 'endpoints', value: summary.value.total_endpoints || 0, label: 'Endpoints', color: 'text-cyber-text' },
  { key: 'findings', value: summary.value.total_findings || 0, label: 'Findings', color: 'text-cyber-text' },
])

onMounted(async () => {
  try {
    const result = await store.getScanResults(sessionId)
    targetUrl.value = result.session?.target || ''
    findings.value = result.findings || []
    summary.value = result.session?.stats || result.session || {}
    if (!Array.isArray(findings.value)) findings.value = []
  } catch (e) { error.value = 'Failed to load report: ' + e.message }
  finally { loading.value = false }
})

async function runComprehensive() {
  llmLoading.value = true
  comprehensiveError.value = ''
  comprehensiveResult.value = ''
  try {
    const result = await store.analyzeScan(sessionId)
    if (result.error) comprehensiveError.value = result.error
    else if (result.summary) comprehensiveResult.value = result.summary
  } catch (e) { comprehensiveError.value = e.message }
  finally { llmLoading.value = false }
}
</script>
