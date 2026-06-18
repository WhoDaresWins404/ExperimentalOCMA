<template>
  <div class="campaign-detail">
    <Button icon="pi pi-arrow-left" label="Back" severity="secondary" text @click="$router.push('/dashboard')" class="back-btn" />

    <div v-if="campaign" class="campaign-header">
      <h1>{{ campaign.name }}</h1>
      <p>{{ campaign.description }}</p>
    </div>

    <Card class="scan-form-card">
      <template #title>Start New Scan</template>
      <template #content>
        <ScanForm :campaign-id="id" @start="handleStartScan" />
      </template>
    </Card>

    <div class="sessions-section">
      <h2>Scan Sessions</h2>

      <div v-if="!campaign" class="empty-state">Loading...</div>
      <div v-else-if="!campaign.sessions || campaign.sessions.length === 0" class="empty-state">
        No scans yet in this campaign.
      </div>
      <div v-else class="session-list">
        <Card v-for="s in campaign.sessions" :key="s.id" class="session-card">
          <template #title>
            <div class="session-target">{{ s.target }}</div>
          </template>
          <template #content>
            <div class="session-meta">
              Status: <Tag :severity="statusSeverity(s.status)" :value="s.status" />
              &middot; {{ s.started_at ? new Date(s.started_at).toLocaleString() : 'Not started' }}
            </div>
          </template>
          <template #footer>
            <div class="session-actions">
              <Button v-if="['scanning','adaptive_scan','reconnaissance','strategize','waf_check','dedup','llm_enrich','generating_report'].includes(s.status)" label="View Live" size="small" @click="$router.push(`/scan/${s.id}`)" />
              <Button v-if="s.status === 'completed'" label="Report" icon="pi pi-file" size="small" severity="info" @click="$router.push(`/report/${s.id}`)" />
              <Button v-if="s.status === 'completed'" label="Map" icon="pi pi-sitemap" size="small" severity="info" @click="$router.push(`/map/${s.id}`)" />
            </div>
          </template>
        </Card>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useScanStore } from '../store/scanStore'
import Button from 'primevue/button'
import Card from 'primevue/card'
import Tag from 'primevue/tag'
import ScanForm from '../components/ScanForm.vue'

const props = defineProps({ id: String })
const route = useRoute()
const router = useRouter()
const store = useScanStore()
const campaign = ref(null)
const effectiveId = props.id || route.params.id

onMounted(async () => {
  campaign.value = await store.getCampaign(effectiveId)
})

function statusSeverity(status) {
  const map = { completed: 'success', scanning: 'warn', adaptive_scan: 'warn', reconnaissance: 'info', strategize: 'info', waf_check: 'info', failed: 'danger', pending: 'secondary' }
  return map[status] || 'info'
}

async function handleStartScan(params) {
  try {
    const result = await store.startScan({ ...params, campaign_name: campaign.value?.name || params.campaign_name })
    campaign.value = await store.getCampaign(effectiveId)
    if (result.session_id) {
      router.push(`/scan/${result.session_id}`)
    }
  } catch (e) {
    console.error('Failed to start scan:', e)
  }
}
</script>

<style scoped>
.campaign-detail { padding: 1.25rem 0; }
.back-btn { margin-bottom: 1.25rem; }
.campaign-header h1 { color: var(--p-primary-color); font-size: 1.8rem; }
.campaign-header p { color: var(--p-surface-300); margin-top: 0.3125rem; }
.scan-form-card { margin: 1.25rem 0; }
.sessions-section h2 { color: var(--p-primary-color); margin-bottom: 0.9375rem; }
.empty-state {
  background: var(--p-surface-600); border-radius: 8px; padding: 2.5rem;
  text-align: center; color: var(--p-surface-400); border: 1px dashed var(--p-surface-500);
}
.session-list { display: grid; gap: 0.75rem; }
.session-meta { color: var(--p-surface-300); font-size: 0.85rem; margin-top: 0.3125rem; display: flex; align-items: center; gap: 0.5rem; }
.session-actions { display: flex; gap: 0.5rem; }
</style>
