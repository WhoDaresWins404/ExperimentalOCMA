<template>
  <div class="campaign-detail">
    <button class="back-btn" @click="$router.push('/dashboard')">&larr; Back</button>
    <div v-if="campaign" class="campaign-header">
      <h1>{{ campaign.name }}</h1>
      <p>{{ campaign.description }}</p>
    </div>

    <div class="scan-form-card">
      <h2>Start New Scan</h2>
      <ScanForm :campaign-id="id" @start="handleStartScan" />
    </div>

    <div class="sessions-section">
      <h2>Scan Sessions</h2>
      <div v-if="!campaign" class="empty-state">Loading...</div>
      <div v-else-if="!campaign.sessions || campaign.sessions.length === 0" class="empty-state">
        No scans yet in this campaign.
      </div>
      <div v-else class="session-list">
        <div v-for="s in campaign.sessions" :key="s.id" class="session-card">
          <div class="session-target">{{ s.target }}</div>
          <div class="session-meta">
            Status: <span :class="'status-' + s.status">{{ s.status }}</span>
            &middot; {{ s.started_at ? new Date(s.started_at).toLocaleString() : 'Not started' }}
          </div>
          <div class="session-actions">
            <button @click="$router.push(`/scan/${s.id}`)" v-if="['scanning','adaptive_scan','reconnaissance','strategize','waf_check','dedup','llm_enrich','generating_report'].includes(s.status)">View Live</button>
            <button @click="$router.push(`/report/${s.id}`)" v-if="s.status === 'completed'">Report</button>
            <button @click="$router.push(`/map/${s.id}`)" v-if="s.status === 'completed'">Map</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useScanStore } from '../store/scanStore'
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
.campaign-detail { padding: 20px 0; }
.back-btn { background: none; border: 1px solid #1e3a5f; color: #8899aa; padding: 8px 16px; border-radius: 5px; cursor: pointer; margin-bottom: 20px; }
.back-btn:hover { color: #00e5ff; border-color: #00e5ff; }
.campaign-header h1 { color: #00e5ff; font-size: 1.8em; }
.campaign-header p { color: #8899aa; margin-top: 5px; }
.scan-form-card {
  background: #111927; border-radius: 8px; padding: 25px;
  border: 1px solid #1e3a5f; margin: 20px 0;
}
.scan-form-card h2 { color: #00e5ff; margin-bottom: 15px; }
.sessions-section h2 { color: #00e5ff; margin-bottom: 15px; }
.empty-state {
  background: #111927; border-radius: 8px; padding: 40px;
  text-align: center; color: #556677; border: 1px dashed #1e3a5f;
}
.session-list { display: grid; gap: 12px; }
.session-card {
  background: #111927; border-radius: 8px; padding: 20px;
  border: 1px solid #1e3a5f;
}
.session-target { color: #e0e0e0; font-weight: bold; }
.session-meta { color: #8899aa; font-size: 0.85em; margin-top: 5px; }
.status-completed { color: #00e5ff; }
.status-scanning { color: #ffd600; }
.status-failed { color: #ff1744; }
.status-pending { color: #8899aa; }
.session-actions { margin-top: 10px; display: flex; gap: 8px; }
.session-actions button {
  background: #1e3a5f; color: #e0e0e0; border: none;
  padding: 6px 14px; border-radius: 4px; cursor: pointer;
}
.session-actions button:hover { background: #2a4a7f; color: #00e5ff; }
</style>
