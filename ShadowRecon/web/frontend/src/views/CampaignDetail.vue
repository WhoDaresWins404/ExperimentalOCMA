<template>
  <div class="py-5">
    <button @click="$router.push('/dashboard')"
      class="bg-transparent border border-cyber-border text-cyber-muted px-4 py-2 rounded cursor-pointer mb-5 hover:text-cyber-accent hover:border-cyber-accent transition-colors">
      &larr; Back
    </button>

    <div v-if="campaign" class="mb-5">
      <h1 class="text-cyber-accent text-3xl font-bold">{{ campaign.name }}</h1>
      <p class="text-cyber-muted mt-1">{{ campaign.description }}</p>
    </div>

    <div class="bg-cyber-surface border border-cyber-border rounded-lg p-6 my-5">
      <h2 class="text-cyber-accent font-bold text-lg mb-4">Start New Scan</h2>
      <ScanForm :campaign-id="id" @start="handleStartScan" />
    </div>

    <div>
      <h2 class="text-cyber-accent font-bold text-lg mb-4">Scan Sessions</h2>
      <div v-if="!campaign" class="bg-cyber-surface border border-dashed border-cyber-border rounded-lg py-10 text-center text-cyber-muted-2">Loading...</div>
      <div v-else-if="!campaign.sessions || campaign.sessions.length === 0" class="bg-cyber-surface border border-dashed border-cyber-border rounded-lg py-10 text-center text-cyber-muted-2">No scans yet in this campaign.</div>
      <div v-else class="grid gap-3">
        <div v-for="s in campaign.sessions" :key="s.id" class="bg-cyber-surface border border-cyber-border rounded-lg p-5">
          <div class="text-cyber-text font-bold">{{ s.target }}</div>
          <div class="text-cyber-muted text-sm mt-1 flex items-center gap-2">
            Status:
            <span class="inline-block px-2 py-0.5 rounded text-xs font-bold" :class="statusClass(s.status)">{{ s.status }}</span>
            &middot; {{ s.started_at ? new Date(s.started_at).toLocaleString() : 'Not started' }}
          </div>
          <div class="flex gap-2 mt-2.5">
            <button v-if="['scanning','adaptive_scan','reconnaissance','strategize','waf_check','dedup','llm_enrich','generating_report'].includes(s.status)" @click="$router.push(`/scan/${s.id}`)"
              class="bg-cyber-surface border border-cyber-border text-cyber-text px-3.5 py-1.5 rounded text-xs cursor-pointer hover:bg-cyber-surface-2 hover:text-cyber-accent transition-colors">View Live</button>
            <button v-if="s.status === 'completed'" @click="$router.push(`/report/${s.id}`)"
              class="bg-cyber-surface border border-cyber-border text-cyber-text px-3.5 py-1.5 rounded text-xs cursor-pointer hover:bg-cyber-surface-2 hover:text-cyber-accent transition-colors">Report</button>
            <button v-if="s.status === 'completed'" @click="$router.push(`/map/${s.id}`)"
              class="bg-cyber-surface border border-cyber-border text-cyber-text px-3.5 py-1.5 rounded text-xs cursor-pointer hover:bg-cyber-surface-2 hover:text-cyber-accent transition-colors">Map</button>
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

onMounted(async () => { campaign.value = await store.getCampaign(effectiveId) })

function statusClass(status) {
  const map = { completed: 'bg-cyber-accent text-black', scanning: 'bg-yellow-400 text-black', adaptive_scan: 'bg-yellow-400 text-black', failed: 'bg-cyber-danger text-white', pending: 'bg-cyber-muted text-black' }
  return map[status] || 'bg-cyber-muted-2 text-cyber-text'
}

async function handleStartScan(params) {
  try {
    const result = await store.startScan({ ...params, campaign_name: campaign.value?.name || params.campaign_name })
    campaign.value = await store.getCampaign(effectiveId)
    if (result.session_id) router.push(`/scan/${result.session_id}`)
  } catch (e) { console.error('Failed to start scan:', e) }
}
</script>
