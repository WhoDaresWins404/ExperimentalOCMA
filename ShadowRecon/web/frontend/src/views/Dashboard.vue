<template>
  <div class="py-5">
    <div class="mb-8">
      <h1 class="text-cyber-accent text-4xl font-bold">ShadowRecon Dashboard</h1>
      <p class="text-cyber-muted mt-1">Web Application Security Scanner</p>
    </div>

    <div class="bg-cyber-surface border border-cyber-border rounded-lg p-6 mb-8">
      <h2 class="text-cyber-accent font-bold text-lg mb-4">New Scan</h2>
      <ScanForm @start="handleStartScan" />
    </div>

    <div>
      <h2 class="text-cyber-accent font-bold text-lg mb-4">Campaigns</h2>
      <div v-if="campaigns.length === 0" class="bg-cyber-surface border border-dashed border-cyber-border rounded-lg py-10 text-center text-cyber-muted-2">
        No campaigns yet. Start a scan above.
      </div>
      <div v-else class="grid gap-3">
        <div v-for="c in campaigns" :key="c.id" @click="$router.push(`/campaign/${c.id}`)"
          class="bg-cyber-surface border border-cyber-border rounded-lg p-5 cursor-pointer transition-all hover:border-cyber-accent">
          <div class="flex justify-between items-center">
            <div class="text-cyber-text font-bold text-lg">{{ c.name }}</div>
            <button @click.stop="deleteCampaign(c.id)" title="Delete campaign"
              class="bg-transparent border border-red-800 text-cyber-danger rounded px-2 py-0.5 text-sm cursor-pointer hover:bg-red-900 hover:text-white transition-colors">&times;</button>
          </div>
          <div class="text-cyber-muted text-sm mt-1">{{ c.description || 'No description' }} &middot; {{ new Date(c.created_at).toLocaleDateString() }}</div>
          <div class="flex gap-1.5 mt-2 flex-wrap">
            <span v-for="tag in c.tags" :key="tag" class="bg-cyber-border text-cyber-accent px-2.5 py-0.5 rounded-full text-xs">{{ tag }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { onMounted, computed } from 'vue'
import { useRouter } from 'vue-router'
import { useScanStore } from '../store/scanStore'
import ScanForm from '../components/ScanForm.vue'
import axios from 'axios'

const store = useScanStore()
const router = useRouter()
const campaigns = computed(() => store.campaigns)
const API = ''

onMounted(() => { store.fetchCampaigns() })

async function deleteCampaign(id) {
  if (!confirm('Delete this campaign and all its scans?')) return
  try {
    await axios.delete(`${API}/api/campaigns/${id}`)
    store.fetchCampaigns()
  } catch (e) { console.error('Failed to delete campaign:', e) }
}

async function handleStartScan(params) {
  try {
    const result = await store.startScan(params)
    if (result.session_id) router.push(`/scan/${result.session_id}`)
    else if (result.campaign_id) router.push(`/campaign/${result.campaign_id}`)
  } catch (e) { console.error('Failed to start scan:', e) }
}
</script>
