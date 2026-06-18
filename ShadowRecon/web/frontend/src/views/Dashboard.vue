<template>
  <div class="dashboard">
    <div class="header-section">
      <h1>ShadowRecon Dashboard</h1>
      <p class="subtitle">Web Application Security Scanner</p>
    </div>

    <Card class="scan-form-card">
      <template #title>New Scan</template>
      <template #content>
        <ScanForm @start="handleStartScan" />
      </template>
    </Card>

    <div class="campaigns-section">
      <h2>Campaigns</h2>
      <div v-if="campaigns.length === 0" class="empty-state">
        No campaigns yet. Start a scan above.
      </div>
      <div v-else class="campaign-list">
        <Card v-for="c in campaigns" :key="c.id" class="campaign-card" @click="$router.push(`/campaign/${c.id}`)">
          <template #title>
            <div class="campaign-card-header">
              <div class="campaign-name">{{ c.name }}</div>
              <Button icon="pi pi-trash" severity="danger" text rounded size="small" @click.stop="deleteCampaign(c.id)" />
            </div>
          </template>
          <template #content>
            <div class="campaign-meta">{{ c.description || 'No description' }} &middot; {{ new Date(c.created_at).toLocaleDateString() }}</div>
            <div class="campaign-tags">
              <Tag v-for="tag in c.tags" :key="tag" :value="tag" severity="info" />
            </div>
          </template>
        </Card>
      </div>
    </div>
  </div>
</template>

<script setup>
import { onMounted, computed } from 'vue'
import { useRouter } from 'vue-router'
import { useScanStore } from '../store/scanStore'
import Card from 'primevue/card'
import Button from 'primevue/button'
import Tag from 'primevue/tag'
import ScanForm from '../components/ScanForm.vue'
import axios from 'axios'

const store = useScanStore()
const router = useRouter()
const campaigns = computed(() => store.campaigns)
const API = ''

onMounted(() => {
  store.fetchCampaigns()
})

async function deleteCampaign(id) {
  if (!confirm('Delete this campaign and all its scans?')) return
  try {
    await axios.delete(`${API}/api/campaigns/${id}`)
    store.fetchCampaigns()
  } catch (e) {
    console.error('Failed to delete campaign:', e)
  }
}

async function handleStartScan(params) {
  try {
    const result = await store.startScan(params)
    if (result.session_id) {
      router.push(`/scan/${result.session_id}`)
    } else if (result.campaign_id) {
      router.push(`/campaign/${result.campaign_id}`)
    }
  } catch (e) {
    console.error('Failed to start scan:', e)
  }
}
</script>

<style scoped>
.dashboard { padding: 1.25rem 0; }
.header-section { margin-bottom: 1.875rem; }
.header-section h1 { color: var(--p-primary-color); font-size: 2rem; }
.subtitle { color: var(--p-surface-300); margin-top: 0.3125rem; }
.scan-form-card { margin-bottom: 1.875rem; }
.campaigns-section h2 { color: var(--p-primary-color); margin-bottom: 0.9375rem; }
.empty-state {
  background: var(--p-surface-600); border-radius: 8px; padding: 2.5rem;
  text-align: center; color: var(--p-surface-400); border: 1px dashed var(--p-surface-500);
}
.campaign-list { display: grid; gap: 0.75rem; }
.campaign-card { cursor: pointer; transition: all 0.2s; }
.campaign-card:hover { border-color: var(--p-primary-color); }
.campaign-card-header { display: flex; justify-content: space-between; align-items: center; width: 100%; }
.campaign-name { color: var(--p-surface-100); font-weight: 700; font-size: 1.1rem; }
.campaign-meta { color: var(--p-surface-300); font-size: 0.85rem; margin-top: 0.3125rem; }
.campaign-tags { margin-top: 0.5rem; display: flex; gap: 0.375rem; flex-wrap: wrap; }
</style>
