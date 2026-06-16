<template>
  <div class="dashboard">
    <div class="header-section">
      <h1>ShadowRecon Dashboard</h1>
      <p class="subtitle">Web Application Security Scanner</p>
    </div>

    <div class="scan-form-card">
      <h2>New Scan</h2>
      <ScanForm @start="handleStartScan" />
    </div>

    <div class="campaigns-section">
      <h2>Campaigns</h2>
      <div v-if="campaigns.length === 0" class="empty-state">
        No campaigns yet. Start a scan above.
      </div>
      <div v-else class="campaign-list">
        <div v-for="c in campaigns" :key="c.id" class="campaign-card" @click="$router.push(`/campaign/${c.id}`)">
          <div class="campaign-name">{{ c.name }}</div>
          <div class="campaign-meta">{{ c.description || 'No description' }} &middot; {{ new Date(c.created_at).toLocaleDateString() }}</div>
          <div class="campaign-tags">
            <span v-for="tag in c.tags" :key="tag" class="tag">{{ tag }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useScanStore } from '../store/scanStore'
import ScanForm from '../components/ScanForm.vue'

const store = useScanStore()
const router = useRouter()

onMounted(() => {
  store.fetchCampaigns()
})

async function handleStartScan(params) {
  const result = await store.startScan(params)
  router.push(`/campaign/${result.campaign_id}`)
}
</script>

<style scoped>
.dashboard { padding: 20px 0; }
.header-section { margin-bottom: 30px; }
.header-section h1 { color: #00e5ff; font-size: 2em; }
.subtitle { color: #8899aa; margin-top: 5px; }
.scan-form-card {
  background: #111927; border-radius: 8px; padding: 25px;
  border: 1px solid #1e3a5f; margin-bottom: 30px;
}
.scan-form-card h2 { color: #00e5ff; margin-bottom: 15px; }
.campaigns-section h2 { color: #00e5ff; margin-bottom: 15px; }
.empty-state {
  background: #111927; border-radius: 8px; padding: 40px;
  text-align: center; color: #556677; border: 1px dashed #1e3a5f;
}
.campaign-list { display: grid; gap: 12px; }
.campaign-card {
  background: #111927; border-radius: 8px; padding: 20px;
  border: 1px solid #1e3a5f; cursor: pointer; transition: all 0.2s;
}
.campaign-card:hover { border-color: #00e5ff; background: #0f1a2e; }
.campaign-name { color: #e0e0e0; font-weight: bold; font-size: 1.1em; }
.campaign-meta { color: #8899aa; font-size: 0.85em; margin-top: 5px; }
.campaign-tags { margin-top: 8px; display: flex; gap: 6px; flex-wrap: wrap; }
.tag {
  background: #1e3a5f; color: #00e5ff; padding: 2px 10px;
  border-radius: 10px; font-size: 0.8em;
}
</style>
