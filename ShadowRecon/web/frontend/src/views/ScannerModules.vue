<template>
  <div class="space-y-6">
    <div class="flex items-center justify-between">
      <h1 class="text-2xl font-bold text-cyber-accent">Scanner Modules</h1>
      <span class="text-xs text-cyber-muted">{{ manifests.length }} modules registered</span>
    </div>

    <div v-if="error" class="bg-red-900/30 border border-red-700/50 rounded-lg p-4 text-sm text-cyber-muted">
      {{ error }}
    </div>

    <div v-if="!loaded" class="text-center py-12 text-cyber-muted">Loading scanner modules...</div>

    <template v-for="(group, category) in grouped" :key="category">
      <div class="mb-6">
        <h2 class="text-lg font-semibold text-cyber-text mb-3 capitalize">{{ category }}</h2>
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          <div v-for="m in group" :key="m.name"
               class="bg-[#0d1b2a]/80 border border-cyber-border rounded-lg p-4 hover:border-cyber-accent/40 transition-colors">
            <div class="flex items-start justify-between mb-2">
              <h3 class="font-medium text-cyber-text text-sm">{{ m.name }}</h3>
              <span class="text-[10px] px-2 py-0.5 rounded-full"
                    :class="riskBadge(m.risk_level)">{{ m.risk_level }}</span>
            </div>
            <div class="flex items-center gap-3 text-[11px] text-cyber-muted">
              <span>Cost: {{ m.estimated_cost }}</span>
              <span v-if="m.prerequisites?.length">Requires: {{ m.prerequisites.join(', ') }}</span>
            </div>
            <div v-if="m.produces_tag_patterns?.length" class="mt-2 flex flex-wrap gap-1">
              <span v-for="tag in m.produces_tag_patterns" :key="tag"
                    class="text-[10px] px-1.5 py-0.5 rounded bg-cyber-accent/10 text-cyber-accent/80">{{ tag }}</span>
            </div>
            <div v-if="m.produces_endpoint_types?.length" class="mt-1 flex flex-wrap gap-1">
              <span v-for="et in m.produces_endpoint_types" :key="et"
                    class="text-[10px] px-1.5 py-0.5 rounded bg-cyan-900/30 text-cyan-400/70">{{ et }}</span>
            </div>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue'

const manifests = ref([])
const loaded = ref(false)
const error = ref('')

const grouped = computed(() => {
  const groups = {}
  for (const m of manifests.value) {
    const cat = m.category || 'other'
    if (!groups[cat]) groups[cat] = []
    groups[cat].push(m)
  }
  return groups
})

function riskBadge(level) {
  if (level === 'aggressive') return 'bg-red-900/40 text-red-400 border border-red-700/30'
  if (level === 'moderate') return 'bg-yellow-900/40 text-yellow-400 border border-yellow-700/30'
  return 'bg-green-900/40 text-green-400 border border-green-700/30'
}

onMounted(async () => {
  try {
    const resp = await fetch('/api/scanners')
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
    manifests.value = await resp.json()
  } catch (e) {
    error.value = `Failed to load scanner modules: ${e.message}`
  } finally {
    loaded.value = true
  }
})
</script>
