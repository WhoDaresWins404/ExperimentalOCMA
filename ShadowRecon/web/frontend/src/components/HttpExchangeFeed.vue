<template>
  <div class="flex flex-col gap-3">
    <div class="flex flex-wrap items-center gap-2 mb-2">
      <input v-model="filterText" placeholder="Filter by URL..."
        class="min-w-0 flex-1 bg-cyber-bg border border-cyber-border text-cyber-text px-3 py-1.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
      <select v-model="filterStatus"
        class="bg-cyber-bg border border-cyber-border text-cyber-text px-3 py-1.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors">
        <option value="">All Status</option>
        <option value="2">2xx</option>
        <option value="3">3xx</option>
        <option value="4">4xx</option>
        <option value="5">5xx</option>
      </select>
      <select v-model="filterScanner"
        class="bg-cyber-bg border border-cyber-border text-cyber-text px-3 py-1.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors">
        <option value="">All Scanners</option>
        <option v-for="s in scannerNames" :key="s" :value="s">{{ s }}</option>
      </select>
      <span class="text-cyber-muted text-xs whitespace-nowrap">{{ filteredExchanges.length }} / {{ exchanges.length }}</span>
    </div>
    <div v-if="filteredExchanges.length === 0" class="text-cyber-muted-2 text-center py-5">No HTTP exchanges yet.</div>
    <div v-for="ex in filteredExchanges" :key="ex.id"
      class="bg-cyber-surface-2 rounded-lg p-3 border-l-4 cursor-pointer"
      :class="statusBorder(ex.status_code)"
      @click="$emit('select', ex.id)">
      <div class="flex items-center gap-2 text-xs min-w-0">
        <span class="font-mono font-bold shrink-0" :class="statusColor(ex.status_code)">{{ ex.status_code }}</span>
        <span class="font-mono text-cyber-muted-2 uppercase shrink-0">{{ ex.method }}</span>
        <span class="text-cyber-muted truncate flex-1 min-w-0 break-all">{{ ex.url }}</span>
        <span class="text-cyber-muted-2 whitespace-nowrap shrink-0">{{ ex.timing_ms }}ms</span>
        <span class="text-cyber-muted-2 whitespace-nowrap shrink-0">{{ formatSize(ex.response_size) }}</span>
      </div>
      <div class="text-cyber-muted-2 text-xs mt-1 truncate break-all italic">{{ ex.body_preview }}</div>
      <div class="text-cyber-muted-2 text-xs mt-1" v-if="ex.scanner">
        <span class="bg-cyber-bg px-1.5 py-0.5 rounded text-cyber-muted">{{ ex.scanner }}</span>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed } from 'vue'

const props = defineProps({ exchanges: { type: Array, default: () => [] } })
defineEmits(['select'])

const filterText = ref('')
const filterStatus = ref('')
const filterScanner = ref('')

const scannerNames = computed(() => {
  const names = new Set()
  for (const ex of props.exchanges) {
    if (ex.scanner) names.add(ex.scanner)
  }
  return [...names].sort()
})

const filteredExchanges = computed(() => {
  let result = props.exchanges
  if (filterText.value) {
    const q = filterText.value.toLowerCase()
    result = result.filter(ex => ex.url.toLowerCase().includes(q) || (ex.body_preview || '').toLowerCase().includes(q))
  }
  if (filterStatus.value) {
    const prefix = filterStatus.value
    result = result.filter(ex => String(ex.status_code).startsWith(prefix))
  }
  if (filterScanner.value) {
    result = result.filter(ex => ex.scanner === filterScanner.value)
  }
  return result
})

function statusColor(code) {
  if (code >= 200 && code < 300) return 'text-cyber-accent'
  if (code >= 300 && code < 400) return 'text-cyber-medium'
  if (code >= 400 && code < 500) return 'text-cyber-warning'
  if (code >= 500) return 'text-cyber-danger'
  return 'text-cyber-muted-2'
}

function statusBorder(code) {
  if (code >= 200 && code < 300) return 'border-cyber-accent'
  if (code >= 300 && code < 400) return 'border-cyber-medium'
  if (code >= 400 && code < 500) return 'border-cyber-warning'
  if (code >= 500) return 'border-cyber-danger'
  return 'border-cyber-border'
}

function formatSize(bytes) {
  if (!bytes && bytes !== 0) return ''
  if (bytes < 1024) return bytes + 'B'
  return (bytes / 1024).toFixed(1) + 'KB'
}
</script>
