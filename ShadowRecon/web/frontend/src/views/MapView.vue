<template>
  <div class="py-5 h-[calc(100vh-100px)] flex flex-col">
    <button @click="$router.push('/dashboard')"
      class="bg-transparent border border-cyber-border text-cyber-muted px-4 py-2 rounded cursor-pointer mb-2.5 w-fit hover:text-cyber-accent hover:border-cyber-accent transition-colors">
      &larr; Back
    </button>
    <h1 class="text-cyber-accent text-2xl font-bold mb-4">Endpoint Map: {{ sessionId ? sessionId.slice(0, 12) : '...' }}</h1>
    <div class="flex justify-end mb-4">
      <span class="text-cyber-muted-2 text-xs">{{ graphData.nodes.length }} nodes / {{ graphData.edges.length }} edges</span>
    </div>
    <div class="flex-1 bg-cyber-bg border border-cyber-border rounded-lg overflow-hidden min-h-[400px]" ref="graphContainer">
      <div v-if="graphData.nodes.length === 0" class="flex items-center justify-center h-full text-cyber-muted-2">Loading graph data...</div>
      <EndpointGraph v-else :graph-data="graphData" />
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, computed } from 'vue'
import { useRoute } from 'vue-router'
import { useScanStore } from '../store/scanStore'
import EndpointGraph from '../components/EndpointGraph.vue'

const props = defineProps({ id: String })
const route = useRoute()
const store = useScanStore()
const sessionId = props.id || route.params.id
const graphContainer = ref(null)
const graphData = computed(() => store.graphData)

onMounted(async () => {
  store.graphData = { nodes: [], edges: [] }
  await store.getScanMap(sessionId)
})
</script>
