<template>
  <div class="map-view">
    <Button icon="pi pi-arrow-left" label="Back" severity="secondary" text @click="$router.push('/dashboard')" class="back-btn" />
    <h1>Endpoint Map: {{ sessionId ? sessionId.slice(0, 12) : '...' }}</h1>
    <div class="map-controls">
      <Tag :value="`${graphData.nodes.length} nodes / ${graphData.edges.length} edges`" severity="info" />
    </div>
    <div class="graph-container" ref="graphContainer">
      <div v-if="graphData.nodes.length === 0" class="empty-graph">
        Loading graph data...
      </div>
      <EndpointGraph v-else :graph-data="graphData" />
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, computed } from 'vue'
import { useRoute } from 'vue-router'
import { useScanStore } from '../store/scanStore'
import Button from 'primevue/button'
import Tag from 'primevue/tag'
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

<style scoped>
.map-view { padding: 1.25rem 0; height: calc(100vh - 100px); display: flex; flex-direction: column; }
.back-btn { margin-bottom: 0.625rem; width: fit-content; }
h1 { color: var(--p-primary-color); margin-bottom: 0.9375rem; font-size: 1.5rem; }
.map-controls { display: flex; justify-content: flex-end; align-items: center; margin-bottom: 0.9375rem; }
.graph-container { flex: 1; background: var(--p-surface-800); border: 1px solid var(--p-surface-500); border-radius: 8px; overflow: hidden; min-height: 400px; }
.empty-graph { display: flex; align-items: center; justify-content: center; height: 100%; color: var(--p-surface-400); }
</style>
