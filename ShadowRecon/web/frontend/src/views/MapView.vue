<template>
  <div class="map-view">
    <button class="back-btn" @click="$router.push('/dashboard')">&larr; Back</button>
    <h1>Endpoint Map: {{ sessionId ? sessionId.slice(0, 12) : '...' }}</h1>
    <div class="map-controls">
      <div class="legend" v-if="graphData.nodes.length">
        <span v-for="item in legendItems" :key="item.type" class="legend-item">
          <span class="legend-dot" :style="{background: item.color}"></span>{{ item.label }}
        </span>
      </div>
      <div class="map-stats">
        {{ graphData.nodes.length }} nodes / {{ graphData.edges.length }} edges
      </div>
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
import EndpointGraph from '../components/EndpointGraph.vue'

const props = defineProps({ id: String })
const route = useRoute()
const store = useScanStore()
const sessionId = props.id || route.params.id
const graphContainer = ref(null)

const graphData = computed(() => store.graphData)

const legendItems = [
  { type: 'host', color: '#4CAF50', label: 'Host' },
  { type: 'endpoint', color: '#2196F3', label: 'Endpoint' },
  { type: 'api', color: '#FF9800', label: 'API' },
  { type: 'auth_provider', color: '#F44336', label: 'Auth' },
  { type: 'finding', color: '#FFD700', label: 'Finding' },
  { type: 'database', color: '#795548', label: 'Database' },
  { type: 'static_asset', color: '#607D8B', label: 'Static' },
]

onMounted(async () => {
  store.graphData = { nodes: [], edges: [] }
  await store.getScanMap(sessionId)
})
</script>

<style scoped>
.map-view { padding: 20px 0; height: calc(100vh - 100px); display: flex; flex-direction: column; }
.back-btn { background: none; border: 1px solid #1e3a5f; color: #8899aa; padding: 8px 16px; border-radius: 5px; cursor: pointer; margin-bottom: 10px; width: fit-content; }
.back-btn:hover { color: #00e5ff; border-color: #00e5ff; }
h1 { color: #00e5ff; margin-bottom: 15px; font-size: 1.5em; }
.map-controls { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
.legend { display: flex; gap: 15px; flex-wrap: wrap; }
.legend-item { display: flex; align-items: center; gap: 5px; color: #8899aa; font-size: 0.85em; }
.legend-dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }
.map-stats { color: #556677; font-size: 0.85em; }
.graph-container { flex: 1; background: #0a0e17; border: 1px solid #1e3a5f; border-radius: 8px; overflow: hidden; min-height: 400px; }
.empty-graph { display: flex; align-items: center; justify-content: center; height: 100%; color: #556677; }
</style>
