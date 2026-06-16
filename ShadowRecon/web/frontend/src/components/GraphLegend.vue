<template>
  <div class="graph-legend">
    <div v-for="item in items" :key="item.type" class="legend-row">
      <span class="legend-dot" :style="{ background: item.color }"></span>
      <span class="legend-label">{{ item.label }}</span>
    </div>
  </div>
</template>

<script setup>
const props = defineProps({
  items: {
    type: Array,
    default: () => [
      { type: 'host', color: '#4CAF50', label: 'Host' },
      { type: 'endpoint', color: '#2196F3', label: 'Endpoint' },
      { type: 'api', color: '#FF9800', label: 'API' },
      { type: 'auth_provider', color: '#F44336', label: 'Auth Provider' },
      { type: 'finding', color: '#FFD700', label: 'Finding/Vulnerability' },
      { type: 'database', color: '#795548', label: 'Database' },
      { type: 'static_asset', color: '#607D8B', label: 'Static Asset' },
      { type: 'unknown', color: '#9E9E9E', label: 'Unknown' },
    ],
  },
})
</script>

<style scoped>
.graph-legend {
  display: flex;
  flex-direction: column;
  gap: 5px;
  padding: 10px;
}
.legend-row {
  display: flex;
  align-items: center;
  gap: 8px;
}
.legend-dot {
  width: 12px;
  height: 12px;
  border-radius: 50%;
  flex-shrink: 0;
}
.legend-label {
  color: #8899aa;
  font-size: 0.85em;
}
</style>
