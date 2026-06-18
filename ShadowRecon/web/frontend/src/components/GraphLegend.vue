<template>
  <div class="flex flex-col gap-1.5 p-2.5">
    <div v-for="item in items" :key="item.type" class="flex items-center gap-2">
      <span class="w-3 h-3 rounded-full flex-shrink-0" :style="{ background: item.color }"></span>
      <span class="text-cyber-muted text-sm">{{ item.label }}</span>
    </div>
  </div>
</template>

<script setup>
defineProps({
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
