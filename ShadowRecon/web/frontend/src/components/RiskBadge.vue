<template>
  <span class="risk-badge" :class="badgeClass" :title="tooltip">
    {{ label }}
  </span>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({ severity: { type: String, default: 'none' }, score: { type: Number, default: null } })

const label = computed(() => {
  if (props.score != null) return props.score.toFixed(1)
  return props.severity.toUpperCase()
})

const badgeClass = computed(() => {
  const s = props.severity.toLowerCase()
  if (s === 'critical' || s === 'high' || s === 'medium' || s === 'low') return s
  return 'info'
})

const tooltip = computed(() => {
  return `${props.severity.toUpperCase()}${props.score != null ? ` (CVSS: ${props.score})` : ''}`
})
</script>

<style scoped>
.risk-badge {
  display: inline-block; padding: 2px 10px; border-radius: 10px;
  font-size: 0.75em; font-weight: bold; white-space: nowrap;
}
.critical { background: #ff1744; color: #fff; }
.high { background: #ff9100; color: #000; }
.medium { background: #ffd600; color: #000; }
.low { background: #00e5ff; color: #000; }
.info { background: #2979ff; color: #fff; }
</style>
