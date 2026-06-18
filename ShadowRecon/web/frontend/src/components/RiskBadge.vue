<template>
  <span class="inline-block px-2.5 py-0.5 rounded-full text-xs font-bold whitespace-nowrap" :class="colorClass">{{ label }}</span>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({ severity: { type: String, default: 'none' }, score: { type: Number, default: null } })

const severityMap = {
  critical: 'bg-cyber-danger text-white',
  high: 'bg-cyber-warning text-black',
  medium: 'bg-cyber-medium text-black',
  low: 'bg-cyber-accent text-black',
}

const colorClass = computed(() => severityMap[props.severity.toLowerCase()] || 'bg-blue-500 text-white')
const label = computed(() => props.score != null ? props.score.toFixed(1) : props.severity.toUpperCase())
</script>
