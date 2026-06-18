<template>
  <Tag :severity="pvSeverity" :value="label" />
</template>

<script setup>
import { computed } from 'vue'
import Tag from 'primevue/tag'

const props = defineProps({ severity: { type: String, default: 'none' }, score: { type: Number, default: null } })

const pvSeverity = computed(() => {
  const s = props.severity.toLowerCase()
  if (s === 'critical') return 'danger'
  if (s === 'high') return 'warn'
  if (s === 'medium') return 'info'
  if (s === 'low') return 'success'
  return 'secondary'
})

const label = computed(() => {
  if (props.score != null) return props.score.toFixed(1)
  return props.severity.toUpperCase()
})
</script>
