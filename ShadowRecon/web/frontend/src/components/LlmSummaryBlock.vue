<template>
  <div class="llm-summary">
    <Card v-for="(section, idx) in sections" :key="idx" :class="['section-card', sectionClass(section.heading)]">
      <template #title>
        <div class="section-heading">{{ section.heading }}</div>
      </template>
      <template #content>
        <div class="section-body">{{ section.body }}</div>
      </template>
    </Card>
  </div>
</template>

<script setup>
import { computed } from 'vue'
import Card from 'primevue/card'

const props = defineProps({ text: { type: String, default: '' } })

const sections = computed(() => {
  const parts = []
  const regex = /^##\s+(.+)$/gm
  let lastIndex = 0
  let match
  while ((match = regex.exec(props.text)) !== null) {
    const start = match.index + match[0].length
    if (lastIndex > 0) {
      const body = props.text.slice(lastIndex, match.index).trim()
      if (body) parts[parts.length - 1].body = body
    }
    parts.push({ heading: match[1].trim(), body: '' })
    lastIndex = start
  }
  if (lastIndex > 0 && parts.length) {
    const body = props.text.slice(lastIndex).trim()
    if (body) parts[parts.length - 1].body = body
  }
  return parts
})

function sectionClass(heading) {
  const h = heading.toLowerCase()
  if (h.includes('executive')) return 'card-exec'
  if (h.includes('critical') || h.includes('high')) return 'card-critical'
  if (h.includes('medium')) return 'card-medium'
  if (h.includes('narrative')) return 'card-narrative'
  if (h.includes('recommended') || h.includes('action')) return 'card-action'
  return ''
}
</script>

<style scoped>
.llm-summary { display: flex; flex-direction: column; gap: 1rem; }
.section-card { border-left: 4px solid var(--p-surface-500); }
.section-heading { color: var(--p-primary-color); font-weight: 700; font-size: 1rem; text-transform: uppercase; letter-spacing: 1px; }
.section-body { color: var(--p-surface-200); font-size: 0.88rem; line-height: 1.7; white-space: pre-wrap; }
.card-exec { border-left-color: var(--p-primary-color); }
.card-critical { border-left-color: var(--p-red-500); }
.card-medium { border-left-color: var(--p-yellow-500); }
.card-narrative { border-left-color: var(--p-orange-400); }
.card-action { border-left-color: var(--p-green-500); }
</style>
