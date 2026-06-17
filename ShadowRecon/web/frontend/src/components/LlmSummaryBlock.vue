<template>
  <div class="llm-summary">
    <div v-for="(section, idx) in sections" :key="idx" :class="['section-card', sectionClass(section.heading)]">
      <div class="section-heading">{{ section.heading }}</div>
      <div class="section-body">{{ section.body }}</div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'

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
.llm-summary { display: flex; flex-direction: column; gap: 16px; }
.section-card { background: #111927; border-radius: 8px; padding: 20px; border-left: 4px solid #1e3a5f; }
.section-heading { color: #00e5ff; font-weight: bold; font-size: 1em; margin-bottom: 12px; text-transform: uppercase; letter-spacing: 1px; }
.section-body { color: #b0b0b0; font-size: 0.88em; line-height: 1.7; white-space: pre-wrap; }
.card-exec { border-left-color: #00e5ff; }
.card-critical { border-left-color: #ff1744; }
.card-medium { border-left-color: #ffd600; }
.card-narrative { border-left-color: #ff9100; }
.card-action { border-left-color: #00c853; }
</style>
