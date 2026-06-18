<template>
  <div class="flex flex-col gap-4">
    <div v-for="(section, idx) in sections" :key="idx" class="bg-cyber-surface rounded-lg p-5 border-l-4" :class="sectionBorder(section.heading)">
      <div class="text-cyber-accent font-bold text-sm mb-3 uppercase tracking-wider">{{ section.heading }}</div>
      <div class="text-cyber-text text-sm leading-relaxed whitespace-pre-wrap opacity-80">{{ section.body }}</div>
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

function sectionBorder(heading) {
  const h = heading.toLowerCase()
  if (h.includes('executive')) return 'border-cyber-accent'
  if (h.includes('critical') || h.includes('high')) return 'border-cyber-danger'
  if (h.includes('medium')) return 'border-cyber-medium'
  if (h.includes('narrative')) return 'border-cyber-warning'
  if (h.includes('recommended') || h.includes('action')) return 'border-green-500'
  return 'border-cyber-border'
}
</script>
