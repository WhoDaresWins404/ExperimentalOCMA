<template>
  <div class="flex flex-col gap-4">
    <div v-for="(section, idx) in sections" :key="idx"
      class="bg-cyber-surface rounded-lg p-5 border-l-4"
      :class="sectionBorder(section.heading)">
      <div v-if="section.heading" class="text-cyber-accent font-bold text-sm mb-3 uppercase tracking-wider">
        {{ section.heading }}
      </div>
      <div class="text-cyber-text text-sm leading-relaxed opacity-80" v-html="section.bodyHtml"></div>
    </div>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({ text: { type: String, default: '' } })

const sections = computed(() => {
  const raw = props.text.trim()
  if (!raw) return []

  const parts = []
  const headingRe = /^#{2,4}\s+(.+)$/gm
  let lastIndex = 0
  let lastHeadingEnd = 0
  let match

  while ((match = headingRe.exec(raw)) !== null) {
    if (lastIndex === 0 && match.index > 0) {
      parts.push({ heading: '', body: raw.slice(0, match.index).trim() })
    }
    if (lastIndex > 0) {
      const body = raw.slice(lastIndex, match.index).trim()
      if (body && parts.length) parts[parts.length - 1].body = body
    }
    parts.push({ heading: match[1].trim(), body: '' })
    lastIndex = match.index + match[0].length
    lastHeadingEnd = match.index + match[0].length
  }

  if (parts.length) {
    const remaining = raw.slice(lastIndex).trim()
    if (remaining && parts.length) parts[parts.length - 1].body = remaining
  } else {
    parts.push({ heading: '', body: raw })
  }

  return parts.map(s => ({
    ...s,
    bodyHtml: renderMarkdown(s.body || ''),
  }))
})

function renderMarkdown(text) {
  let html = text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')

  html = html.replace(/```(\w*)\n([\s\S]*?)```/g, (_, lang, code) => {
    const escaped = code
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
    return `<pre class="bg-cyber-bg border border-cyber-border rounded p-3 my-2 overflow-x-auto text-[11px] leading-relaxed">${escaped}</pre>`
  })

  html = html.replace(/`([^`]+)`/g, '<code class="bg-cyber-bg border border-cyber-border rounded px-1.5 py-0.5 text-[11px] text-cyber-accent">$1</code>')

  html = html.replace(/\*\*([^*]+)\*\*/g, '<strong class="text-cyber-text font-bold">$1</strong>')
  html = html.replace(/\*([^*]+)\*/g, '<em class="italic">$1</em>')

  const lines = html.split('\n')
  const out = []
  let inList = false
  for (let line of lines) {
    const listMatch = line.match(/^(\s*)[-*+]\s+(.*)/)
    const numMatch = line.match(/^(\s*)\d+[.)]\s+(.*)/)
    if (listMatch || numMatch) {
      const content = listMatch ? listMatch[2] : numMatch[2]
      if (!inList) { out.push('<ul class="list-disc pl-5 my-1 space-y-0.5">'); inList = true }
      out.push(`<li class="text-cyber-text text-sm opacity-80">${content}</li>`)
    } else {
      if (inList) { out.push('</ul>'); inList = false }
      if (line.trim() === '') {
        out.push('')
      } else {
        out.push(`<p class="my-1.5">${line}</p>`)
      }
    }
  }
  if (inList) out.push('</ul>')

  return out.join('\n')
}

function sectionBorder(heading) {
  const h = heading.toLowerCase()
  if (!heading) return 'border-cyber-border'
  if (h.includes('executive')) return 'border-cyber-accent'
  if (h.includes('critical') || h.includes('high')) return 'border-cyber-danger'
  if (h.includes('medium')) return 'border-cyber-medium'
  if (h.includes('narrative')) return 'border-cyber-warning'
  if (h.includes('recommended') || h.includes('action') || h.includes('remediation')) return 'border-green-500'
  if (h.includes('risk')) return 'border-orange-500'
  return 'border-cyber-border'
}
</script>
