<template>
  <div class="fixed inset-0 z-50 flex items-center justify-center bg-black/60" @click.self="$emit('close')">
    <div class="bg-cyber-surface border border-cyber-border rounded-lg w-full max-w-3xl mx-4 max-h-[85vh] flex flex-col">
      <div class="flex items-center justify-between p-4 border-b border-cyber-border">
        <h3 class="text-cyber-accent font-bold text-lg">HTTP Exchange Detail</h3>
        <button @click="$emit('close')"
          class="text-cyber-muted hover:text-cyber-text cursor-pointer text-xl leading-none">&times;</button>
      </div>
      <div class="p-4 overflow-y-auto flex-1 space-y-4">
        <div class="grid grid-cols-3 gap-3 text-xs">
          <div class="bg-cyber-bg rounded p-2">
            <span class="text-cyber-muted-2 block">Status</span>
            <span class="font-bold font-mono" :class="statusColor(data.status_code)">{{ data.status_code }}</span>
          </div>
          <div class="bg-cyber-bg rounded p-2">
            <span class="text-cyber-muted-2 block">Method</span>
            <span class="font-mono text-cyber-text">{{ data.method }}</span>
          </div>
          <div class="bg-cyber-bg rounded p-2">
            <span class="text-cyber-muted-2 block">Timing</span>
            <span class="text-cyber-text">{{ data.timing_ms }}ms</span>
          </div>
        </div>
        <div class="bg-cyber-bg rounded p-2 text-xs">
          <span class="text-cyber-muted-2 block mb-1">URL</span>
          <span class="text-cyber-text break-all font-mono">{{ data.url }}</span>
        </div>
        <div>
          <h4 class="text-cyber-accent text-sm font-bold mb-2">Request Headers</h4>
          <pre class="bg-cyber-bg border border-cyber-border rounded p-3 text-xs font-mono text-cyber-text max-h-48 overflow-y-auto whitespace-pre-wrap">{{ formatHeaders(data.request_headers) }}</pre>
        </div>
        <div v-if="data.request_body">
          <h4 class="text-cyber-accent text-sm font-bold mb-2">Request Body</h4>
          <pre class="bg-cyber-bg border border-cyber-border rounded p-3 text-xs font-mono text-cyber-text max-h-48 overflow-y-auto whitespace-pre-wrap">{{ data.request_body }}</pre>
        </div>
        <div>
          <h4 class="text-cyber-accent text-sm font-bold mb-2">Response Headers</h4>
          <pre class="bg-cyber-bg border border-cyber-border rounded p-3 text-xs font-mono text-cyber-text max-h-48 overflow-y-auto whitespace-pre-wrap">{{ formatHeaders(data.response_headers) }}</pre>
        </div>
        <div v-if="data.response_body">
          <h4 class="text-cyber-accent text-sm font-bold mb-2">Response Body</h4>
          <pre class="bg-cyber-bg border border-cyber-border rounded p-3 text-xs font-mono text-cyber-text max-h-64 overflow-y-auto whitespace-pre-wrap">{{ data.response_body }}</pre>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
defineProps({ data: { type: Object, required: true } })
defineEmits(['close'])

function formatHeaders(headers) {
  if (!headers) return '(empty)'
  if (typeof headers === 'string') {
    try {
      const parsed = JSON.parse(headers)
      return Object.entries(parsed).map(([k, v]) => `${k}: ${v}`).join('\n')
    } catch { return headers }
  }
  if (typeof headers === 'object') {
    return Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\n')
  }
  return String(headers)
}

function statusColor(code) {
  if (code >= 200 && code < 300) return 'text-cyber-accent'
  if (code >= 300 && code < 400) return 'text-cyber-medium'
  if (code >= 400 && code < 500) return 'text-cyber-warning'
  if (code >= 500) return 'text-cyber-danger'
  return 'text-cyber-muted-2'
}
</script>
