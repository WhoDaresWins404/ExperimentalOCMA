<template>
  <div class="relative w-full h-full">
    <div class="flex gap-1.5 flex-wrap pb-2.5 mb-2.5 border-b border-cyber-border">
      <button v-for="f in filterDefs" :key="f.key"
        :class="['flex items-center gap-1.5 px-3 py-1.5 rounded text-xs cursor-pointer transition-all', typeFilter[f.key] ? 'bg-cyber-accent text-cyber-bg font-bold' : 'bg-cyber-bg border border-cyber-border text-cyber-muted hover:border-cyber-accent hover:text-cyber-text']"
        @click="toggleFilter(f.key)">
        <span class="w-2 h-2 rounded-full inline-block" :style="{ background: f.color }"></span>
        {{ f.label }}
      </button>
    </div>

    <div ref="svgContainer" class="relative w-full h-full min-h-[400px]">
      <div class="absolute bottom-3 right-3 bg-[rgba(10,14,23,0.85)] border border-cyber-border rounded-lg p-2.5 flex flex-col gap-1 pointer-events-none z-10">
        <div v-for="f in filterDefs" :key="f.key" class="flex items-center gap-1.5">
          <span class="w-2 h-2 rounded-full flex-shrink-0" :style="{ background: f.color }"></span>
          <span class="text-cyber-muted text-xs">{{ f.label }}</span>
        </div>
      </div>
    </div>

    <div
      ref="tooltip"
      class="absolute pointer-events-none bg-cyber-surface border border-cyber-border rounded-lg p-3 text-xs leading-relaxed z-50 max-w-[320px] shadow-xl"
      :style="tooltipStyle"
      v-show="tooltipVisible"
    >
      <div class="flex justify-between items-center gap-2 mb-2 pb-1.5 border-b border-cyber-border">
        <span class="text-cyber-accent font-bold text-sm word-break break-all">{{ tooltipData.label }}</span>
        <span v-if="tooltipData.severity" class="inline-block px-2 py-0.5 rounded-full text-[10px] font-bold uppercase whitespace-nowrap" :class="sevClass(tooltipData.severity)">{{ tooltipData.severity }}</span>
      </div>
      <div class="flex flex-col gap-0.5">
        <div v-if="tooltipData.type" class="flex gap-1.5 items-baseline">
          <span class="text-cyber-muted-2 min-w-[70px] text-[11px] flex-shrink-0">Type</span>
          <span class="text-cyber-text text-[11px] word-break break-all">{{ tooltipData.typeDisplay }}</span>
        </div>
        <div v-if="tooltipData.url" class="flex gap-1.5 items-baseline">
          <span class="text-cyber-muted-2 min-w-[70px] text-[11px] flex-shrink-0">URL</span>
          <span class="text-cyber-accent text-[11px] word-break break-all">{{ tooltipData.url }}</span>
        </div>
        <div v-if="tooltipData.cvss" class="flex gap-1.5 items-baseline">
          <span class="text-cyber-muted-2 min-w-[70px] text-[11px] flex-shrink-0">CVSS</span>
          <span class="text-[11px] font-bold" :class="cvssClass(tooltipData.cvssColor)">{{ tooltipData.cvss }}</span>
        </div>
        <div v-if="tooltipData.scanner" class="flex gap-1.5 items-baseline">
          <span class="text-cyber-muted-2 min-w-[70px] text-[11px] flex-shrink-0">Scanner</span>
          <span class="text-cyber-text text-[11px]">{{ tooltipData.scanner }}</span>
        </div>
        <div v-if="tooltipData.confidence" class="flex gap-1.5 items-baseline">
          <span class="text-cyber-muted-2 min-w-[70px] text-[11px] flex-shrink-0">Confidence</span>
          <span class="text-cyber-text text-[11px]">{{ (tooltipData.confidence * 100).toFixed(0) }}%</span>
        </div>
        <div v-if="tooltipData.method" class="flex gap-1.5 items-baseline">
          <span class="text-cyber-muted-2 min-w-[70px] text-[11px] flex-shrink-0">Method</span>
          <span class="text-cyber-text text-[11px]">{{ tooltipData.method }}</span>
        </div>
        <div v-if="tooltipData.statusCode" class="flex gap-1.5 items-baseline">
          <span class="text-cyber-muted-2 min-w-[70px] text-[11px] flex-shrink-0">Status</span>
          <span class="text-cyber-text text-[11px]">{{ tooltipData.statusCode }}</span>
        </div>
        <div v-if="tooltipData.responseSize" class="flex gap-1.5 items-baseline">
          <span class="text-cyber-muted-2 min-w-[70px] text-[11px] flex-shrink-0">Size</span>
          <span class="text-cyber-text text-[11px]">{{ tooltipData.responseSize }}</span>
        </div>
        <div v-if="tooltipData.contentType" class="flex gap-1.5 items-baseline">
          <span class="text-cyber-muted-2 min-w-[70px] text-[11px] flex-shrink-0">Content-Type</span>
          <span class="text-cyber-text text-[11px]">{{ tooltipData.contentType }}</span>
        </div>
        <div v-if="tooltipData.path" class="flex gap-1.5 items-baseline">
          <span class="text-cyber-muted-2 min-w-[70px] text-[11px] flex-shrink-0">Path</span>
          <span class="text-cyber-text text-[11px]">{{ tooltipData.path }}</span>
        </div>
        <div v-if="tooltipData.discoveredBy" class="flex gap-1.5 items-baseline">
          <span class="text-cyber-muted-2 min-w-[70px] text-[11px] flex-shrink-0">Discovered By</span>
          <span class="text-cyber-text text-[11px]">{{ tooltipData.discoveredBy }}</span>
        </div>
        <div v-if="tooltipData.description" class="flex gap-1.5 items-baseline">
          <span class="text-cyber-muted-2 min-w-[70px] text-[11px] flex-shrink-0">Description</span>
          <span class="text-cyber-muted text-[10px] max-h-12 overflow-hidden">{{ tooltipData.description }}</span>
        </div>
        <div v-if="tooltipData.remediation" class="flex gap-1.5 items-baseline">
          <span class="text-cyber-muted-2 min-w-[70px] text-[11px] flex-shrink-0">Remediation</span>
          <span class="text-cyber-muted text-[10px] max-h-12 overflow-hidden">{{ tooltipData.remediation }}</span>
        </div>
        <div v-if="tooltipData.llmDesc" class="flex gap-1.5 items-baseline">
          <span class="text-cyber-muted-2 min-w-[70px] text-[11px] flex-shrink-0">LLM</span>
          <span class="text-cyber-muted text-[10px] max-h-12 overflow-hidden">{{ tooltipData.llmDesc }}</span>
        </div>
        <div v-if="tooltipData.orphan" class="flex gap-1.5 items-baseline">
          <span class="text-cyber-muted-2 min-w-[70px] text-[11px] flex-shrink-0">Note</span>
          <span class="text-cyber-warning text-[11px]">Not linked to specific endpoint</span>
        </div>
        <div v-if="tooltipData.tags && tooltipData.tags.length" class="flex gap-1.5 items-baseline">
          <span class="text-cyber-muted-2 min-w-[70px] text-[11px] flex-shrink-0">Tags</span>
          <span class="flex gap-1 flex-wrap">
            <span v-for="t in tooltipData.tags" :key="t" class="bg-cyber-bg px-1.5 py-0.5 rounded text-cyber-muted text-[10px]">{{ t }}</span>
          </span>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted, watch, onUnmounted, reactive } from 'vue'
import * as d3 from 'd3'

const props = defineProps({ graphData: { type: Object, default: () => ({ nodes: [], edges: [] }) } })
const svgContainer = ref(null)
const tooltip = ref(null)
const tooltipVisible = ref(false)
const tooltipStyle = ref({})
const tooltipData = reactive({})

let simulation = null
let svg = null
const pinnedPositions = new Map()

const typeFilter = ref({
  host: true, endpoint: true, api: true,
  auth_provider: true, database: true, static_asset: true, finding: true,
})

const filterDefs = [
  { key: 'host', label: 'Host', color: '#4CAF50' },
  { key: 'endpoint', label: 'Endpoint', color: '#2196F3' },
  { key: 'api', label: 'API', color: '#FF9800' },
  { key: 'auth_provider', label: 'Auth', color: '#F44336' },
  { key: 'database', label: 'Database', color: '#795548' },
  { key: 'static_asset', label: 'Static', color: '#607D8B' },
  { key: 'finding', label: 'Findings', color: '#FFD700' },
]

function toggleFilter(key) {
  typeFilter.value[key] = !typeFilter.value[key]
  updateGraph()
}

const colorMap = {
  host: '#4CAF50', endpoint: '#2196F3', api: '#FF9800',
  auth_provider: '#F44336', database: '#795548',
  static_asset: '#607D8B', unknown: '#9E9E9E',
}

const sevColors = { critical: '#ff1744', high: '#ff9100', medium: '#ffd600', low: '#00e5ff' }
const typeDisplayNames = {
  host: 'Host', endpoint: 'Endpoint', api: 'API',
  auth_provider: 'Auth Provider', database: 'Database',
  static_asset: 'Static Asset', unknown: 'Unknown',
}

function sevClass(severity) {
  const s = severity.toLowerCase()
  if (s === 'critical') return 'bg-cyber-danger text-white'
  if (s === 'high') return 'bg-cyber-warning text-black'
  if (s === 'medium') return 'bg-cyber-medium text-black'
  if (s === 'low') return 'bg-cyber-accent text-black'
  return 'bg-blue-500 text-white'
}

function cvssClass(color) {
  return {
    critical: 'text-cyber-danger',
    high: 'text-cyber-warning',
    medium: 'text-cyber-medium',
    low: 'text-cyber-accent',
  }[color] || ''
}

function hideTooltip() { tooltipVisible.value = false }

function showTooltip(event, d) {
  const rect = svgContainer.value.getBoundingClientRect()
  const meta = d.metadata || {}
  const cvss = meta.cvss_score
  let cvssColor = 'low'
  if (cvss >= 9) cvssColor = 'critical'
  else if (cvss >= 7) cvssColor = 'high'
  else if (cvss >= 4) cvssColor = 'medium'
  const size = meta.response_size
  let sizeStr = ''
  if (size) sizeStr = size > 1024 ? (size / 1024).toFixed(1) + 'KB' : size + 'B'
  const url = d.url || ''
  let path = ''
  try { path = new URL(url).pathname } catch (e) { path = url }
  Object.assign(tooltipData, {
    label: d.label || '', type: d.type || '', typeDisplay: typeDisplayNames[d.type] || d.type || '', url, path,
    severity: d.severity || meta.severity || '', cvss: cvss != null ? cvss.toFixed(1) : '', cvssColor,
    scanner: meta.scanner || '', confidence: meta.confidence || '', method: meta.method || '',
    statusCode: meta.status_code || '', responseSize: sizeStr, contentType: meta.content_type || '',
    description: meta.description || '', remediation: meta.remediation || '', llmDesc: meta.llm_description || '',
    orphan: meta.orphan || false, discoveredBy: meta.discovered_by || '', tags: meta.tags || [],
  })
  tooltipVisible.value = true
}

function moveTooltip(event) {
  const rect = svgContainer.value.getBoundingClientRect()
  let left = event.clientX - rect.left + 12
  let top = event.clientY - rect.top - 10
  const tw = tooltip.value?.offsetWidth || 280
  const th = tooltip.value?.offsetHeight || 200
  if (left + tw > rect.width - 10) left = event.clientX - rect.left - tw - 12
  if (top + th > rect.height - 10) top = rect.height - th - 10
  if (top < 10) top = 10
  tooltipStyle.value = { left: left + 'px', top: top + 'px' }
}

onMounted(() => { initGraph() })
onUnmounted(() => {
  if (simulation) simulation.stop()
  window.removeEventListener('scroll', hideTooltip, true)
})
watch(() => props.graphData, () => { if (svgContainer.value) updateGraph() }, { deep: true })

function initGraph() {
  if (!svgContainer.value) return
  const container = svgContainer.value
  const width = container.clientWidth || 800
  const height = container.clientHeight || 600
  svg = d3.select(container).append('svg').attr('width', width).attr('height', height).attr('viewBox', [0, 0, width, height]).style('background', '#0a0e17')
  svg.append('defs').append('marker').attr('id', 'arrowhead').attr('viewBox', '0 -5 10 10').attr('refX', 20).attr('refY', 0).attr('markerWidth', 6).attr('markerHeight', 6).attr('orient', 'auto').append('path').attr('d', 'M0,-5L10,0L0,5').attr('fill', '#90A4AE')
  const zoom = d3.zoom().scaleExtent([0.1, 4]).on('zoom', (event) => { svg.select('g.graph-group').attr('transform', event.transform) })
  svg.call(zoom)
  svg.append('g').attr('class', 'graph-group')
  window.addEventListener('scroll', hideTooltip, true)
  updateGraph()
}

function getActiveTypes() {
  const active = new Set()
  for (const [key, val] of Object.entries(typeFilter.value)) { if (val) active.add(key) }
  return active
}

function updateGraph() {
  if (!svg) return
  const { nodes = [], edges = [] } = props.graphData
  if (nodes.length === 0) return
  const activeTypes = getActiveTypes()
  const container = svgContainer.value
  const width = container.clientWidth || 800
  const height = container.clientHeight || 600
  svg.attr('width', width).attr('height', height).attr('viewBox', [0, 0, width, height])
  const g = svg.select('g.graph-group')
  const nodeData = nodes.map(n => {
    const meta = n.metadata || {}
    const obj = { id: n.id || n.label, label: n.label || '?', type: n.node_type || 'unknown', isFinding: meta.is_finding || false, severity: meta.severity || '', url: n.url || '', metadata: meta }
    if (pinnedPositions.has(obj.id)) { const p = pinnedPositions.get(obj.id); obj.fx = p.fx; obj.fy = p.fy; obj.x = p.x; obj.y = p.y }
    return obj
  }).filter(n => activeTypes.has(n.type) || (n.isFinding && activeTypes.has('finding')))
  const validIds = new Set(nodeData.map(n => n.id))
  const linkData = edges.map(e => ({ source: e.source_node || e.source, target: e.target_node || e.target, type: e.edge_type || 'unknown', label: e.label || '' })).filter(e => validIds.has(e.source) && validIds.has(e.target))
  if (simulation) simulation.stop()
  const nodeCount = nodeData.length
  simulation = d3.forceSimulation(nodeData)
    .force('link', d3.forceLink(linkData).id(d => d.id).distance(d => Math.max(60, 200 / Math.sqrt(nodeCount))))
    .force('charge', d3.forceManyBody().strength(Math.min(-200, -nodeCount * 5)))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force('collision', d3.forceCollide(Math.max(20, Math.min(50, 400 / Math.sqrt(nodeCount)))))
  const link = g.selectAll('line').data(linkData, d => `${d.source}-${d.target}`).join('line').attr('stroke', '#1e3a5f').attr('stroke-width', 1.5).attr('marker-end', 'url(#arrowhead)')
  const node = g.selectAll('g.node').data(nodeData, d => d.id).join('g').attr('class', 'node').call(d3.drag().on('start', (event, d) => { if (!event.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y }).on('drag', (event, d) => { d.fx = event.x; d.fy = event.y }).on('end', (event, d) => { if (!event.active) simulation.alphaTarget(0); d.fx = d.x; d.fy = d.y; pinnedPositions.set(d.id, { fx: d.x, fy: d.y, x: d.x, y: d.y }) }))
  const nodeRadius = d => d.isFinding ? 14 : (d.type === 'host' ? 18 : 9)
  node.selectAll('circle').data(d => [d]).join('circle').attr('r', nodeRadius).attr('fill', d => d.isFinding ? '#FFD700' : (colorMap[d.type] || '#9E9E9E')).attr('stroke', d => d.isFinding ? (sevColors[d.severity] || '#FFD700') : '#1e3a5f').attr('stroke-width', d => d.isFinding ? 2.5 : 1.5).style('cursor', 'pointer').on('click', (event, d) => { if (d.url) window.open(d.url, '_blank') }).on('mouseenter', (event, d) => { showTooltip(event, d) }).on('mousemove', (event, d) => { moveTooltip(event) }).on('mouseleave', () => { hideTooltip() })
  simulation.on('tick', () => { link.attr('x1', d => d.source.x).attr('y1', d => d.source.y).attr('x2', d => d.target.x).attr('y2', d => d.target.y); node.attr('transform', d => `translate(${d.x},${d.y})`) })
}
</script>
