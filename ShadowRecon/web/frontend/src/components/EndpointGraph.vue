<template>
  <div class="graph-wrapper">
    <div class="graph-filters">
      <button v-for="f in filterDefs" :key="f.key"
        :class="['filter-btn', { active: typeFilter[f.key] }]"
        @click="toggleFilter(f.key)">
        <span class="filter-dot" :style="{ background: f.color }"></span>
        {{ f.label }}
      </button>
    </div>

    <div ref="svgContainer" class="graph-svg-container">
      <div class="graph-legend">
        <div v-for="f in filterDefs" :key="f.key" class="legend-item">
          <span class="legend-dot" :style="{ background: f.color }"></span>
          <span class="legend-label">{{ f.label }}</span>
        </div>
      </div>
    </div>

    <div
      ref="tooltip"
      class="graph-tooltip"
      :style="tooltipStyle"
      v-show="tooltipVisible"
    >
      <div class="tooltip-header">
        <span class="tooltip-title">{{ tooltipData.label }}</span>
        <span v-if="tooltipData.severity" :class="'sev-badge sev-' + tooltipData.severity">{{ tooltipData.severity }}</span>
      </div>
      <div class="tooltip-body">
        <div v-if="tooltipData.type" class="tt-row"><span class="tt-label">Type</span><span class="tt-val">{{ tooltipData.typeDisplay }}</span></div>
        <div v-if="tooltipData.url" class="tt-row"><span class="tt-label">URL</span><span class="tt-val tt-url">{{ tooltipData.url }}</span></div>
        <div v-if="tooltipData.cvss" class="tt-row"><span class="tt-label">CVSS</span><span class="tt-val" :class="'cvss-' + tooltipData.cvssColor">{{ tooltipData.cvss }}</span></div>
        <div v-if="tooltipData.scanner" class="tt-row"><span class="tt-label">Scanner</span><span class="tt-val">{{ tooltipData.scanner }}</span></div>
        <div v-if="tooltipData.confidence" class="tt-row"><span class="tt-label">Confidence</span><span class="tt-val">{{ (tooltipData.confidence * 100).toFixed(0) }}%</span></div>
        <div v-if="tooltipData.method" class="tt-row"><span class="tt-label">Method</span><span class="tt-val">{{ tooltipData.method }}</span></div>
        <div v-if="tooltipData.statusCode" class="tt-row"><span class="tt-label">Status</span><span class="tt-val">{{ tooltipData.statusCode }}</span></div>
        <div v-if="tooltipData.responseSize" class="tt-row"><span class="tt-label">Size</span><span class="tt-val">{{ tooltipData.responseSize }}</span></div>
        <div v-if="tooltipData.contentType" class="tt-row"><span class="tt-label">Content-Type</span><span class="tt-val">{{ tooltipData.contentType }}</span></div>
        <div v-if="tooltipData.path" class="tt-row"><span class="tt-label">Path</span><span class="tt-val">{{ tooltipData.path }}</span></div>
        <div v-if="tooltipData.discoveredBy" class="tt-row"><span class="tt-label">Discovered By</span><span class="tt-val">{{ tooltipData.discoveredBy }}</span></div>
        <div v-if="tooltipData.description" class="tt-row tt-desc"><span class="tt-label">Description</span><span class="tt-val">{{ tooltipData.description }}</span></div>
        <div v-if="tooltipData.remediation" class="tt-row tt-desc"><span class="tt-label">Remediation</span><span class="tt-val">{{ tooltipData.remediation }}</span></div>
        <div v-if="tooltipData.llmDesc" class="tt-row tt-desc"><span class="tt-label">LLM</span><span class="tt-val">{{ tooltipData.llmDesc }}</span></div>
        <div v-if="tooltipData.orphan" class="tt-row"><span class="tt-label">Note</span><span class="tt-val tt-warn">Not linked to specific endpoint</span></div>
        <div v-if="tooltipData.tags && tooltipData.tags.length" class="tt-row">
          <span class="tt-label">Tags</span>
          <span class="tt-val"><span v-for="t in tooltipData.tags" :key="t" class="tt-tag">{{ t }}</span></span>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, watch, onUnmounted, reactive } from 'vue'
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
  host: true,
  endpoint: true,
  api: true,
  auth_provider: true,
  database: true,
  static_asset: true,
  finding: true,
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

function hideTooltip() {
  tooltipVisible.value = false
}

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
    label: d.label || '',
    type: d.type || '',
    typeDisplay: typeDisplayNames[d.type] || d.type || '',
    url,
    path,
    severity: d.severity || meta.severity || '',
    cvss: cvss != null ? cvss.toFixed(1) : '',
    cvssColor,
    scanner: meta.scanner || '',
    confidence: meta.confidence || '',
    method: meta.method || '',
    statusCode: meta.status_code || '',
    responseSize: sizeStr,
    contentType: meta.content_type || '',
    description: meta.description || '',
    remediation: meta.remediation || '',
    llmDesc: meta.llm_description || '',
    orphan: meta.orphan || false,
    discoveredBy: meta.discovered_by || '',
    tags: meta.tags || [],
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

watch(() => props.graphData, () => {
  if (svgContainer.value) updateGraph()
}, { deep: true })

function initGraph() {
  if (!svgContainer.value) return
  const container = svgContainer.value
  const width = container.clientWidth || 800
  const height = container.clientHeight || 600

  svg = d3.select(container)
    .append('svg')
    .attr('width', width)
    .attr('height', height)
    .attr('viewBox', [0, 0, width, height])
    .style('background', '#0a0e17')

  svg.append('defs').append('marker')
    .attr('id', 'arrowhead')
    .attr('viewBox', '0 -5 10 10')
    .attr('refX', 20)
    .attr('refY', 0)
    .attr('markerWidth', 6)
    .attr('markerHeight', 6)
    .attr('orient', 'auto')
    .append('path')
    .attr('d', 'M0,-5L10,0L0,5')
    .attr('fill', '#90A4AE')

  const zoom = d3.zoom()
    .scaleExtent([0.1, 4])
    .on('zoom', (event) => {
      svg.select('g.graph-group').attr('transform', event.transform)
    })
  svg.call(zoom)

  svg.append('g').attr('class', 'graph-group')

  window.addEventListener('scroll', hideTooltip, true)
  updateGraph()
}

function getActiveTypes() {
  const active = new Set()
  for (const [key, val] of Object.entries(typeFilter.value)) {
    if (val) active.add(key)
  }
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
  svg.attr('width', width).attr('height', height)
  svg.attr('viewBox', [0, 0, width, height])

  const g = svg.select('g.graph-group')

  const nodeData = nodes
    .map(n => {
      const meta = n.metadata || {}
      const obj = {
        id: n.id || n.label,
        label: n.label || '?',
        type: n.node_type || 'unknown',
        isFinding: meta.is_finding || false,
        severity: meta.severity || '',
        url: n.url || '',
        metadata: meta,
      }
      if (pinnedPositions.has(obj.id)) {
        const p = pinnedPositions.get(obj.id)
        obj.fx = p.fx; obj.fy = p.fy
        obj.x = p.x; obj.y = p.y
      }
      return obj
    })
    .filter(n => activeTypes.has(n.type) || (n.isFinding && activeTypes.has('finding')))

  const validIds = new Set(nodeData.map(n => n.id))
  const linkData = edges
    .map(e => ({
      source: e.source_node || e.source,
      target: e.target_node || e.target,
      type: e.edge_type || 'unknown',
      label: e.label || '',
    }))
    .filter(e => validIds.has(e.source) && validIds.has(e.target))

  if (simulation) simulation.stop()

  const nodeCount = nodeData.length
  const chargeStrength = Math.min(-200, -nodeCount * 5)
  const collideRadius = Math.max(20, Math.min(50, 400 / Math.sqrt(nodeCount)))

  simulation = d3.forceSimulation(nodeData)
    .force('link', d3.forceLink(linkData).id(d => d.id).distance(d => Math.max(60, 200 / Math.sqrt(nodeCount))))
    .force('charge', d3.forceManyBody().strength(chargeStrength))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force('collision', d3.forceCollide(collideRadius))

  const link = g.selectAll('line')
    .data(linkData, d => `${d.source}-${d.target}`)
    .join('line')
    .attr('stroke', '#1e3a5f')
    .attr('stroke-width', 1.5)
    .attr('marker-end', 'url(#arrowhead)')

  const node = g.selectAll('g.node')
    .data(nodeData, d => d.id)
    .join('g')
    .attr('class', 'node')
    .call(d3.drag()
      .on('start', (event, d) => {
        if (!event.active) simulation.alphaTarget(0.3).restart()
        d.fx = d.x
        d.fy = d.y
      })
      .on('drag', (event, d) => {
        d.fx = event.x
        d.fy = event.y
      })
      .on('end', (event, d) => {
        if (!event.active) simulation.alphaTarget(0)
        d.fx = d.x
        d.fy = d.y
        pinnedPositions.set(d.id, { fx: d.x, fy: d.y, x: d.x, y: d.y })
      })
    )

  const nodeRadius = d => d.isFinding ? 14 : (d.type === 'host' ? 18 : 9)

  node.selectAll('circle')
    .data(d => [d])
    .join('circle')
    .attr('r', nodeRadius)
    .attr('fill', d => {
      if (d.isFinding) return '#FFD700'
      return colorMap[d.type] || '#9E9E9E'
    })
    .attr('stroke', d => {
      if (d.isFinding) return sevColors[d.severity] || '#FFD700'
      return '#1e3a5f'
    })
    .attr('stroke-width', d => d.isFinding ? 2.5 : 1.5)
    .style('cursor', 'pointer')
    .on('click', (event, d) => {
      if (d.url) window.open(d.url, '_blank')
    })
    .on('mouseenter', (event, d) => {
      showTooltip(event, d)
    })
    .on('mousemove', (event, d) => {
      moveTooltip(event)
    })
    .on('mouseleave', () => {
      hideTooltip()
    })

  simulation.on('tick', () => {
    link
      .attr('x1', d => d.source.x)
      .attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x)
      .attr('y2', d => d.target.y)
    node.attr('transform', d => `translate(${d.x},${d.y})`)
  })
}
</script>

<style scoped>
.graph-wrapper { position: relative; width: 100%; height: 100%; }

.graph-filters {
  display: flex; gap: 6px; flex-wrap: wrap; padding: 10px 0;
  border-bottom: 1px solid #1e3a5f; margin-bottom: 10px;
}
.filter-btn {
  display: flex; align-items: center; gap: 5px;
  background: #0a0e17; border: 1px solid #1e3a5f;
  color: #8899aa; padding: 5px 12px; border-radius: 4px;
  font-size: 0.8em; cursor: pointer; transition: all 0.2s;
}
.filter-btn:hover { border-color: #00e5ff; color: #e0e0e0; }
.filter-btn.active { background: #1a2a4a; border-color: #00e5ff; color: #00e5ff; }
.filter-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }

.graph-svg-container {
  position: relative;
  width: 100%; height: 100%; min-height: 400px;
}
.graph-svg-container svg { display: block; }

.graph-legend {
  position: absolute; bottom: 12px; right: 12px;
  background: rgba(10, 14, 23, 0.85); border: 1px solid #1e3a5f;
  border-radius: 6px; padding: 8px 12px; display: flex; flex-direction: column; gap: 3px;
  pointer-events: none; z-index: 10;
}
.legend-item { display: flex; align-items: center; gap: 6px; }
.legend-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
.legend-label { color: #8899aa; font-size: 0.75em; }

.graph-tooltip {
  position: absolute; pointer-events: none;
  background: #111927; border: 1px solid #1e3a5f;
  border-radius: 8px; padding: 12px; font-size: 12px;
  line-height: 1.5; z-index: 1000; max-width: 320px;
  box-shadow: 0 4px 20px rgba(0,0,0,0.5);
}
.tooltip-header {
  display: flex; justify-content: space-between; align-items: center;
  gap: 8px; margin-bottom: 8px; padding-bottom: 6px;
  border-bottom: 1px solid #1e3a5f;
}
.tooltip-title { color: #00e5ff; font-weight: bold; font-size: 13px; word-break: break-all; }
.sev-badge {
  display: inline-block; padding: 2px 8px; border-radius: 10px;
  font-size: 10px; font-weight: bold; text-transform: uppercase; white-space: nowrap;
}
.sev-critical { background: #ff1744; color: #fff; }
.sev-high { background: #ff9100; color: #000; }
.sev-medium { background: #ffd600; color: #000; }
.sev-low { background: #00e5ff; color: #000; }
.sev-none { background: #2979ff; color: #fff; }
.tooltip-body { display: flex; flex-direction: column; gap: 3px; }
.tt-row { display: flex; gap: 6px; align-items: baseline; }
.tt-label { color: #556677; min-width: 70px; font-size: 11px; flex-shrink: 0; }
.tt-val { color: #e0e0e0; font-size: 11px; word-break: break-all; }
.tt-url { color: #00e5ff; }
.tt-warn { color: #ff9800; }
.tt-desc .tt-val { font-size: 10px; color: #8899aa; max-height: 48px; overflow: hidden; }
.cvss-critical { color: #ff1744; font-weight: bold; }
.cvss-high { color: #ff9100; font-weight: bold; }
.cvss-medium { color: #ffd600; font-weight: bold; }
.cvss-low { color: #00e5ff; }
.tt-tag {
  display: inline-block; background: #0a0e17;
  padding: 1px 6px; border-radius: 4px; font-size: 10px;
  color: #8899aa; margin-right: 3px;
}
</style>