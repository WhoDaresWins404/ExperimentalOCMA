<template>
  <div class="graph-wrapper">
    <div ref="svgContainer" class="graph-svg-container"></div>
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
        <div v-if="tooltipData.type" class="tt-row"><span class="tt-label">Type</span><span class="tt-val">{{ tooltipData.type }}</span></div>
        <div v-if="tooltipData.url" class="tt-row"><span class="tt-label">URL</span><span class="tt-val tt-url">{{ tooltipData.url }}</span></div>
        <div v-if="tooltipData.cvss" class="tt-row"><span class="tt-label">CVSS</span><span class="tt-val" :class="'cvss-' + tooltipData.cvssColor">{{ tooltipData.cvss }}</span></div>
        <div v-if="tooltipData.scanner" class="tt-row"><span class="tt-label">Scanner</span><span class="tt-val">{{ tooltipData.scanner }}</span></div>
        <div v-if="tooltipData.confidence" class="tt-row"><span class="tt-label">Confidence</span><span class="tt-val">{{ (tooltipData.confidence * 100).toFixed(0) }}%</span></div>
        <div v-if="tooltipData.method" class="tt-row"><span class="tt-label">Method</span><span class="tt-val">{{ tooltipData.method }}</span></div>
        <div v-if="tooltipData.statusCode" class="tt-row"><span class="tt-label">Status</span><span class="tt-val">{{ tooltipData.statusCode }}</span></div>
        <div v-if="tooltipData.responseSize" class="tt-row"><span class="tt-label">Size</span><span class="tt-val">{{ tooltipData.responseSize }}</span></div>
        <div v-if="tooltipData.contentType" class="tt-row"><span class="tt-label">Content-Type</span><span class="tt-val">{{ tooltipData.contentType }}</span></div>
        <div v-if="tooltipData.description" class="tt-row tt-desc"><span class="tt-label">Description</span><span class="tt-val">{{ tooltipData.description }}</span></div>
        <div v-if="tooltipData.remediation" class="tt-row tt-desc"><span class="tt-label">Remediation</span><span class="tt-val">{{ tooltipData.remediation }}</span></div>
        <div v-if="tooltipData.llmDesc" class="tt-row tt-desc"><span class="tt-label">LLM</span><span class="tt-val">{{ tooltipData.llmDesc }}</span></div>
        <div v-if="tooltipData.tags && tooltipData.tags.length" class="tt-row">
          <span class="tt-label">Tags</span>
          <span class="tt-val"><span v-for="t in tooltipData.tags" :key="t" class="tt-tag">{{ t }}</span></span>
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

const colorMap = {
  host: '#4CAF50', endpoint: '#2196F3', api: '#FF9800',
  parameter: '#9C27B0', auth_provider: '#F44336',
  database: '#795548', static_asset: '#607D8B',
  application: '#00BCD4', unknown: '#9E9E9E',
}

const sevColors = { critical: '#ff1744', high: '#ff9100', medium: '#ffd600', low: '#00e5ff' }

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

  Object.assign(tooltipData, {
    label: d.label || '',
    type: d.type || '',
    url: d.url || '',
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
      svg.select('g').attr('transform', event.transform)
    })
  svg.call(zoom)

  svg.append('g').attr('class', 'graph-group')

  window.addEventListener('scroll', hideTooltip, true)
  updateGraph()
}

function updateGraph() {
  if (!svg) return
  const { nodes = [], edges = [] } = props.graphData
  if (nodes.length === 0) return

  const container = svgContainer.value
  const width = container.clientWidth || 800
  const height = container.clientHeight || 600
  svg.attr('width', width).attr('height', height)
  svg.attr('viewBox', [0, 0, width, height])

  const g = svg.select('g.graph-group')

  const nodeData = nodes.map(n => ({
    id: n.id || n.label,
    label: n.label || '?',
    type: n.node_type || 'unknown',
    isFinding: n.metadata?.is_finding || false,
    severity: n.metadata?.severity || '',
    url: n.url || '',
    metadata: n.metadata || {},
  }))

  const linkData = edges.map(e => ({
    source: e.source_node || e.source,
    target: e.target_node || e.target,
    type: e.edge_type || 'unknown',
    label: e.label || '',
  }))

  if (simulation) simulation.stop()

  simulation = d3.forceSimulation(nodeData)
    .force('link', d3.forceLink(linkData).id(d => d.id).distance(100))
    .force('charge', d3.forceManyBody().strength(-200))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force('collision', d3.forceCollide(30))

  const link = g.selectAll('line')
    .data(linkData, d => `${d.source}-${d.target}`)
    .join('line')
    .attr('stroke', '#1e3a5f')
    .attr('stroke-width', 1.5)
    .attr('marker-end', 'url(#arrowhead)')

  const linkLabel = g.selectAll('text.link-label')
    .data(linkData, d => `${d.source}-${d.target}`)
    .join('text')
    .attr('class', 'link-label')
    .text(d => d.label)
    .attr('font-size', 9)
    .attr('fill', '#556677')
    .attr('text-anchor', 'middle')

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
        d.fx = null
        d.fy = null
      })
    )

  const nodeRadius = d => d.isFinding ? 18 : 12

  node.selectAll('circle')
    .data(d => [d])
    .join('circle')
    .attr('r', nodeRadius)
    .attr('fill', d => d.isFinding ? '#FFD700' : (colorMap[d.type] || '#9E9E9E'))
    .attr('stroke', d => {
      if (d.isFinding) return sevColors[d.severity] || '#FFD700'
      return '#1e3a5f'
    })
    .attr('stroke-width', 2)
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

  node.selectAll('text.node-label')
    .data(d => [d])
    .join('text')
    .attr('class', 'node-label')
    .text(d => d.label.length > 15 ? d.label.slice(0, 12) + '...' : d.label)
    .attr('dy', d => nodeRadius(d) + 14)
    .attr('text-anchor', 'middle')
    .attr('fill', '#8899aa')
    .attr('font-size', 10)

  simulation.on('tick', () => {
    link
      .attr('x1', d => d.source.x)
      .attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x)
      .attr('y2', d => d.target.y)
    linkLabel
      .attr('x', d => (d.source.x + d.target.x) / 2)
      .attr('y', d => (d.source.y + d.target.y) / 2)
    node.attr('transform', d => `translate(${d.x},${d.y})`)
  })
}
</script>

<style scoped>
.graph-wrapper {
  position: relative;
  width: 100%;
  height: 100%;
}
.graph-svg-container {
  width: 100%;
  height: 100%;
  min-height: 400px;
}
.graph-svg-container svg {
  display: block;
}
.graph-tooltip {
  position: absolute;
  pointer-events: none;
  background: #111927;
  border: 1px solid #1e3a5f;
  border-radius: 8px;
  padding: 12px;
  font-size: 12px;
  line-height: 1.5;
  z-index: 1000;
  max-width: 320px;
  box-shadow: 0 4px 20px rgba(0,0,0,0.5);
}
.tooltip-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
  padding-bottom: 6px;
  border-bottom: 1px solid #1e3a5f;
}
.tooltip-title {
  color: #00e5ff;
  font-weight: bold;
  font-size: 13px;
  word-break: break-all;
}
.sev-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 10px;
  font-weight: bold;
  text-transform: uppercase;
  white-space: nowrap;
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
.tt-desc .tt-val { font-size: 10px; color: #8899aa; max-height: 48px; overflow: hidden; }
.cvss-critical { color: #ff1744; font-weight: bold; }
.cvss-high { color: #ff9100; font-weight: bold; }
.cvss-medium { color: #ffd600; font-weight: bold; }
.cvss-low { color: #00e5ff; }
.tt-tag {
  display: inline-block;
  background: #0a0e17;
  padding: 1px 6px;
  border-radius: 4px;
  font-size: 10px;
  color: #8899aa;
  margin-right: 3px;
}
</style>