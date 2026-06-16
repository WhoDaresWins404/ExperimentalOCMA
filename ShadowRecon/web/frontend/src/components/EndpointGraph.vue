<template>
  <div ref="svgContainer" class="graph-svg-container"></div>
</template>

<script setup>
import { ref, onMounted, watch, onUnmounted } from 'vue'
import * as d3 from 'd3'

const props = defineProps({ graphData: { type: Object, default: () => ({ nodes: [], edges: [] }) } })
const svgContainer = ref(null)
let simulation = null
let svg = null

const colorMap = {
  host: '#4CAF50', endpoint: '#2196F3', api: '#FF9800',
  parameter: '#9C27B0', auth_provider: '#F44336',
  database: '#795548', static_asset: '#607D8B',
  application: '#00BCD4', unknown: '#9E9E9E',
}

onMounted(() => {
  initGraph()
})

onUnmounted(() => {
  if (simulation) simulation.stop()
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
    .attr('fill', d => {
      if (d.isFinding) return '#FFD700'
      return colorMap[d.type] || '#9E9E9E'
    })
    .attr('stroke', d => {
      if (d.isFinding) {
        const sevColors = { critical: '#ff1744', high: '#ff9100', medium: '#ffd600', low: '#00e5ff' }
        return sevColors[d.severity] || '#FFD700'
      }
      return '#1e3a5f'
    })
    .attr('stroke-width', 2)
    .style('cursor', 'pointer')
    .on('click', (event, d) => {
      if (d.url) {
        window.open(d.url, '_blank')
      }
    })
    .append('title')
    .text(d => `${d.label}\nType: ${d.type}${d.url ? '\nURL: ' + d.url : ''}`)

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
.graph-svg-container {
  width: 100%;
  height: 100%;
  min-height: 400px;
}
.graph-svg-container svg {
  display: block;
}
</style>
