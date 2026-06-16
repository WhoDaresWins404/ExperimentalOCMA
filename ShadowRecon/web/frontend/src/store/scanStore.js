import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import axios from 'axios'

const API = '/api'

export const useScanStore = defineStore('scan', () => {
  const campaigns = ref([])
  const currentSession = ref(null)
  const findings = ref([])
  const endpoints = ref([])
  const graphData = ref({ nodes: [], edges: [] })
  const scanStatus = ref('idle')
  const ws = ref(null)
  const connected = ref(false)

  async function fetchCampaigns() {
    const { data } = await axios.get(`${API}/campaigns`)
    campaigns.value = data
  }

  async function getCampaign(id) {
    const { data } = await axios.get(`${API}/campaigns/${id}`)
    return data
  }

  async function startScan(params) {
    const { data } = await axios.post(`${API}/scan`, params)
    return data
  }

  async function getScanStatus(sessionId) {
    const { data } = await axios.get(`${API}/scan/${sessionId}/status`)
    return data
  }

  async function getScanResults(sessionId) {
    const { data } = await axios.get(`${API}/scan/${sessionId}/results`)
    return data
  }

  async function getScanMap(sessionId) {
    const { data } = await axios.get(`${API}/scan/${sessionId}/map`)
    graphData.value = data
    return data
  }

  function connectWebSocket(sessionId) {
    if (ws.value) ws.value.close()
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:'
    const url = `${protocol}//${location.host}/ws/scan/${sessionId}`
    ws.value = new WebSocket(url)
    ws.value.onopen = () => { connected.value = true }
    ws.value.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data)
        handleWsMessage(msg)
      } catch (e) {
        console.error('WS parse error:', e)
      }
    }
    ws.value.onclose = () => { connected.value = false }
    ws.value.onerror = () => { connected.value = false }
  }

  function handleWsMessage(msg) {
    const { event, data } = msg
    switch (event) {
      case 'status':
        scanStatus.value = data.status
        break
      case 'finding':
        findings.value.push(data)
        break
      case 'endpoint':
        endpoints.value.push(data)
        break
      case 'complete':
        scanStatus.value = 'completed'
        currentSession.value = data.summary
        break
      case 'error':
        scanStatus.value = 'error'
        break
      case 'cancelled':
        scanStatus.value = 'cancelled'
        break
      case 'scanner_start':
      case 'scanner_done':
        break
    }
  }

  function disconnectWebSocket() {
    if (ws.value) ws.value.close()
    ws.value = null
    connected.value = false
  }

  function reset() {
    currentSession.value = null
    findings.value = []
    endpoints.value = []
    graphData.value = { nodes: [], edges: [] }
    scanStatus.value = 'idle'
    disconnectWebSocket()
  }

  return {
    campaigns, currentSession, findings, endpoints, graphData,
    scanStatus, connected,
    fetchCampaigns, getCampaign, startScan, getScanStatus,
    getScanResults, getScanMap, connectWebSocket, disconnectWebSocket, reset,
  }
})
