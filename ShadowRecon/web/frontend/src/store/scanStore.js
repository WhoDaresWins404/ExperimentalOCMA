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
    try {
      const { data } = await axios.get(`${API}/campaigns`)
      campaigns.value = data
    } catch (e) {
      console.error('Failed to fetch campaigns:', e)
    }
  }

  async function getCampaign(id) {
    const { data } = await axios.get(`${API}/campaigns/${id}`)
    return data
  }

  async function startScan(params) {
    const { data } = await axios.post(`${API}/scan`, {
      url: params.url,
      campaign_name: params.campaign_name || 'default',
      campaign_description: params.campaign_description || '',
      threads: params.threads || 25,
      timeout: params.timeout || 30,
      scan_mode: params.scan_mode || 'full',
      detection_mode: params.detection_mode || 'detect',
      enable_proxy: params.enable_proxy || false,
      enable_llm: params.enable_llm || false,
      auth_type: params.auth_type || 'none',
      auth_cookie_string: params.auth_cookie_string || '',
      auth_bearer_token: params.auth_bearer_token || '',
      auth_header_key: params.auth_header_key || '',
      auth_header_value: params.auth_header_value || '',
      auth_basic_username: params.auth_basic_username || '',
      auth_basic_password: params.auth_basic_password || '',
      crawl_depth: params.crawl_depth || 2,
      xss_mode: params.xss_mode || 'probe',
      enable_llm_payloads: params.enable_llm_payloads || false,
      enabled_scanners: params.enabled_scanners || [],
    })
    return data
  }

  async function getScanStatus(sessionId) {
    try {
      const { data } = await axios.get(`${API}/scan/${sessionId}/status`)
      return data
    } catch (e) {
      return null
    }
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

  async function analyzeFinding(sessionId, findingId) {
    const { data } = await axios.post(`${API}/llm/analyze-finding/${sessionId}/${findingId}`)
    return data
  }

  async function analyzeScan(sessionId) {
    const { data } = await axios.post(`${API}/llm/analyze-scan/${sessionId}`)
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
        scanStatus.value = 'failed'
        break
      case 'cancelled':
        scanStatus.value = 'cancelled'
        break
    }
  }

  function disconnectWebSocket() {
    if (ws.value) {
      ws.value.onclose = null
      ws.value.close()
    }
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
    getScanResults, getScanMap, analyzeFinding, analyzeScan,
    connectWebSocket, disconnectWebSocket, reset,
  }
})
