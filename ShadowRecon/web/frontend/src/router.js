import { createRouter, createWebHashHistory } from 'vue-router'
import Dashboard from './views/Dashboard.vue'
import LiveScan from './views/LiveScan.vue'
import Report from './views/Report.vue'
import MapView from './views/MapView.vue'
import CampaignDetail from './views/CampaignDetail.vue'
import ScannerModules from './views/ScannerModules.vue'

const routes = [
  { path: '/', redirect: '/dashboard' },
  { path: '/dashboard', name: 'Dashboard', component: Dashboard },
  { path: '/scan/', redirect: '/dashboard' },
  { path: '/scan', redirect: '/dashboard' },
  { path: '/scan/:id', name: 'LiveScan', component: LiveScan, props: true },
  { path: '/report/:id', name: 'Report', component: Report, props: true },
  { path: '/map/:id', name: 'MapView', component: MapView, props: true },
  { path: '/campaign/:id', name: 'CampaignDetail', component: CampaignDetail, props: true },
  { path: '/scanners', name: 'ScannerModules', component: ScannerModules },
]

export default createRouter({
  history: createWebHashHistory(),
  routes,
})
