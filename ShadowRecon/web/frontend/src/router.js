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
  { path: '/ux-test', name: 'UxLauncher', component: () => import('./views/UxLauncher.vue') },
  { path: '/ux/wizard', name: 'UxWizard', component: () => import('./views/UxWizard.vue') },
  { path: '/ux/hub', name: 'UxHub', component: () => import('./views/UxHub.vue') },
  { path: '/ux/ide', name: 'UxIde', component: () => import('./views/UxIde.vue') },
  { path: '/ux/widgets', name: 'UxWidgets', component: () => import('./views/UxWidgets.vue') },
]

export default createRouter({
  history: createWebHashHistory(),
  routes,
})
