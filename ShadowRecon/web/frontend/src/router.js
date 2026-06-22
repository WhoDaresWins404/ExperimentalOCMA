import { createRouter, createWebHashHistory } from 'vue-router'
import Dashboard from './views/Dashboard.vue'
import LiveScan from './views/LiveScan.vue'
import Report from './views/Report.vue'
import MapView from './views/MapView.vue'
import CampaignDetail from './views/CampaignDetail.vue'
import ScannerModules from './views/ScannerModules.vue'
import UxLauncher from './views/UxLauncher.vue'
import UxWizard from './views/UxWizard.vue'
import UxHub from './views/UxHub.vue'
import UxIde from './views/UxIde.vue'
import UxWidgets from './views/UxWidgets.vue'

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
  { path: '/ux-test', name: 'UxLauncher', component: UxLauncher },
  { path: '/ux/wizard', name: 'UxWizard', component: UxWizard },
  { path: '/ux/hub', name: 'UxHub', component: UxHub },
  { path: '/ux/ide', name: 'UxIde', component: UxIde },
  { path: '/ux/widgets', name: 'UxWidgets', component: UxWidgets },
  { path: '/:pathMatch(.*)*', name: 'NotFound', redirect: '/dashboard' },
]

export default createRouter({
  history: createWebHashHistory(),
  routes,
})
