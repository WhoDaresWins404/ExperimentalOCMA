<template>
  <div class="py-8 max-w-5xl mx-auto">
    <div class="mb-8">
      <h1 class="text-cyber-accent text-3xl font-bold">UX Test Lab</h1>
      <p class="text-cyber-muted mt-1">Test drive four different UI proposals for the scan experience</p>
    </div>

    <div class="grid grid-cols-1 sm:grid-cols-2 gap-5">
      <div v-for="p in proposals" :key="p.path" @click="$router.push(p.path)"
        class="bg-cyber-surface border border-cyber-border rounded-xl p-6 cursor-pointer transition-all hover:border-cyber-accent hover:-translate-y-0.5 hover:shadow-lg hover:shadow-cyber-accent/10 group">
        <div class="flex items-center gap-3 mb-3">
          <div class="text-3xl">{{ p.icon }}</div>
          <div>
            <div class="text-cyber-text font-bold text-lg group-hover:text-cyber-accent transition-colors">{{ p.title }}</div>
            <div class="text-cyber-muted-2 text-xs uppercase tracking-wider">{{ p.tag }}</div>
          </div>
        </div>
        <p class="text-cyber-muted text-sm mb-4">{{ p.desc }}</p>
        <div class="flex flex-wrap gap-1.5 mb-3">
          <span v-for="f in p.features" :key="f"
            class="bg-cyber-bg border border-cyber-border text-cyber-muted-2 px-2 py-0.5 rounded text-[10px]">{{ f }}</span>
        </div>
        <div class="flex items-center justify-between border-t border-cyber-border pt-3 mt-auto">
          <span class="text-cyber-muted-2 text-xs">Complexity: {{ p.complexity }}</span>
          <span class="text-cyber-accent text-xs font-bold opacity-0 group-hover:opacity-100 transition-opacity">Try it &rarr;</span>
        </div>
      </div>
    </div>

    <div class="mt-10 bg-cyber-surface border border-cyber-border rounded-lg p-5">
      <h2 class="text-cyber-accent font-bold text-sm mb-2">About</h2>
      <p class="text-cyber-muted text-sm leading-relaxed">
        Each proposal represents a different UX philosophy for the scan configuration and monitoring experience.
        All are fully functional — they use the same API and scan engine as the main dashboard.
        Navigate between proposals using the browser back button or the back links on each page.
        Once you've decided which one to keep, we'll promote it to replace the default scan workflow.
      </p>
    </div>
  </div>
</template>

<script setup>
import { useRouter } from 'vue-router'
const $router = useRouter()

const proposals = [
  {
    path: '/ux/wizard',
    icon: '🧭',
    title: 'Wizard',
    tag: 'Proposal 1 — Guided Setup',
    desc: 'Multi-step wizard that walks you through scan configuration one step at a time.',
    features: ['5 steps', 'guided', 'progressive disclosure', 'review before launch'],
    complexity: 'Low',
  },
  {
    path: '/ux/hub',
    icon: '🎛️',
    title: 'Hub & Spoke',
    tag: 'Proposal 2 — Command Center',
    desc: 'Dashboard-centric approach with sidebar navigation, template management, and a slide-in scan panel.',
    features: ['multi-scan', 'templates', 'history', 'scanner stats', 'slide-in panel'],
    complexity: 'Medium',
  },
  {
    path: '/ux/ide',
    icon: '💻',
    title: 'IDE Workspace',
    tag: 'Proposal 3 — Split Pane',
    desc: 'Three-panel IDE-like layout with explorer, tabbed content, and context inspector.',
    features: ['resizable panels', 'explorer tree', 'context panel', 'query param support'],
    complexity: 'High',
  },
  {
    path: '/ux/widgets',
    icon: '📊',
    title: 'Widget Dashboard',
    tag: 'Proposal 4 — Modular Widgets',
    desc: 'Drag-enabled widget grid with live stats, findings timeline, scanner progress, and chain explorer.',
    features: ['drag layout', 'add/remove', 'localStorage', 'real-time stats'],
    complexity: 'High',
  },
]
</script>
