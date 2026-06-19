<template>
  <div class="min-h-screen flex flex-col bg-cyber-bg text-cyber-text">
    <nav class="bg-gradient-to-r from-[#0d1b2a] to-[#1b2838] px-8 py-3.5 flex items-center justify-between border-b border-cyber-border">
      <div class="flex items-center gap-2 text-cyber-accent text-xl font-bold cursor-pointer select-none" @click="$router.push('/dashboard')">
        <span class="text-xl leading-none">&#9670;</span>
        ShadowRecon
      </div>
      <div class="flex items-center gap-5">
        <router-link to="/dashboard" class="text-cyber-muted hover:text-cyber-accent text-sm no-underline transition-colors">Dashboard</router-link>
        <router-link to="/scanners" class="text-cyber-muted hover:text-cyber-accent text-sm no-underline transition-colors">Scanner Modules</router-link>
      </div>
    </nav>
    <main class="flex-1 p-6 max-w-[1400px] mx-auto w-full">
      <router-view />
    </main>
  </div>
</template>
