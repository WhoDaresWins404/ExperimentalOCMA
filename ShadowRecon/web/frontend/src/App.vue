<template>
  <div class="app">
    <Toolbar class="app-toolbar">
      <template #start>
        <div class="nav-brand" @click="$router.push('/dashboard')">
          <span class="brand-icon pi pi-shield"></span>
          <span class="brand-text">ShadowRecon</span>
        </div>
      </template>
      <template #end>
        <Button label="Dashboard" icon="pi pi-home" text @click="$router.push('/dashboard')" />
      </template>
    </Toolbar>
    <main class="main-content">
      <router-view />
    </main>
  </div>
</template>

<script setup>
import Toolbar from 'primevue/toolbar'
import Button from 'primevue/button'
</script>

<style scoped>
.app {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}
.app-toolbar {
  border-radius: 0;
  border-left: none;
  border-right: none;
  border-top: none;
  padding: 0.75rem 2rem;
}
.nav-brand {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  cursor: pointer;
  color: var(--p-primary-color);
  font-size: 1.25rem;
  font-weight: 700;
}
.brand-icon { font-size: 1.3rem; }
.main-content {
  flex: 1;
  padding: 1.5rem;
  max-width: 1400px;
  margin: 0 auto;
  width: 100%;
}
</style>
