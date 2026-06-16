<template>
  <div class="app">
    <nav class="navbar">
      <div class="nav-brand" @click="$router.push('/dashboard')">
        <span class="brand-icon">&#9670;</span>
        ShadowRecon
      </div>
      <div class="nav-links">
        <router-link to="/dashboard">Dashboard</router-link>
      </div>
    </nav>
    <main class="main-content">
      <router-view />
    </main>
  </div>
</template>

<script setup>
</script>

<style>
.app {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}
.navbar {
  background: linear-gradient(135deg, #0d1b2a, #1b2838);
  padding: 15px 30px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  border-bottom: 1px solid #1e3a5f;
}
.nav-brand {
  color: #00e5ff;
  font-size: 1.3em;
  font-weight: bold;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 8px;
}
.brand-icon {
  color: #00e5ff;
  font-size: 1.2em;
}
.nav-links a {
  color: #8899aa;
  text-decoration: none;
  margin-left: 20px;
  font-size: 0.9em;
  transition: color 0.2s;
}
.nav-links a:hover { color: #00e5ff; }
.main-content {
  flex: 1;
  padding: 20px;
  max-width: 1400px;
  margin: 0 auto;
  width: 100%;
}
</style>
