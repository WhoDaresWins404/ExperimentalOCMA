<template>
  <div class="py-8 max-w-4xl mx-auto">
    <div class="flex items-center justify-between mb-6">
      <button @click="goBack" class="bg-transparent border border-cyber-border text-cyber-muted px-4 py-2 rounded cursor-pointer hover:text-cyber-accent hover:border-cyber-accent transition-colors text-sm">&larr; Back to UX Lab</button>
      <h1 class="text-cyber-accent text-xl font-bold">Scan Wizard</h1>
      <span class="text-cyber-muted-2 text-sm">Step {{ step }} of 5</span>
    </div>

    <div class="flex items-center justify-between mb-8 px-2">
      <div v-for="(s, i) in steps" :key="i" class="flex items-center flex-1">
        <div class="flex flex-col items-center">
          <div class="w-9 h-9 rounded-full flex items-center justify-center text-sm font-bold transition-colors" :class="i + 1 === step ? 'bg-cyber-accent text-cyber-bg' : i + 1 < step ? 'bg-cyber-accent/30 text-cyber-accent' : 'bg-cyber-surface border border-cyber-border text-cyber-muted-2'">{{ i + 1 }}</div>
          <span class="text-[10px] mt-1 font-bold uppercase tracking-wider" :class="i + 1 === step ? 'text-cyber-accent' : 'text-cyber-muted-2'">{{ s }}</span>
        </div>
        <div v-if="i < steps.length - 1" class="flex-1 h-0.5 mx-3 rounded" :class="i + 1 < step ? 'bg-cyber-accent/50' : 'bg-cyber-border'"></div>
      </div>
    </div>

    <div class="bg-cyber-surface border border-cyber-border rounded-xl p-6 min-h-[420px]">
      <div v-if="step === 1">
        <h2 class="text-cyber-accent font-bold text-lg mb-4">Target</h2>
        <div class="grid grid-cols-2 gap-5">
          <div class="space-y-4">
            <div>
              <label for="wiz-url" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Target URL <span class="text-cyber-danger">*</span></label>
              <input id="wiz-url" v-model="form.url" type="text" placeholder="https://example.com" required
                class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
            </div>
            <div>
              <label for="wiz-campaign" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Campaign Name</label>
              <input id="wiz-campaign" v-model="form.campaign_name" type="text" placeholder="default"
                class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
            </div>
            <div>
              <label for="wiz-camp-desc" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Campaign Description</label>
              <input id="wiz-camp-desc" v-model="form.campaign_description" type="text" placeholder="Optional description"
                class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
            </div>
            <div>
              <label for="wiz-scope" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Scope Patterns</label>
              <textarea id="wiz-scope" v-model="form.scope_text" rows="4" placeholder="*.example.com&#10;*.example.org&#10;-*.dev.example.com"
                class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors font-mono"></textarea>
              <p class="text-cyber-muted-2 text-[10px] mt-0.5">One per line. Prefix with - for exclusion.</p>
            </div>
          </div>
          <div class="space-y-4">
            <div>
              <label class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Authentication</label>
              <select v-model="form.auth_type"
                class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3 py-2 rounded text-sm outline-none focus:border-cyber-accent transition-colors cursor-pointer">
                <option value="none">None</option>
                <option value="cookie">Cookie</option>
                <option value="bearer">Bearer Token</option>
                <option value="header">Custom Header</option>
                <option value="basic">Basic Auth</option>
              </select>
            </div>
            <div v-if="form.auth_type === 'cookie'">
              <label for="wiz-auth-cookie" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Cookie String</label>
              <input id="wiz-auth-cookie" v-model="form.auth_cookie_string" type="text" placeholder="session=abc123; token=xyz"
                class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
            </div>
            <div v-if="form.auth_type === 'bearer'">
              <label for="wiz-auth-bearer" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Bearer Token</label>
              <input id="wiz-auth-bearer" v-model="form.auth_bearer_token" type="text" placeholder="eyJhbGci..."
                class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
            </div>
            <div v-if="form.auth_type === 'header'">
              <label for="wiz-auth-hdr-key" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Header Key</label>
              <input id="wiz-auth-hdr-key" v-model="form.auth_header_key" type="text" placeholder="X-API-Key"
                class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
              <label for="wiz-auth-hdr-val" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1 mt-2">Header Value</label>
              <input id="wiz-auth-hdr-val" v-model="form.auth_header_value" type="text" placeholder="YourValue123"
                class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
            </div>
            <div v-if="form.auth_type === 'basic'" class="space-y-2">
              <div>
                <label for="wiz-auth-basic-user" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Username</label>
                <input id="wiz-auth-basic-user" v-model="form.auth_basic_username" type="text" placeholder="admin"
                  class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
              </div>
              <div>
                <label for="wiz-auth-basic-pass" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Password</label>
                <input id="wiz-auth-basic-pass" v-model="form.auth_basic_password" type="password" placeholder="********"
                  class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
              </div>
            </div>
          </div>
        </div>
      </div>

      <div v-if="step === 2">
        <h2 class="text-cyber-accent font-bold text-lg mb-4">Profile</h2>
        <div class="grid grid-cols-2 gap-4">
          <label v-for="p in profileDefs" :key="p.key"
            :class="['flex flex-col items-start gap-2 bg-cyber-surface-2 border-2 rounded-xl p-5 cursor-pointer transition-all relative', scanProfile === p.key ? 'border-cyber-accent bg-cyber-accent/5' : 'border-cyber-border hover:border-cyber-accent/50']">
            <input type="radio" v-model="scanProfile" :value="p.key" class="absolute opacity-0 pointer-events-none" />
            <div class="flex items-center gap-2 w-full">
              <div class="text-cyber-text font-bold text-base">{{ p.title }}</div>
              <div class="text-[0.6rem] uppercase tracking-wider px-2 py-0.5 rounded ml-auto" :class="badgeClass(p.key)">{{ p.badge }}</div>
            </div>
            <div class="text-cyber-muted text-xs leading-relaxed">{{ p.desc }}</div>
          </label>
        </div>

        <div v-if="scanProfile !== 'custom'" class="mt-4 bg-cyber-bg border border-cyber-border rounded-lg p-4">
          <div class="text-cyber-muted-2 text-[10px] uppercase tracking-wider mb-2">Preset Summary</div>
          <div class="grid grid-cols-3 gap-2 text-xs">
            <div class="flex justify-between bg-cyber-surface rounded px-3 py-1.5"><span class="text-cyber-muted-2">Mode</span><span class="text-cyber-text font-bold">{{ form.scan_mode }}</span></div>
            <div class="flex justify-between bg-cyber-surface rounded px-3 py-1.5"><span class="text-cyber-muted-2">Threads</span><span class="text-cyber-text font-bold">{{ form.threads }}</span></div>
            <div class="flex justify-between bg-cyber-surface rounded px-3 py-1.5"><span class="text-cyber-muted-2">Crawl Depth</span><span class="text-cyber-text font-bold">{{ form.crawl_depth }}</span></div>
            <div class="flex justify-between bg-cyber-surface rounded px-3 py-1.5"><span class="text-cyber-muted-2">XSS</span><span class="text-cyber-text font-bold">{{ form.xss_mode }}</span></div>
            <div class="flex justify-between bg-cyber-surface rounded px-3 py-1.5"><span class="text-cyber-muted-2">LLM</span><span class="text-cyber-text font-bold">{{ form.enable_llm ? 'On' : 'Off' }}</span></div>
            <div class="flex justify-between bg-cyber-surface rounded px-3 py-1.5"><span class="text-cyber-muted-2">LLM Payloads</span><span class="text-cyber-text font-bold">{{ form.enable_llm_payloads ? 'On' : 'Off' }}</span></div>
          </div>
        </div>

        <div v-else class="mt-4 bg-cyber-bg border border-cyber-border rounded-lg p-4 space-y-4">
          <div class="text-cyber-muted-2 text-[10px] uppercase tracking-wider">Custom Settings</div>
          <div>
            <label class="text-cyber-muted text-xs uppercase tracking-wide mb-1 block">Scan Mode</label>
            <div class="flex gap-2.5">
              <label v-for="m in scanModeOptions" :key="m.value"
                class="flex-1 flex flex-col gap-0.5 bg-cyber-surface-2 border border-cyber-border rounded px-3 py-2 cursor-pointer hover:border-cyber-accent transition-colors">
                <input type="radio" v-model="form.scan_mode" :value="m.value" class="accent-cyber-accent" />
                <span class="text-cyber-text text-sm font-bold">{{ m.label }}</span>
                <span class="text-cyber-muted-2 text-xs">{{ m.desc }}</span>
              </label>
            </div>
          </div>
          <div class="flex gap-4">
            <div class="w-28">
              <label for="wiz-threads" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Threads</label>
              <input id="wiz-threads" v-model.number="form.threads" type="number" min="1" max="100"
                class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3 py-2 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
            </div>
            <div class="w-28">
              <label for="wiz-timeout" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Timeout (s)</label>
              <input id="wiz-timeout" v-model.number="form.timeout" type="number" min="5" max="120"
                class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3 py-2 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
            </div>
            <div class="w-36">
              <label for="wiz-detection" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Detection Mode</label>
              <select id="wiz-detection" v-model="form.detection_mode"
                class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3 py-2 rounded text-sm outline-none focus:border-cyber-accent transition-colors cursor-pointer">
                <option value="detect">Detection</option>
                <option value="confirm">Confirmation</option>
              </select>
            </div>
          </div>
          <div class="flex gap-4">
            <div class="w-28">
              <label for="wiz-crawl" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Crawl Depth</label>
              <input id="wiz-crawl" v-model.number="form.crawl_depth" type="number" min="0" max="5"
                class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3 py-2 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
            </div>
            <div class="w-52">
              <label for="wiz-xss" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">XSS Mode</label>
              <select id="wiz-xss" v-model="form.xss_mode"
                class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3 py-2 rounded text-sm outline-none focus:border-cyber-accent transition-colors cursor-pointer">
                <option value="probe">Probe Only (safe)</option>
                <option value="exploit">Exploit (LLM payloads)</option>
              </select>
            </div>
          </div>
          <div class="flex gap-4">
            <label class="flex items-center gap-1.5 cursor-pointer bg-cyber-surface-2 border border-cyber-border rounded px-3.5 py-2 hover:border-cyber-accent transition-colors">
              <input type="checkbox" v-model="form.enable_llm_payloads" class="accent-cyber-accent" />
              <span class="text-cyber-text text-sm">Enable LLM Payloads</span>
            </label>
            <label class="flex items-center gap-1.5 cursor-pointer bg-cyber-surface-2 border border-cyber-border rounded px-3.5 py-2 hover:border-cyber-accent transition-colors">
              <input type="checkbox" v-model="form.enable_proxy" class="accent-cyber-accent" />
              <span class="text-cyber-text text-sm">Enable Proxy</span>
            </label>
          </div>
        </div>
      </div>

      <div v-if="step === 3">
        <h2 class="text-cyber-accent font-bold text-lg mb-4">Modules</h2>
        <div class="flex items-center gap-3 mb-4">
          <input v-model="scannerSearch" type="text" placeholder="Search scanners..." class="flex-1 bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
          <button @click="selectAllScanners" class="text-[10px] px-3 py-1.5 rounded bg-cyber-bg border border-cyber-border text-cyber-muted hover:text-cyber-accent hover:border-cyber-accent transition-colors cursor-pointer">Select All</button>
          <button @click="deselectAllScanners" class="text-[10px] px-3 py-1.5 rounded bg-cyber-bg border border-cyber-border text-cyber-muted hover:text-cyber-accent hover:border-cyber-accent transition-colors cursor-pointer">Deselect All</button>
        </div>
        <div class="text-cyber-muted-2 text-xs mb-4">{{ form.enabled_scanners.length }} of {{ scannerManifests.length }} scanners selected</div>
        <div v-if="scannerLoading" class="text-cyber-muted text-sm py-8 text-center">Loading scanners...</div>
        <div v-else-if="Object.keys(filteredScannerGroups).length === 0" class="text-cyber-muted text-sm py-8 text-center">No scanners match your search.</div>
        <div v-else class="space-y-3 max-h-[280px] overflow-y-auto pr-1">
          <div v-for="(group, cat) in filteredScannerGroups" :key="cat">
            <details class="bg-cyber-bg border border-cyber-border rounded-lg group">
              <summary class="text-cyber-muted-2 text-xs uppercase tracking-wider px-3 py-2 cursor-pointer select-none hover:text-cyber-accent transition-colors flex items-center gap-2">{{ cat }} <span class="text-cyber-muted-2 font-normal">({{ group.length }})</span></summary>
              <div class="px-3 pb-2 pt-1 space-y-1 border-t border-cyber-border">
                <label v-for="m in group" :key="m.name"
                  class="flex items-center gap-2 px-2.5 py-1.5 rounded cursor-pointer text-xs transition-colors"
                  :class="form.enabled_scanners.includes(m.name) ? 'bg-cyber-accent/10 text-cyber-accent' : 'text-cyber-muted hover:bg-cyber-surface'">
                  <input type="checkbox" :value="m.name" v-model="form.enabled_scanners" class="accent-cyber-accent" />
                  <span class="flex-1">{{ m.name }}</span>
                  <span class="text-[0.55rem] uppercase px-1.5 py-0.5 rounded font-bold" :class="riskBadgeClass(m.risk || 'safe')">{{ m.risk || 'safe' }}</span>
                </label>
              </div>
            </details>
          </div>
        </div>
      </div>

      <div v-if="step === 4">
        <h2 class="text-cyber-accent font-bold text-lg mb-4">Advanced</h2>
        <div class="space-y-5 max-w-xl">
          <div class="flex items-center gap-4 flex-wrap">
            <label class="flex items-center gap-1.5 cursor-pointer bg-cyber-surface-2 border border-cyber-border rounded px-3.5 py-2 hover:border-cyber-accent transition-colors">
              <input type="checkbox" v-model="form.enable_llm" class="accent-cyber-accent" />
              <span class="text-cyber-text text-sm">Enable LLM Analysis</span>
            </label>
            <button :disabled="llmTesting" @click="testLlm"
              class="bg-cyber-surface-2 border border-cyber-border text-cyber-text px-3.5 py-2 rounded text-xs cursor-pointer hover:bg-cyber-surface hover:text-cyber-accent transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
              {{ llmTesting ? 'Testing...' : 'Test LLM' }}
            </button>
            <span v-if="llmResult"
              :class="['text-xs px-2.5 py-1 rounded', llmResult.reachable && llmResult.model_found ? 'bg-green-900 text-green-400' : llmResult.reachable ? 'bg-yellow-900 text-yellow-400' : 'bg-red-900 text-red-400']"
              :title="llmResult.error || ''">
              {{ llmResult.reachable && llmResult.model_found ? `LLM OK (${llmResult.model})` : (llmResult.error ? 'LLM: ' + llmResult.error : 'LLM unreachable') }}
            </span>
          </div>

          <label class="flex items-center gap-1.5 cursor-pointer">
            <input type="checkbox" v-model="enableOast" class="accent-cyber-accent" />
            <span class="text-cyber-text text-sm">Enable OAST Integration</span>
          </label>

          <div>
            <label class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Delay Between Requests: {{ rateLimit }}s</label>
            <input type="range" min="0" max="30" step="0.5" v-model.number="rateLimit"
              class="w-full accent-cyber-accent cursor-pointer" />
            <div class="flex justify-between text-[10px] text-cyber-muted-2"><span>0s</span><span>30s</span></div>
          </div>

          <label class="flex items-center gap-1.5 cursor-pointer bg-cyber-surface-2 border border-cyber-border rounded px-3.5 py-2 hover:border-cyber-accent transition-colors max-w-fit">
            <input type="checkbox" v-model="form.enable_proxy" class="accent-cyber-accent" />
            <span class="text-cyber-text text-sm">Enable Proxy</span>
          </label>

          <div>
            <label for="wiz-cron" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Schedule (cron expression)</label>
            <input id="wiz-cron" v-model="scheduleCron" type="text" placeholder="0 2 * * * (daily at 2am)"
              class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors font-mono" />
          </div>

          <div>
            <label for="wiz-webhook" class="block text-cyber-muted text-xs uppercase tracking-wide mb-1">Webhook URL</label>
            <input id="wiz-webhook" v-model="webhookUrl" type="text" placeholder="https://hooks.example.com/scan-complete"
              class="w-full bg-cyber-bg border border-cyber-border text-cyber-text px-3.5 py-2.5 rounded text-sm outline-none focus:border-cyber-accent transition-colors" />
          </div>
        </div>
      </div>

      <div v-if="step === 5">
        <h2 class="text-cyber-accent font-bold text-lg mb-4">Review &amp; Launch</h2>
        <div class="bg-cyber-bg border border-cyber-border rounded-xl p-5 space-y-4">
          <div class="flex items-center justify-between">
            <div>
              <div class="text-cyber-muted-2 text-[10px] uppercase tracking-wider">Target URL</div>
              <div class="text-cyber-text text-sm font-bold mt-0.5">{{ form.url || '(not set)' }}</div>
            </div>
            <button @click="step = 1" class="text-[10px] text-cyber-accent hover:underline bg-transparent border-none cursor-pointer">Edit</button>
          </div>
          <div class="border-t border-cyber-border"></div>
          <div class="flex items-center justify-between">
            <div>
              <div class="text-cyber-muted-2 text-[10px] uppercase tracking-wider">Campaign</div>
              <div class="text-cyber-text text-sm font-bold mt-0.5">{{ form.campaign_name || 'default' }}</div>
              <div v-if="form.campaign_description" class="text-cyber-muted text-xs mt-0.5">{{ form.campaign_description }}</div>
            </div>
            <button @click="step = 1" class="text-[10px] text-cyber-accent hover:underline bg-transparent border-none cursor-pointer">Edit</button>
          </div>
          <div class="border-t border-cyber-border"></div>
          <div class="flex items-center justify-between">
            <div>
              <div class="text-cyber-muted-2 text-[10px] uppercase tracking-wider">Profile</div>
              <div class="text-cyber-text text-sm font-bold mt-0.5">{{ profileDefs.find(p => p.key === scanProfile)?.title || scanProfile }}</div>
            </div>
            <button @click="step = 2" class="text-[10px] text-cyber-accent hover:underline bg-transparent border-none cursor-pointer">Edit</button>
          </div>
          <div class="border-t border-cyber-border"></div>
          <div class="flex items-center justify-between">
            <div>
              <div class="text-cyber-muted-2 text-[10px] uppercase tracking-wider">Scanners</div>
              <div class="text-cyber-text text-sm font-bold mt-0.5">{{ form.enabled_scanners.length }} of {{ scannerManifests.length }} selected</div>
            </div>
            <button @click="step = 3" class="text-[10px] text-cyber-accent hover:underline bg-transparent border-none cursor-pointer">Edit</button>
          </div>
          <div class="border-t border-cyber-border"></div>
          <div class="flex items-center justify-between">
            <div>
              <div class="text-cyber-muted-2 text-[10px] uppercase tracking-wider">Authentication</div>
              <div class="text-cyber-text text-sm font-bold mt-0.5 capitalize">{{ form.auth_type }}</div>
            </div>
            <button @click="step = 1" class="text-[10px] text-cyber-accent hover:underline bg-transparent border-none cursor-pointer">Edit</button>
          </div>
          <div class="border-t border-cyber-border"></div>
          <div class="flex items-center justify-between">
            <div>
              <div class="text-cyber-muted-2 text-[10px] uppercase tracking-wider">LLM Analysis</div>
              <div class="text-cyber-text text-sm font-bold mt-0.5">{{ form.enable_llm ? 'Enabled' : 'Disabled' }}</div>
            </div>
            <button @click="step = 4" class="text-[10px] text-cyber-accent hover:underline bg-transparent border-none cursor-pointer">Edit</button>
          </div>
          <div v-if="scanProfile === 'custom' || form.enable_proxy || rateLimit > 0 || scheduleCron || webhookUrl" class="border-t border-cyber-border"></div>
          <div v-if="scanProfile === 'custom'" class="flex items-center justify-between">
            <div>
              <div class="text-cyber-muted-2 text-[10px] uppercase tracking-wider">Custom Overrides</div>
              <div class="text-cyber-text text-xs mt-0.5">Mode: {{ form.scan_mode }}, Threads: {{ form.threads }}, Timeout: {{ form.timeout }}s, Crawl: {{ form.crawl_depth }}, XSS: {{ form.xss_mode }}</div>
            </div>
            <button @click="step = 2" class="text-[10px] text-cyber-accent hover:underline bg-transparent border-none cursor-pointer">Edit</button>
          </div>
          <div v-if="form.enable_proxy" class="flex items-center justify-between">
            <div>
              <div class="text-cyber-muted-2 text-[10px] uppercase tracking-wider">Proxy</div>
              <div class="text-cyber-text text-xs mt-0.5">Enabled</div>
            </div>
            <button @click="step = 4" class="text-[10px] text-cyber-accent hover:underline bg-transparent border-none cursor-pointer">Edit</button>
          </div>
          <div v-if="rateLimit > 0" class="flex items-center justify-between">
            <div>
              <div class="text-cyber-muted-2 text-[10px] uppercase tracking-wider">Rate Limit</div>
              <div class="text-cyber-text text-xs mt-0.5">{{ rateLimit }}s delay</div>
            </div>
            <button @click="step = 4" class="text-[10px] text-cyber-accent hover:underline bg-transparent border-none cursor-pointer">Edit</button>
          </div>
          <div v-if="scheduleCron" class="flex items-center justify-between">
            <div>
              <div class="text-cyber-muted-2 text-[10px] uppercase tracking-wider">Schedule</div>
              <div class="text-cyber-text text-xs mt-0.5 font-mono">{{ scheduleCron }}</div>
            </div>
            <button @click="step = 4" class="text-[10px] text-cyber-accent hover:underline bg-transparent border-none cursor-pointer">Edit</button>
          </div>
          <div v-if="webhookUrl" class="flex items-center justify-between">
            <div>
              <div class="text-cyber-muted-2 text-[10px] uppercase tracking-wider">Webhook</div>
              <div class="text-cyber-text text-xs mt-0.5 break-all">{{ webhookUrl }}</div>
            </div>
            <button @click="step = 4" class="text-[10px] text-cyber-accent hover:underline bg-transparent border-none cursor-pointer">Edit</button>
          </div>
        </div>
      </div>
    </div>

    <div class="flex items-center justify-between mt-6">
      <button @click="prevStep" :disabled="step === 1 && submitting"
        class="bg-transparent border border-cyber-border text-cyber-muted px-5 py-2.5 rounded text-sm cursor-pointer hover:text-cyber-accent hover:border-cyber-accent transition-colors disabled:opacity-30 disabled:cursor-not-allowed">
        &larr; Back
      </button>
      <button v-if="step < 5" @click="nextStep" :disabled="!canGoNext"
        class="bg-cyber-accent text-cyber-bg font-bold px-6 py-2.5 rounded text-sm cursor-pointer hover:bg-[#00b8d4] transition-colors disabled:opacity-40 disabled:cursor-not-allowed">
        Next &rarr;
      </button>
      <button v-else @click="handleSubmit" :disabled="submitting"
        class="bg-green-500 text-white font-bold px-8 py-2.5 rounded text-sm cursor-pointer hover:bg-green-400 transition-colors disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2">
        <span v-if="submitting" class="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin inline-block"></span>
        {{ submitting ? 'Launching...' : 'Launch Scan' }}
      </button>
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, computed, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useScanStore } from '../store/scanStore'

const $router = useRouter()
const store = useScanStore()
const API = ''

const steps = ['Target', 'Profile', 'Modules', 'Advanced', 'Review']
const step = ref(1)
const submitting = ref(false)
const llmTesting = ref(false)
const llmResult = ref(null)
const scannerManifests = ref([])
const scannerLoading = ref(false)
const scannerSearch = ref('')
const enableOast = ref(false)
const rateLimit = ref(0)
const scheduleCron = ref('')
const webhookUrl = ref('')

const PROFILES = {
  quick:   { scan_mode: 'light',   crawl_depth: 0, threads: 10, timeout: 30,   xss_mode: 'probe',  enable_llm: false, enable_llm_payloads: false, detection_mode: 'detect' },
  standard:{ scan_mode: 'full',    crawl_depth: 1, threads: 25, timeout: 30,   xss_mode: 'probe',  enable_llm: true,  enable_llm_payloads: false, detection_mode: 'detect' },
  deep:    { scan_mode: 'full',    crawl_depth: 2, threads: 50, timeout: 60,   xss_mode: 'exploit', enable_llm: true,  enable_llm_payloads: true,  detection_mode: 'confirm' },
}

const profileDefs = [
  { key: 'quick',    title: 'Quick',     desc: 'Light scan, no crawl, ~5 min',      badge: 'fast' },
  { key: 'standard', title: 'Standard',  desc: 'Full scan, depth 1, LLM critical+',  badge: 'balanced' },
  { key: 'deep',     title: 'Deep',      desc: 'Full scan, depth 2, LLM exploit',    badge: 'thorough' },
  { key: 'custom',   title: 'Custom',    desc: 'Fine-tune every setting',             badge: 'manual' },
]

const scanModeOptions = [
  { label: 'Full Scan', value: 'full', desc: 'All scanners, maximum coverage' },
  { label: 'Light Scan', value: 'light', desc: 'Directory + misconfig + crawl' },
  { label: 'WAF Only', value: 'waf_only', desc: 'Detect WAF, skip all other scans' },
]

const scanProfile = ref('standard')

const form = reactive({
  url: '',
  campaign_name: 'default',
  campaign_description: '',
  threads: 25,
  timeout: 30,
  scan_mode: 'full',
  detection_mode: 'detect',
  enable_proxy: false,
  enable_llm: false,
  auth_type: 'none',
  auth_cookie_string: '',
  auth_bearer_token: '',
  auth_header_key: '',
  auth_header_value: '',
  auth_basic_username: '',
  auth_basic_password: '',
  crawl_depth: 1,
  xss_mode: 'probe',
  enable_llm_payloads: false,
  enabled_scanners: [],
  scope: {},
  scope_text: '',
})

const filteredScannerGroups = computed(() => {
  const groups = {}
  const q = scannerSearch.value.toLowerCase()
  for (const m of scannerManifests.value) {
    if (q && !m.name.toLowerCase().includes(q)) continue
    const cat = m.category || 'other'
    if (!groups[cat]) groups[cat] = []
    groups[cat].push(m)
  }
  return groups
})

const canGoNext = computed(() => {
  if (step.value === 1) return form.url.trim().length > 0
  return true
})

watch(scanProfile, (profile) => {
  if (profile !== 'custom') {
    const p = PROFILES[profile]
    if (p) Object.assign(form, p)
  }
})

watch(step, (s) => {
  if (s === 3 && scannerManifests.value.length === 0) {
    fetchScanners()
  }
})

function badgeClass(key) {
  return {
    quick: 'bg-green-900 text-green-400',
    standard: 'bg-cyan-900 text-cyber-accent',
    deep: 'bg-red-900 text-red-400',
    custom: 'bg-purple-900 text-purple-300',
  }[key] || ''
}

function riskBadgeClass(risk) {
  return {
    aggressive: 'bg-red-900 text-red-400',
    moderate: 'bg-yellow-900 text-yellow-400',
    safe: 'bg-green-900 text-green-400',
  }[risk] || 'bg-green-900 text-green-400'
}

function goBack() {
  $router.push('/ux-test')
}

function prevStep() {
  if (step.value > 1) step.value--
}

function nextStep() {
  if (step.value < 5) step.value++
}

async function fetchScanners() {
  scannerLoading.value = true
  try {
    const resp = await fetch(`${API}/api/scanners`)
    if (resp.ok) {
      scannerManifests.value = await resp.json()
      if (form.enabled_scanners.length === 0) {
        form.enabled_scanners = scannerManifests.value.map(m => m.name)
      }
    }
  } catch (e) {
    console.error('Failed to load scanners', e)
  } finally {
    scannerLoading.value = false
  }
}

function selectAllScanners() {
  form.enabled_scanners = scannerManifests.value.map(m => m.name)
}

function deselectAllScanners() {
  form.enabled_scanners = []
}

async function testLlm() {
  llmTesting.value = true
  llmResult.value = null
  try {
    const res = await fetch(`${API}/api/llm/check`)
    const data = await res.json()
    llmResult.value = data
  } catch (e) {
    llmResult.value = { reachable: false, error: e.message }
  } finally {
    llmTesting.value = false
  }
}

function parseScope() {
  const lines = (form.scope_text || '').split('\n').map(l => l.trim()).filter(Boolean)
  const in_scope = []
  const out_of_scope = []
  for (const line of lines) {
    if (line.startsWith('-')) {
      out_of_scope.push(line.slice(1).trim())
    } else {
      in_scope.push(line)
    }
  }
  return { in_scope, out_of_scope }
}

async function handleSubmit() {
  submitting.value = true
  try {
    const payload = { ...form }
    payload.scope = parseScope()
    delete payload.scope_text
    const result = await store.startScan(payload)
    const sessionId = result.session_id || result.id
    if (sessionId) {
      $router.push(`/scan/${sessionId}`)
    }
  } catch (e) {
    console.error('Failed to start scan:', e)
  } finally {
    submitting.value = false
  }
}
</script>
