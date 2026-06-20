<template>
  <div class="text-cyber-text text-xs leading-relaxed">
    <template v-if="isString">
      <span class="whitespace-pre-wrap">{{ value }}</span>
    </template>
    <template v-else-if="isArray">
      <div v-for="(item, i) in value" :key="i" class="flex items-start gap-1.5 py-0.5">
        <span class="text-cyber-muted-2 mt-0.5 shrink-0">&bull;</span>
        <div class="min-w-0 flex-1">
          <LlmValueRenderer :value="item" />
        </div>
      </div>
    </template>
    <template v-else-if="isObject">
      <div class="flex flex-col gap-1.5">
        <div v-for="(v, k) in value" :key="k" class="flex flex-col gap-0.5">
          <div class="text-cyber-muted-2 text-[10px] uppercase tracking-wider font-bold">{{ formatKey(k) }}</div>
          <div class="pl-2">
            <LlmValueRenderer :value="v" />
          </div>
        </div>
      </div>
    </template>
    <template v-else>
      <span>{{ value }}</span>
    </template>
  </div>
</template>

<script setup>
import { computed } from 'vue'

const props = defineProps({ value: { default: null } })

const isString = computed(() => typeof props.value === 'string')
const isArray = computed(() => Array.isArray(props.value))
const isObject = computed(() => props.value && typeof props.value === 'object' && !Array.isArray(props.value))

function formatKey(k) {
  return k.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}
</script>
