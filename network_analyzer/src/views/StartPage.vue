<script setup lang="ts">

  import PulsingLogo from '../components/StartPage/PulsingLogo.vue';
  import Button from '../components/common/Button.vue';

</script>

<template>
  <div class="start-page">
    <h1 class="title">Network Analyzer</h1>
    
    <PulsingLogo class="pulsing-logo" />

    <p class=description>
      A simple Network Sniffer powered by <a>Tauri</a>⚡. Embrace the power of <a>Rust</a> while
      keeping a fresh look with <a>Vue.js</a> 😼.
    </p>

    <Button title="Let's Start ⚡" @click="()=>{ this.$router.push('/select-device')}" />

  </div>
</template>

<style scoped>
  .start-page {
    display: flex; 
    flex-direction: column;
    align-items:center;
  }

  .pulsing-logo{
    margin: 2rem auto;
  }

  button {
    margin: 1rem auto;
  }
</style>