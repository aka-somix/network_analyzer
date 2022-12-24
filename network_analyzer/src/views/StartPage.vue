<template>
  <div class="start-page">
    <h1 class="title">Network Analyzer</h1>
    
    <PulsingLogo class="pulsing-logo" />

    <p class=description>
      Lorem Ipsum non ricordo la formula completa. Qui ci va una descrizione del tool. 
      <br> Molto carino e funzionale devo dire. 
    </p>

    <button>Let's Start!</button>

  </div>
</template>

<script setup lang="ts">

  import PulsingLogo from '../components/StartPage/PulsingLogo.vue';

</script>

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