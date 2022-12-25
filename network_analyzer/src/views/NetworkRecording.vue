<script setup lang="ts">
  import { ref, onMounted, Ref } from 'vue'
  import { Device } from '../models/network';
  import {BackendAPI} from '../api';
  import { useRouter } from 'vue-router';
 
  import Button from '../components/common/Button.vue';
  

  /*
   * REFS
   */
  const device: Ref<Device | null> = ref(null);
  const router = useRouter();

  // HOOKS
  onMounted(async () => {
    device.value = await BackendAPI.getDevice();
  })
  
  /*
   * METHODS
   */

</script>

<template>
  <div class="box">
    <header>
      <h2 class="title">Network Analysis</h2>
      <p class="descriptive">
        Listening on: <br/>
        <a class="clickable" @click="() => router.push('/select-device')">
          {{device?.name}}
        </a>
      </p>
    </header>

    <div class="record-panel">
      Nothing to see here yet 🤫
    </div>

    <div 
      class="circle-button blue clickable" 
    >
      <h3>PAUSE</h3>
    </div>

    <div 
      class="circle-button red clickable" 
    >
      <h3>REC</h3>
    </div>
    

  </div>
</template>

<style scoped>

  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  header > h2 {
    font-size: 2em;
  }

  p.descriptive {
    text-align: left;
  }

  p > a.clickable:hover {
    cursor: pointer;
  }

  .record-panel {
    height: 50vh;
    width: 80vw;
    overflow-y: scroll;
    padding: 2rem;
    box-shadow: 0px 0px 10px 2px #01101e82;
    border-radius: 10px;

    -ms-overflow-style: none;  /* IE and Edge */
    scrollbar-width: none;  /* Firefox */
  }
  .record-panel::-webkit-scrollbar {
    display: none;
  }

  .circle-button {
    width: 9vw;
    height: 9vw;
    background-color: #112132;
    border-radius: 100%;
    text-align: center;
    display: flex;
    align-items: center;
    justify-items: center;
    float: right;
    margin: auto 0.6rem;
    transition: 200ms;
    box-shadow: 2px 2px 10px 5px #01101e82;
  }

  .circle-button.clickable.red {
    background-color: #ff4400;
  }

  .circle-button.clickable.blue {
    background-color: #003566;
  }

  .circle-button.clickable:hover {
    transform: scale(1.1);
    cursor: pointer;
    box-shadow: 4px 6px 5px 5px #01101e82;
  }

  .circle-button h3 {
    margin: auto;
    font-size: 1.1em;
  }

</style>