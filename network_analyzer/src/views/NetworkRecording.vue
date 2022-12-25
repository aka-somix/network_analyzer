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
  <div>
    <h1 class="title">Network Recording</h1>
    
    <h2>Current Device is: {{device?.name}}</h2>

    <Button title="Back to Selection" @click="() => router.push('/select-device')"/>

  </div>
</template>
