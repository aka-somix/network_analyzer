<script setup lang="ts">
  import { ref, Ref } from 'vue'
  import DevicePanel from '../components/DeviceSelection/DevicePanel.vue';
  
  import { Device } from '../models/network';

  // TODO This is a mock. Replace with real data
  const devices: Ref<Device[]> = ref([
    {
      name: 'Device 1',
      ipv4Address: "10.10.0.1",
      netmask: "255.255.255.0",
    },
    {
      name: 'Device 2',
      ipv4Address: "10.10.0.2",
      netmask: "255.255.255.0",
    },
    {
      name: 'Device 3',
      ipv4Address: "10.10.0.2",
      netmask: "255.255.255.0",
    },
  ]);

</script>

<template>
  <div>
    <h2 class="title">Select the Network Device:</h2>

    <!-- DEVICES -->
    <div class="devices-panel">
    
      <DevicePanel 
      v-for="device in devices"
      :device="device"
      >
        {{device.name}} | {{device.ipv4Address}}
      </DevicePanel>
    
    </div>

    <!-- BUTTONS -->

    <div>

    </div>

  </div>
</template>
