<script setup lang="ts">
  import { Device } from '../../models/network';

  defineProps<{
    device: Device
  }>()


</script>

<template>
  <div class="panel">
    
    <img src="../../assets/device.png" alt="Device" />
    
    <h2 class="device-name">{{device.name}}</h2>
    
    <div class="addresses">
      <h4 class="address">ipv4: <strong>{{device.ipv4Address}}</strong></h4>
      <h4>netmask: <strong>{{device.netmask}}</strong></h4>
    </div>
  
  </div>
</template>

<style scoped>
  .panel {
    height: 16vh;
    width: 80vw;
    margin: .2rem;

    background-color: #003566;
    border-radius: 10px;

    display: grid;
    grid-template-columns: 20vw 30vw 30vw;
    column-gap: 1vw;
  }

  .panel:hover {
    cursor: pointer;
  }

  img {
    width: 10vw;
    justify-self: center;
    align-self: center;
  }

  .device-name {
    justify-self: left;
    align-self: center;
  }

  .addresses {
    justify-self: center;
    align-self: center;
    text-align: left;
  }
  
  .addresses h4 {
    font-weight: 300;
  }

</style>