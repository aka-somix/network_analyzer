<script setup lang="ts">
  import { ref, onMounted, Ref } from 'vue'
  import { Device } from '../models/network';
  import { RecordingStatus } from '../models/commons';
  import {BackendAPI} from '../api';
  import { useRouter } from 'vue-router';

  /*
   * REFS
   */
  const router = useRouter();

  // Current Device to analyze traffic from
  const device: Ref<Device | null> = ref(null);
  // Data Recorded
  const recordedData: Ref<string> = ref("Nothing to see here yet 🤫");
  // TimerID for the recording
  const timerId: Ref<number | null> = ref(null); 
  // Status of the application
  const status: Ref<RecordingStatus> = ref('IDLE');

  /**
   * HOOKS
   */ 
  onMounted(async () => {
    device.value = await BackendAPI.getDevice();
  })
  
  /*
   * METHODS
   */

  function updateRecordedData() {
    console.log(`Updating Data for timer ${timerId.value}`);
    
    const randomString = ["Ciao Amanda", "Hello World", "Qualcosa a caso", "Ultima stringa random"];

    const randomIdx = Math.floor(Math.random()*10) % randomString.length;

    console.log(`Random idx ${randomIdx} with associated string ${randomString[randomIdx]}`);

    recordedData.value = randomString[randomIdx];
  }

  function startRecording() {

    // Prevent multiple timers
    if (timerId.value !== null) return;

    console.log("Starting a new Recording");
    // update status
    status.value = 'REC';

    // Start polling data from backend
    timerId.value = setInterval(() => {
      updateRecordedData();
    }, 1000);
  }

  function pauseRecording() {
    // Assert that a timer is actually active
    if (timerId.value === null) return;
    
    // Stop Interval

    // update status
    status.value = 'IDLE';

    console.log(`Canceling timer ${timerId.value}`);
    clearInterval(timerId.value);
    
    // reset timerId to null
    timerId.value = null;
  }

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
      {{recordedData}}
    </div>

    <div 
      class="circle-button blue"
      :class="status === 'REC' ? 'clickable': '' "
      @click="pauseRecording" 
    >
      <h3>PAUSE</h3>
    </div>

    <div 
      class="circle-button red"
      :class="status === 'IDLE' ? 'clickable': '' "
      @click="startRecording" 
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