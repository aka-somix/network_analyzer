import { createRouter, createWebHashHistory} from 'vue-router'

export default createRouter({
  history: createWebHashHistory(),
  routes: [
    {
      path: '/',
      component: import('./views/StartPage.vue'),
    },
    {
      path: '/select-device',
      component: () => import('./views/DeviceSelection.vue'),
    },
    {
      path: '/record',
      component: () => import('./views/NetworkRecording.vue'),
    },
  ],
})
