import Vue from 'vue'
import Router from 'vue-router'
import Header from '@/components/Header.vue'

Vue.use(Router)

export default new Router({
  mode: 'history',
  routes: [
    {
      path: '/',
      component: Header
    }
  ]
})
