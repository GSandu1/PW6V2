import Vue from 'vue';
import Router from 'vue-router';
import Home from '../src/components/MainPage.vue'; 
import LikedVideos from '../src/components/LikedVideos.vue';

Vue.use(Router);

export default new Router({
  routes: [
    {
      path: '/',
      name: 'Home',
      component: Home
    },
    {
      path: '/likedvideos',
      name: 'LikedVideos',
      component: LikedVideos
    }
  ]
});