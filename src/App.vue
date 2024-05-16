<template>
  <div id="app" class="container">
    <button @click="drawerOpen = !drawerOpen" class="drawer-toggle"><svg width="20px" height="20px" viewBox="-0.5 0 25 25" fill="none" xmlns="http://www.w3.org/2000/svg">
<path d="M2 12.32H22" stroke="#000000" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
<path d="M2 18.32H22" stroke="#000000" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
<path d="M2 6.32001H22" stroke="#000000" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
</svg></button>
    <Drawer :is-open="drawerOpen" :is-dark-theme="darkTheme" 
            @toggle-drawer="drawerOpen = !drawerOpen"
            @toggle-theme="toggleTheme" />
    <router-view :videos="videos" :selectVideo="selectVideo" :handleUnlike="handleUnlike" 
                 @videoSelect="onVideoSelect" @termChange="fetchVideos">
    </router-view>
  </div>
</template>

<script>
import axios from "axios";
import Drawer from './components/Drawer.vue';


const API_KEY = 'AIzaSyCb26l4AVOa7V37RznlWgAbnDZymZAtJ_c';
const YOUTUBE_V3_URL = 'https://www.googleapis.com/youtube/v3/search';

export default {
  name: "App",
  components: {
    Drawer
  },
  data() {
    return {
      drawerOpen: false,
      videos: [],
      selectVideo: null,
      darkTheme: false
    };
  },
  methods: {
    toggleTheme() {
      this.darkTheme = !this.darkTheme;
      document.body.className = this.darkTheme ? "dark-theme" : "";
      
    },
    fetchVideos(searchTerm) {
      axios.get(YOUTUBE_V3_URL, {
        params: {
          key: API_KEY,
          type: 'video',
          part: 'snippet',
          q: searchTerm
        }
      })
      .then(response => {
        this.videos = response.data.items;
      });
    },
    onVideoSelect(video) {
      this.selectVideo = video;
    },
    handleUnlike(videoId) {
      const likedVideos = JSON.parse(localStorage.getItem('likedVideos')) || [];
      const updatedLikedVideos = likedVideos.filter(id => id !== videoId);
      localStorage.setItem('likedVideos', JSON.stringify(updatedLikedVideos));
      this.fetchVideos();
    }
  }
};
</script>

<style>

:root {
  --background-color: #fff;
  --text-color: #000;
  --text-color-hover: #fff;
  --input-background: #fff;
  --input-text: #000;
}


.dark-theme {
  --background-color: #333;
  --text-color: #fff;
  --text-color-hover:#000000;
  --input-background: #555;
  --input-text: #fff;
}

body {
  background-color: var(--background-color);
  color: var(--text-color);
}

input {
  background-color: var(--input-background);
  color: var(--input-text);
}

.drawer-toggle {
  position: fixed; 
  top: 20px; 
  left: 20px; 
  padding: 10px 20px; 
  color: white;
  border: none; 
  border-radius: 12px; 
  font-size: 16px;
  cursor: pointer; 
  box-shadow: 0 2px 5px rgba(0, 0, 0, 0.2); 
  transition: background-color 0.3s, box-shadow 0.3s; 
  outline: none; 
}

.drawer-toggle:hover {
  background-color: #0056b3; 
  box-shadow: 0 4px 8px rgba(0, 0, 0, 0.3); 
}

.drawer-toggle:focus {
  outline: none; 
}


</style>
