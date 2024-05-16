<template>
    <div class="container">
      <h2 class="h2div">Liked Videos</h2>
      <div class="row">
        <VideoDetail
          v-for="video in filteredVideos"
          :key="video.id.videoId"
          :video="video"
          :isLiked="true"
          @unlikeVideo="handleUnlikeVideo"
        />
      </div>
    </div>
  </template>
  
  <script>
  import VideoDetail from './VideoDetail.vue';
  
  export default {
    name: 'LikedVideos',
    components: {
      VideoDetail
    },
    props: ['videos'],
    data() {
      return {
        likedVideoIds: JSON.parse(localStorage.getItem('likedVideos')) || []
      };
    },
    computed: {
      filteredVideos() {
        return this.videos.filter(video => this.likedVideoIds.includes(video.id.videoId));
      }
    },
    methods: {
      handleUnlikeVideo(videoId) { 
        const index = this.likedVideoIds.indexOf(videoId);
        if (index > -1) {
          this.likedVideoIds.splice(index, 1); 
          localStorage.setItem('likedVideos', JSON.stringify(this.likedVideoIds));
          this.$emit('unlikeVideo', videoId);
        }
      }
    }
  };
  </script>
    
    <style>
    .embed-responsive-item {
      width: 100%;
      height: 200px; 
    }

    .h2div{
      width: 100%;
      display: flex;
      justify-content: center;
      margin-top: 30px;
    }
    </style>
    