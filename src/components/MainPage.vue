<template>
    <div class="searchDiv">
      <SearchBar @termChange="fetchVideos" />
      <div class="row">
        <VideoDetail :video="selectVideo" />
        <VideoList :videos="videos" @videoSelect="handleVideoSelect" />
      </div>
    </div>
  </template>
  
  <script>
  import SearchBar from './SearchBar.vue';
  import VideoList from './VideoList';
  import VideoDetail from './VideoDetail';
  
  export default {
    name: 'MainPage',
    components: {
      SearchBar,
      VideoList,
      VideoDetail
    },
    props: {
      videos: Array,
      selectVideo: Object
    },
    methods: {
      fetchVideos(searchTerm) {
        this.$emit('termChange', searchTerm);
      },
      handleVideoSelect(video) {
        this.$emit('videoSelect', video);
      }
    }
  };
  </script>
  
  <style>
    .searchDiv{
      margin-top: 30px;
    }
  </style>