<template>
  <div v-if="video" class="col-md-8">
    <div class="embed-responsive embed-responsive-16by9">
      <iframe class="embed-responsive-item" :src="videoUrl" allowfullscreen></iframe>
    </div>
    <div class="detail">
      <h4>{{ video.snippet.title }}</h4>
      <p>{{ video.snippet.description }}</p>
      <button @click="toggleLike" class="btn" :class="{ 'btn-danger': isLiked, 'btn-primary': !isLiked }">
        {{ isLiked ? 'Unlike' : 'Like' }}
      </button>
    </div>
  </div>
</template>

<script>
const YOUTUBE_URL = "https://www.youtube.com/embed/";

export default {
  name: "VideoDetail",
  props: ["video", "isLiked"],
  computed: {
    videoUrl() {
      return `${YOUTUBE_URL}${this.video.id.videoId}`;
    }
  },
  methods: {
    toggleLike() {
    const likedVideos = JSON.parse(localStorage.getItem('likedVideos')) || [];
    const videoId = this.video.id.videoId;
    if (this.isLiked) {
      const index = likedVideos.indexOf(videoId);
      if (index > -1) {
        likedVideos.splice(index, 1);
      }
    } else {
      likedVideos.push(videoId);
    }
    localStorage.setItem('likedVideos', JSON.stringify(likedVideos));
    this.$emit(this.isLiked ? 'unlikeVideo' : 'likeVideo', videoId);

  }
  }
};
</script>


<style scoped>
.detail {
  margin: 10px;
  padding: 10px;
  border: 1px solid #ddd;
  border-radius: 4px;
}

.btn-primary {
  margin-top: 10px;
}
</style>