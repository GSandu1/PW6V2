<template>
    <div :class="['drawer', { 'is-open': isOpen }]">
      <div class="closeButton-div">
        <button @click="toggleDrawer" class="closeDrawer">
          <svg class="svgIcon" viewBox="0 0 25 25" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path d="M3 21.32L21 3.32001" stroke="#000000" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
            <path d="M3 3.32001L21 21.32" stroke="#000000" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
        </button>
      </div>
      <div class="drawer-content">
        <nav>
          <router-link class="rouetButton" to="/">Home</router-link>
          <router-link class="rouetButton" to="/likedvideos">Liked Videos</router-link>
        </nav>
        <div class="theme-switcher">
          <span>Dark-mode</span>
          <label class="switch">
            <input type="checkbox" @change="$emit('toggle-theme')" :checked="isDarkTheme">
            <span class="slider round"></span>
          </label>
        </div>
      </div>
    </div>
</template>

  
  <script>
  export default {
    name: "Drawer",
    props: {
      isOpen: Boolean,
      isDarkTheme: Boolean
    },
    methods: {
        toggleDrawer() {
          // eslint-disable-next-line
            console.log('Toggling drawer'); // Check if this logs when the button is clicked
            this.$emit('toggle-drawer');
        }
    },

  }
  </script>
  
  <style >
  .drawer {
    position: fixed;
    left: 0;
    top: 0;
    width: 300px;
    height: 100%;
    background-color: var(--background-color);
    box-shadow: 2px 0 5px rgba(0,0,0,0.5);
    transform: translateX(-100%);
    transition: transform 0.3s ease;
    z-index: 999;
    display: flex;
    flex-direction: column;
    padding: 20px;
  }
  
  .drawer.is-open {
    transform: translateX(0);
  }
  
  .drawer button, .drawer nav a, .theme-switcher {

    margin-bottom: 10px; /* Consistent spacing */
    background-color: var(--background-color);
    /* background-color: transparent; */
    color: var(--text-color);


    cursor: pointer;
    transition: background-color 0.2s;
 
  }
  
  .drawer button:hover, .drawer nav a:hover {
    background-color: #e0e0e0;
    color: var(--text-color-hover);
  }
  
  .drawer nav {
    display: flex;
    flex-direction: column;
  }
  
  .theme-switcher {
    display: flex;
    align-items: center; 
    padding: 15px;
  }
  
  .theme-switcher span {
    margin-right: 10px; /* Space between label and switch */
  }
  
  .switch {
    position: relative;
    display: inline-block;
    width: 60px;
    height: 34px;
    margin: 0; /* Remove margin for alignment */
  }
  
  .switch input {
    opacity: 0;
    width: 0;
    height: 0;
  }
  
  .slider {
    position: absolute;
    cursor: pointer;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background-color: #ccc;
    transition: .4s;
    border-radius: 34px;
  }
  
  .slider:before {
    position: absolute;
    content: "";
    height: 26px;
    width: 26px;
    left: 4px;
    bottom: 4px;
    background-color: white;
    transition: .4s;
    border-radius: 50%;
  }
  
  input:checked + .slider {
    background-color: #2196F3;
  }
  
  input:checked + .slider:before {
    transform: translateX(15px);
  }
  
  .slider.round {
    border-radius: 34px;
  }
  
  .slider.round:before {
    border-radius: 50%;
  }

  .closeDrawer{
    width: 54px;
    height: 54px;
    display: flex;
    justify-content: center;
    align-items: center;
    border: solid ;
    border: 1px solid black;
    border-radius: 5px;


  }

  .svgIcon{
    width: 30px!important;
    height: 30px!important;
  }



  .closeButton-div{
    /* display: flex;
    justify-content: end;
    align-items: center; */
    position: fixed;
    top:20px;
    right:10px;
  }

  .rouetButton{
    /* width: 220px; */
    padding:15px;
  }
  
  </style>
  
  