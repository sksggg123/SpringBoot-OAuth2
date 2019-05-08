<template>
    <div>
      <a href="/oauth2/authorization/github">{{ login }} _ 1</a>
      <br>
      <a href="/user">{{ login }} _ 2</a>
      <br>
      <a href="/login">{{ login }} _ 3</a>
      <br>
      <a href="/login/github">{{ login }} _ 4</a>
      <br>
      <a href="/oauth2/authorization/google" >google 로그인</a>
    </div>
</template>

<script>
    export default {
        data() {
          return {
            login: 'Github Login',
          }
        },
    }
</script>

<style scoped>

</style>
