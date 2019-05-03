<template>
    <div>
      <a href="/oauth2/authorization/github">{{ login }}</a>
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
