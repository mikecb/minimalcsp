package minimalcsp_test

s := `<!doctype html>

<html lang="en">
<head>
<title>mikecb.org</title>

<!-- Meta info -->
<meta charset="utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link rel="shortcut icon" href="images/favicon/favicon.ico" type="image/x-icon">
<link rel="icon" href="images/favicon/favicon.ico" type="image/x-icon">

<!-- MDL styles and js -->
<script async src="js/material.min.js"></script>
<link rel="stylesheet" href="stylesheets/material.cyan-deep_orange.min.css">
<link rel="stylesheet" href="stylesheets/icon.css">

<!-- Local styles -->
<link href="https://fonts.googleapis.com/css?family=Open+Sans:300" rel="stylesheet">
<link href="stylesheets/home.css" rel="stylesheet">

<!-- Google Analytics -->
<script>
window.ga=window.ga||function(){(ga.q=ga.q||[]).push(arguments)};ga.l=+new Date;
ga('create', 'UA-42723924-1', 'auto');
ga('send', 'pageview');
</script>
<script async src='https://www.google-analytics.com/analytics.js'></script>

</head>

<body>
<!-- Uses a transparent header that draws on top of the layout's background -->
<style>
.layout-transparent .mdl-layout__header,
.layout-transparent .mdl-layout__drawer-button {
color: white;
}
</style>

<div class="layout-transparent mdl-layout mdl-js-layout">
<header class="mdl-layout__header mdl-layout__header--transparent">
</header>
<div class="mdl-layout__drawer">
<span class="mdl-layout-title">mikecb.org</span>
<nav class="mdl-navigation">
  <a class="mdl-navigation__link" href="/pages/about.html">about</a>
  <a class="mdl-navigation__link" href="https://github.com/stars/mikecb">tools</a>
  <a class="mdl-navigation__link" href="/pages/projects.html"></a>
</nav>
</div>
<main class="mdl-layout__content">
  <div class="name">Michael C. Brown</div>
  <div class="title">Lawyer, Economist, Online Adventurer</div>

  <div class="logos">
      <a href="https://mikecborg.wordpress.com">Blog</a>
      <a href="https://twitter.com/mikecb">Twitter</a>
      <a href="https://github.com/mikecb">Github</a>
      <a href="https://news.ycombinator.com/user?id=mikecb">HN</a>
      <a href="https://www.linkedin.com/in/mikecb">LinkedIn</a>
  </div>
</main>
</div>
</body>

</html>`
