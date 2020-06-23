package templates

// AuthCodeBrowserSuccessHTML is the success page on browser based authentication.
const AuthCodeBrowserSuccessHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<title>Authenticated</title>
	<script>
		window.close()
	</script>
	<style>
		body {
			background-color: #eee;
			margin: 0;
			padding: 0;
			font-family: sans-serif;
		}
		.placeholder {
			margin: 5em;
			padding: 2em;
			background-color: #fff;
			border-radius: 1em;
		}
	</style>
</head>
<body>
	<div class="placeholder">
		<h1>Authenticated</h1>
		<p>You have logged in to the cluster. You can close this window.</p>
	</div>
</body>
</html>
`
