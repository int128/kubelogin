package authcode

import (
	"fmt"
	"net/url"
)

// BrowserSuccessHTML is the success page on browser based authentication.
const BrowserSuccessHTML = `
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
			margin: 2em;
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

func BrowserRedirectHTML(target string) string {
	targetURL, err := url.Parse(target)
	if err != nil {
		return fmt.Sprintf(`invalid URL is set: %s`, err)
	}
	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="en">
<head>
	<meta http-equiv="refresh" content="0;URL=%s">
	<meta charset="UTF-8">
	<title>Authenticated</title>
</head>
<body>
	<a href="%s">redirecting...</a>
</body>
</html>
`, targetURL, targetURL)
}
