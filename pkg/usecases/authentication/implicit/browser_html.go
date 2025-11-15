package implicit

import "fmt"

// BrowserSuccessHTML is the HTML page shown after successful authentication
const BrowserSuccessHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Authentication Successful</title>
</head>
<body>
    <h1>Authentication Successful</h1>
    <p>You can close this window.</p>
</body>
</html>`

// BrowserRedirectHTML returns HTML that redirects to the given URL
func BrowserRedirectHTML(url string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="0;url=%s">
    <title>Authentication Successful</title>
</head>
<body>
    <p>Redirecting to <a href="%s">%s</a>...</p>
</body>
</html>`, url, url, url)
}
