# authsession
Go / Golang , Google Oauth2 authentication and sessions handling to use with webpages.

## Oauth2

Oauth2 for authenticating towards Google. Will return the personalia of the user logged in.

You need to register an Oauth2 App at google cloud, with a callback similar to the one specified in the code example below.

After registering an app at Google Cloud, you need to export environment variables like the example below

```
export cookiestorekey=some-cookie-store-key-here
export googlekey=some-google-key-here
export googlesecret=some-google-secret-here
```

## Sessions

Using Gorilla Sessions for session handling, and storing all session values in a session token.
This token can be checked for the key `authenticated` and if true user will get access to the page requested.

A wrapper function is also included, and you wrap this around the HandlerFunc you define in your http.HandleFunc statement. Example below.

```Go
    a := authsession.NewAuth("http://", "localhost", ":8080")
    //Run will start the http.HandleFunc's needed for authentication.
    //The HandleFunc's started with Run() are :
    //http.HandleFunc("/login", a.login)
	//http.HandleFunc("/logout", a.logout)
    //http.HandleFunc("/callback", a.handleGoogleCallback)
    //
    //Then you can specify and use /login, /logout in your html page, and you use the /callback when you registert the callback url in the Oauth2 app at google cloud. Example of callback string for google is `http://localhost:8080/callback`
	a.Run()

    http.HandleFunc("/upload", a.IsAuthenticated(d.uploadImage))

    err := http.ListenAndServe(*hostListen+*port, nil)
	if err != nil {
		log.Println("error: ListenAndServer failed: ", err)
	}

```