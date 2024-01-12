# AnanasMusicBot

Open Source Twitch Spotify Bot, by twitch.tv/ananasxpress_

AnanasMusicBot allows Twitch-Streamers to host their own Songrequest Channelpoints-Redemptions, by hosting this project.
There is no additional cost, except from hosting a webserver that can run a NodeJS App, that supports https and certificates.

If you need help, hosting this on your server, you can always contact me.

## Prerequisites

- Insomnia REST Caller (https://insomnia.rest/download)
- Server with nodejs installed
- Set up a MySQL-Database
  - Execute the setup.sql to create the initial database structure
- Create Spotify-App
  - https://developer.spotify.com/dashboard/create
  - Write down your Client ID and Client Secret
- Create a Twitch Account, that is your actual Chat-Bot
- Create Twitch App
  - https://dev.twitch.tv/console/apps
  - Write down your Client ID and Client Secret
- Setup your webserver, so that it can host a https Webserver, therefore you need to get a certificate
  - Create a folder "certs"
  - Add certificate and key as "cert.pem" and "key.pem" to the folder.
- Create a file '.env', copy everything from .example.env and fill in the values as described in the placeholders.

Once this is done, you need to create the connection between your Bot Account and the Twitch App and allow the Bot to reauthenticate itself

- Log into your Twitch Bot Account
- Navigate to https://id.twitch.tv/oauth2/authorize?response_type=code&client_id=YOUR_CLIENT_ID&redirect_uri=YOUR_TWITCH_REDIRECT_URI&scope=chat%3Aread+chat%3Aedit
- Authenticate the bot, you will then be redirected to the redirect URI.
- Check the URL in your browser, there will be a query parameter called "code".
- Copy the value
- Execute a POST request with Insomnia to:
  https://id.twitch.tv/oauth2/token?client_id=YOUR_CLIENT_ID8&client_secret=YOUR_CLIENT_SECRET&code=CODE_RETURNED_FROM_PREVIOUS_STEP&grant_type=authorization_code&redirect_uri=YOUR_TWITCH_REDIRECT_URI
- Log into your Database
- In table 'bot_tokenstore' add a new row
- Values: "twitch_id" -> Twitch ID of the Bot, "accessToken" -> Value of "access_token" from the POST Request, "expires_in" -> Set to 0, obtainmentTimestamp -> Set to 0, "refreshToken" -> Value of "refresh_token" from the POST Request, "scope" -> "[chat:edit,chat:read] 

On the next start, the bot should automatically get a new token and persist it.

## Installation

```
npm install
```

```
npm install -g forever
```

```
forever start index.js
```

## Usage

To finally use the bot, start it and then visit YOUR_BASE_URL/start

First connect your Twitch Account and give the bot access to the requested scopes. 
Then fill in your Twitch ID and Username.
You will be redirected back to the start and can click on Connect to Spotify.
Give the Spotify App Access to your account
The Bot should then join your channel and write a message that it is there. Type !srcommands to check that it works and see all available commands.

If you want to give others the opportunity to use your instance, they have to follow the steps to connect their account and also they need to give you their email address, so that you can add them in the Spotify Developer Console.
There is a limited space of 25 Users in the Development Mode of a Spotify App.

## License

[CC BY-NC 4.0 DEED](https://creativecommons.org/licenses/by-nc/4.0/)
