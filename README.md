# AnanasMusicBot

Open Source Twitch Spotify Bot, by twitch.tv/ananasxpress_

AnanasMusicBot allows Twitch-Streamers to host their own Songrequest Channelpoints-Redemptions, by hosting this project.
There is no additional cost, except from hosting a webserver that can run a NodeJS App, that supports https and certificates.

If you need help, hosting this on your server, you can always contact me.

## Prerequisites

Server with nodejs installed

Set up a MySQL-Database
Execute the setup.sql to create the initial database structure

Create Spotify-App
https://developer.spotify.com/dashboard/create
Write down your Client ID and Client Secret

Create Twitch App
https://dev.twitch.tv/console/apps
Write down your Client ID and Client Secret

Setup your webserver, so that it can host a https Webserver, therefore you need to get a certificate and store it securely.

Fill in the .env file by replacing the corresponding values.

Install "forever" globally

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


## License

[CC BY-NC 4.0 DEED](https://creativecommons.org/licenses/by-nc/4.0/)
