# AnanasMusicBot

AnanasMusicBot allows Twitch-Streamers to host their own Songrequest Channelpoints-Redemptions, by hosting this project.

If you need help, hosting this on your server, you can always contact me.

## Prerequisites

Server with nodejs installed

MySQL-Database

Spotify-App
https://developer.spotify.com/dashboard/create

Install "forever" globally

## Installation

musicbot-server is hosting the channelpoints redemption service.

```
forever start index.js
```

musicbot is creating the Chatbot.

```
forever start irc-client.js
```

```
npm install
```

## License

[MIT](https://choosealicense.com/licenses/mit/)
