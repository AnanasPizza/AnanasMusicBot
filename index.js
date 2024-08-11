import crypto from 'crypto';
import express from 'express';
import https from 'https';
import http from 'http';
import querystring from 'node:querystring';
import sessions from 'express-session';
import fs from 'fs';
import axios, { all } from 'axios';
import mysql from 'mysql2';
import dotenv from "dotenv";
import { RefreshingAuthProvider } from '@twurple/auth';
import { ChatClient } from '@twurple/chat';
import { ApiClient } from '@twurple/api';
import schedule from 'node-schedule';
import bodyParser from 'body-parser';
import {isNumberFromOneToTen, convertMillisecondsToMinuteSeconds} from "./lib/lib.js";
import CryptoJS from "crypto-js";
import Filter from 'bad-words';
import util from 'util';
import qs from 'qs';
import cookieParser from 'cookie-parser';
const filter = new Filter();

// Notification request headers
const TWITCH_MESSAGE_ID = 'Twitch-Eventsub-Message-Id'.toLowerCase();
const TWITCH_MESSAGE_TIMESTAMP = 'Twitch-Eventsub-Message-Timestamp'.toLowerCase();
const TWITCH_MESSAGE_SIGNATURE = 'Twitch-Eventsub-Message-Signature'.toLowerCase();
const MESSAGE_TYPE = 'Twitch-Eventsub-Message-Type'.toLowerCase();

// Notification message types
const MESSAGE_TYPE_VERIFICATION = 'webhook_callback_verification';
const MESSAGE_TYPE_NOTIFICATION = 'notification';
const MESSAGE_TYPE_REVOCATION = 'revocation';

// Prepend this string to the HMAC that's created from the message
const HMAC_PREFIX = 'sha256=';

dotenv.config();

const ENCRYPTION_PWD = process.env.ENCRYPTION_PWD;
const TWITCH_CLIENT_ID            = process.env.TWITCH_CLIENT;
const TWITCH_SECRET               = process.env.TWITCH_SECRET;

const requestTimeoutMap = new Map();

const nick = process.env.NICKNAME;

var state = generateRandomString(16);

const app = express();

// Need raw message body for signature verification
app.use(express.raw({          
    type: 'application/json'
}));

app.use(bodyParser.urlencoded({ extended: true }));

app.use('/', express.static('public'));
app.use(cookieParser());

let dbconfig = {
  host: process.env.DB_HOST,
  port: 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 5,
  maxIdle: 5, // max idle connections, the default value is the same as `connectionLimit`
  idleTimeout: 10000, // idle connections timeout, in milliseconds, the default value 60000
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 0
};

let appAccessToken = {
  access_token: "",
	expires_in: 0,
  obtained_at: Date.now()
}

const devMode = process.env.DEV_MODE === "true";

let pool = mysql.createPool(dbconfig);

pool.on('release', () => {
  console.log('Connection released to the pool');
});

pool.on('acquire', () => {
  console.log('Connection acquired from the pool');
});


const oneDay = 1000 * 60 * 60 * 24;
app.use(sessions({
  secret: process.env.SESSION_SECRET,
  saveUninitialized:true,
  cookie: { maxAge: oneDay },
  resave: false 
}));

const sql = 'SELECT twitchlogin, spotify_instance_id FROM tokenstore ORDER BY id ASC';
let twitchIds = [];
let highestSpotifyId = 1;
let spotifyInstanceIdMap = new Map();
console.log('Devmode:' + devMode);
if (!devMode) {
  pool.query(sql, (err, results, fields) => {
    if (err) {
      console.log(err);
      return;
    }
    // Iterate the results
    results.forEach((row) => {
      twitchIds.push(row.twitchlogin);
      if (spotifyInstanceIdMap.has(row.spotify_instance_id)) {
        let currVal = spotifyInstanceIdMap.get(row.spotify_instance_id);
        currVal += 1;
        spotifyInstanceIdMap.set(row.spotify_instance_id, currVal);
      } else {
        spotifyInstanceIdMap.set(row.spotify_instance_id, 1);
      }
      highestSpotifyId = row.spotify_instance_id;
    });
    console.log(spotifyInstanceIdMap);
    //Maximum 25 users allowed per spotify development instance.
    if (spotifyInstanceIdMap.get(highestSpotifyId) >= 25) {
      //Switch to the next instance.
      highestSpotifyId += 1;
    }
  });
} else {
  console.log("Development Mode, joining " + process.env.TWITCH_OWNER +" only");
  twitchIds.push(process.env.TWITCH_OWNER);
  pool.query(sql, (err, results, fields) => {
    if (err) {
      console.log(err);
      return;
    }
    // Iterate the results
    results.forEach((row) => {
      if (spotifyInstanceIdMap.has(row.spotify_instance_id)) {
        let currVal = spotifyInstanceIdMap.get(row.spotify_instance_id);
        currVal += 1;
        spotifyInstanceIdMap.set(row.spotify_instance_id, currVal);
      } else {
        spotifyInstanceIdMap.set(row.spotify_instance_id, 1);
      }
      highestSpotifyId = row.spotify_instance_id;
    });
    console.log(spotifyInstanceIdMap);
    //Maximum 25 users allowed per spotify development instance.
    if (spotifyInstanceIdMap.get(highestSpotifyId) >= 25) {
      //Switch to the next instance.
      highestSpotifyId += 1;
    }
  });
}

const clientId = process.env.TWITCH_CLIENT;
const clientSecret = process.env.TWITCH_SECRET;

const authProvider = new RefreshingAuthProvider(
	{
		clientId,
		clientSecret
	}
);

authProvider.onRefresh(async (userId, newTokenData) => await updateToken(userId, newTokenData));

const tokenDataChat = await getChatTokendata();
const tokenDataApi = await getApiTokendata();
await authProvider.addUserForToken(tokenDataChat, ['chat']);
await authProvider.addUserForToken(tokenDataApi, ['api']);
async function getChatTokendata() {
  const sql = 'SELECT * FROM bot_tokenstore where twitch_id = ?';
  const promisePool = pool.promise();
  const [rows,fields] = await promisePool.query(sql, [process.env.TWITCH_ID]);
  let tokenData = {
    accessToken: "",
    refreshToken: "",
    expiresIn: 0,
    obtainmentTimestamp: Date.now()
  };
  // Iterate the results
  rows.forEach((row) => {
    tokenData.accessToken = CryptoJS.AES.decrypt(row["accessToken"], ENCRYPTION_PWD).toString(CryptoJS.enc.Utf8),
    tokenData.refreshToken = CryptoJS.AES.decrypt(row["refreshToken"], ENCRYPTION_PWD).toString(CryptoJS.enc.Utf8),
    tokenData.expiresIn = row["expiresIn"],
    tokenData.obtainmentTimestamp = row["obtainmentTimestamp"]
  });
  return tokenData;
}

async function getApiTokendata() {
  const sql = 'SELECT * FROM bot_tokenstore where twitch_id = ?';
  const promisePool = pool.promise();
  const [rows,fields] = await promisePool.query(sql, [process.env.TWITCH_ID]);
  let tokenData = {
    accessToken: "",
    refreshToken: "",
    expiresIn: 0,
    obtainmentTimestamp: Date.now()
  };
  // Iterate the results
  rows.forEach((row) => {
    tokenData.accessToken = CryptoJS.AES.decrypt(row["accessToken"], ENCRYPTION_PWD).toString(CryptoJS.enc.Utf8),
    tokenData.refreshToken = CryptoJS.AES.decrypt(row["refreshToken"], ENCRYPTION_PWD).toString(CryptoJS.enc.Utf8),
    tokenData.expiresIn = row["expiresIn"],
    tokenData.obtainmentTimestamp = row["obtainmentTimestamp"]
  });
  return tokenData;
}


async function updateToken(userId, newTokenData) {
  let tokenEnc = new String(CryptoJS.AES.encrypt(newTokenData["accessToken"], ENCRYPTION_PWD)).toString();
  let refreshEnc = new String(CryptoJS.AES.encrypt(newTokenData["refreshToken"], ENCRYPTION_PWD)).toString();
  pool.getConnection(function(conn_err, conn) {
    if (conn_err) {
      console.log(console_err);
      return false;
    }
    const updateQuery = `
      UPDATE bot_tokenstore
      SET accessToken = ?, expiresIn = ?, obtainmentTimestamp = ?, refreshToken = ?, scope = ?
      WHERE LOWER(twitch_id) = ?
    `;
    conn.query(updateQuery, [tokenEnc, newTokenData["expiresIn"], Date.now(), refreshEnc, "[" + newTokenData["scope"] + "]", userId], (err, results) => {
      if (err) {
        console.log(err);
        pool.releaseConnection(conn);
        return;
      }
      pool.releaseConnection(conn);
    });
  });
}

const chatClient = new ChatClient({ authProvider, channels: twitchIds, rejoinChannelsOnReconnect: true });
const apiClient = new ApiClient({ authProvider });
chatClient.connect();

chatClient.onAuthenticationSuccess((text, retryCount) => {
  console.log("Connected to Server");
  chatClient.say(process.env.NICKNAME, "AnanasMusicBot V1 Connected");
});

chatClient.onAuthenticationFailure((text, retryCount) => {
  console.log("Epic Fail, could not connect");
})


async function getAllEventSubs() {
  const baseUrl = 'https://api.twitch.tv/helix/eventsub/subscriptions';
  const accessToken = await getTwitchAppAuthToken();
  const clientId = TWITCH_CLIENT_ID;

  const headers = {
    'Authorization': `Bearer ${accessToken}`,
    'Client-Id': clientId
  };

  let response = await axios.get(baseUrl, { headers });
  return response.data;
}

async function removeDisabledWebhooks(disabledWebhooks) {
  for (var entry of disabledWebhooks.entries()) {
    var key = entry[0], value = entry[1];
    for (let i = 0; i < value.length; i++) {
      console.log("Removing failed webhook " + value[i] + " for channelid " + key);
      await deleteWebhook(value[i]);
    }
  }
}

async function getTempAuthTokenByCode(code) {
  const data = {
    client_id: process.env.TWITCH_CLIENT,
    client_secret: process.env.TWITCH_SECRET,
    code: code,
    grant_type: 'authorization_code',
    redirect_uri: process.env.TWITCH_REDIRECT_URI
  };
  
  let result = await axios.post('https://id.twitch.tv/oauth2/token', data, {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    }
  });
  return result.data;
}

async function getUserInfoByToken(oauthToken) {
  let result = await axios.get('https://api.twitch.tv/helix/users', {
    headers: {
      'Authorization': 'Bearer ' + oauthToken,
      'Client-ID': process.env.TWITCH_CLIENT
    }
  });
  return result.data;
}

async function deleteWebhook(webhookId) {
  const baseUrl = 'https://api.twitch.tv/helix/eventsub/subscriptions?id=';
    const accessToken = await getTwitchAppAuthToken();
    const clientId = TWITCH_CLIENT_ID;
    const url = baseUrl + webhookId;
    const headers = {
      'Authorization': `Bearer ${accessToken}`,
      'Client-Id': clientId
    };
    try {
      const response = await axios.delete(url, {headers});
      if (response.data.status === 404) {
        console.log("Already deleted");
      } else {
        console.log(response.data);
      }
    } catch(err) {
      console.log(err.response.data);
      if (err.response.data.status === 404) {
        console.log("Already deleted");
      } else {
        console.log("Error when deleting webhook:\n"+err.response);
      }
    }
}

async function keepSubscriptionsAlive() {
  console.log("Getting all event subs");
  let allEventSubs = await getAllEventSubs();
  const eventSubsData = allEventSubs.data;
  console.log(util.inspect(allEventSubs, false, null, true));
  let enabledTwitchIds = [];
  let disabledTwitchIds = [];
  let disabledWebhooks = new Map();
  for (let y = 0; y < eventSubsData.length; y++) {
    let eventSub = eventSubsData[y];
    if (eventSub.status === 'enabled') {
      enabledTwitchIds.push(eventSub.condition.broadcaster_user_id);
      console.log("Eventsub enabled for channelid " + eventSub.condition.broadcaster_user_id);
    } else if (eventSub.status === 'notification_failures_exceeded') {
      disabledTwitchIds.push(eventSub.condition.broadcaster_user_id);
      if (disabledWebhooks.has(eventSub.condition.broadcaster_user_id)) {
        let entry = disabledWebhooks.get(eventSub.condition.broadcaster_user_id);
        entry.push(eventSub.id);
        disabledWebhooks.set(eventSub.condition.broadcaster_user_id, entry);
      } else {
        let entry = [eventSub.id];
        disabledWebhooks.set(eventSub.condition.broadcaster_user_id, entry);
      }
      console.log("Got disabled eventsub for channelid " + eventSub.condition.eventSub.condition.broadcaster_user_id);
      chatClient.say("ananasmusicbot", "EventSub for channel with id " + eventSub.condition.broadcaster_user_id + " not active anymore. Trying to refresh");
    }
  }
  disabledTwitchIds = disabledTwitchIds.filter(n => !enabledTwitchIds.includes(n));
  console.log(disabledTwitchIds);
  console.log("Trying to refresh subscription call.")
  let appToken = await getAppAccessToken();
  console.log("New token retrieved: " + appToken);
  for (let j = 0; j < disabledTwitchIds.length; j++) {
    let id = disabledTwitchIds[j];
    //let twitchToken = await getTwitchTokenByChannelId(id);
    //executeSubscriptionCall(twitchToken, id);
    executeSubscriptionCall(appToken, id);
  }
  removeDisabledWebhooks(disabledWebhooks);
}

async function getTwitchAppAuthToken() {
  if ((appAccessToken.obtained_at + (appAccessToken.expires_in * 1000)) < Date.now()) {
    const url = `https://id.twitch.tv/oauth2/token`;
    const data = new URLSearchParams({
      client_id: TWITCH_CLIENT_ID,
      client_secret: TWITCH_SECRET,
      grant_type: 'client_credentials'
    });
    const headers = {
      'Content-Type': 'application/x-www-form-urlencoded'
    };
    const response = await axios.post(url, data, { headers });
    appAccessToken.access_token = response.data.access_token;
    appAccessToken.expires_in = response.data.expires_in;
    appAccessToken.obtained_at = Date.now();
    return appAccessToken.access_token;
  } else {
    return appAccessToken.access_token;
  }
}
  
app.get("/start", async (req, res) => {
  var session=req.session;
  res.send(`
      <html>
      <head>
        <title>Login</title>
      </head>
        <body>
          <p>Currently Attached Twitch ID: ` + session.broadcasterId + `
          <a href="https://id.twitch.tv/oauth2/authorize?client_id=` + process.env.TWITCH_CLIENT +`&redirect_uri=`+ process.env.TWITCH_REDIRECT_URI +`&response_type=code&scope=channel%3Aread%3Aredemptions" class="btn btn-primary">Connect with Twitch</a>
          <a href="` + process.env.SPOTIFY_AUTH_URI +`" class="btn btn-primary">Connect with Spotify</a>
        </body>
      </html>
  `);
});
  
app.get('/spotifyauth', function(req, res) {
  var scope = 'user-modify-playback-state user-read-playback-state user-read-currently-playing user-read-recently-played';
  res.redirect('https://accounts.spotify.com/authorize?' +
    querystring.stringify({
      response_type: 'code',
      client_id: process.env.SPOTIFY_CLIENT,
      scope: scope,
      redirect_uri: process.env.SPOTIFY_CALLBACK_URI,
      state: state
    })
  );
});
  
app.get('/spotifycallback', function(req, res) {
  var code = req.query.code || null;
  var returned_state = req.query.state || null;
  const session = req.session;
  session.spotifycode = code;
  if (returned_state === null || returned_state !== state) {
    res.redirect('/#' +
      querystring.stringify({
        error: 'state_mismatch'
      }));
  } else {
    const options = {
      hostname: 'accounts.spotify.com',
      port: 443,
      path: '/api/token',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + (new Buffer.from(process.env.SPOTIFY_CLIENT + ':' + process.env.SPOTIFY_SECRET).toString('base64'))
      },
    };
    
    // Create the request body
    const data = "redirect_uri="+process.env.SPOTIFY_CALLBACK_URI
    +"&code="+code
    +"&grant_type=authorization_code";
    
  
    // Create the HTTP request
    const request = https.request(options, (response) => {
      // Handle the response
      let responseBody = '';
      response.on('data', (chunk) => {
        responseBody += chunk;
      });
      response.on('end', () => {
        let jsonBody = JSON.parse(responseBody);
        let accesstoken = new String(CryptoJS.AES.encrypt(jsonBody.access_token, ENCRYPTION_PWD)).toString();
        let refreshtoken = new String(CryptoJS.AES.encrypt(jsonBody.refresh_token, ENCRYPTION_PWD)).toString();
        let expiresin = jsonBody.expires_in;
        
        let dateInMillisecs = new Date().getTime();
        let dateInSecs = Math.round(dateInMillisecs / 1000);

        let calcExpiryDate = expiresin + dateInSecs - 10;
        pool.getConnection(function(err, conn) {
          // Do something with the connection
          if (session.broadcasterId != undefined) {
            let sql = "INSERT INTO tokenstore(twitchid, twitchlogin, spotifytoken, spotifyrefresh, spotifyexpiration, spotify_instance_id)"
            +"VALUES('"+session.broadcasterId+"','"+session.broadcasterName+"','"+accesstoken+"','"+refreshtoken+"','"+calcExpiryDate+"','"+highestSpotifyId+"')";
            try {
              conn.query(sql);
              console.log("Trying to join" + session.broadcasterName);
              let channelname = session.broadcasterName;
              chatClient.join(channelname);
              chatClient.say(channelname, "/me Channel Points Subscription is active now");
              res.redirect("https://ananasmusicbot.de/start");
            } catch (err) {
              console.log(err);
              res.sendStatus(500);
            }
          } else {
            res.redirect("https://ananasmusicbot.de/start");
          }
          // Don't forget to release the connection when finished!
          pool.releaseConnection(conn);
        });
      });
    });
    // Write the request body
    request.write(data);
    // End the request
    request.end();
  }
});
  
app.post('/eventsub', async (req, res) => {
    try {
      let secret = getSecret();
      let message = getHmacMessage(req);
      let hmac = HMAC_PREFIX + getHmac(secret, message);  // Signature to compare
      
      if (true === verifyMessage(hmac, req.headers[TWITCH_MESSAGE_SIGNATURE])) {
          let notification = JSON.parse(req.body);
          if (MESSAGE_TYPE_NOTIFICATION === req.headers[MESSAGE_TYPE]) {
            // Get JSON object from body, so you can process the message.
            // TODO: Do something with the event's data.
            let eventtitle = notification.event.reward.title;
            if ("channel.channel_points_custom_reward_redemption.add" === notification.subscription.type && eventtitle === "Songrequest") {
              res.sendStatus(204);
              let userInput = notification.event.user_input;
              let broadcasterId = notification.event.broadcaster_user_id;
              let requestedBy = notification.event.user_name;
              let broadcasterName = notification.event.broadcaster_user_name;
              console.log("Handling SR with input " + userInput + " in channel " + broadcasterName);
              const isBroadcaster = broadcasterName.trim().toLowerCase() === requestedBy.trim().toLowerCase();
              //const liveOnly = await getLiveOnly(null, broadcasterId);
              //console.log("Liveonly? " + liveOnly);
              const isChannelLive = true //await isLive(broadcasterName);
              console.log("Is Live? " + isChannelLive);
              console.log("Is Broadcaster? " + isBroadcaster);
              //If Broadcaster requested, or it's not live only, or the channel is live anyways: Allow spotify action;
              let allowSpotifyActions = isBroadcaster || isChannelLive; // || !liveOnly || ;
  
              if (!allowSpotifyActions) {
                chatClient.say(broadcasterName, "/me @" + requestedBy + ", Can't request songs when channel is offline due to specific setting");
              } else {
                let blacklisted = await isUserBlacklisted(broadcasterId, requestedBy);
                if (blacklisted) {
                  chatClient.say(broadcasterName, "/me @" + requestedBy + ", you are currently blacklisted for songrequests");
                } else {
                  const spotifyAuthToken = await getSpotifyToken(broadcasterName);
                  sendSongToQueue(spotifyAuthToken, userInput, broadcasterName, requestedBy, broadcasterId);
                }
              }            
            } else if ("channel.channel_points_custom_reward_redemption.add" === notification.subscription.type && eventtitle === "Skip Song") {
              res.sendStatus(204);
              let broadcasterId = notification.event.broadcaster_user_id;
              let requestedBy = notification.event.user_name;
              let broadcasterName = notification.event.broadcaster_user_name;
              console.log("Handling SkipSong in channel " + broadcasterName);
              const isBroadcaster = broadcasterName.trim().toLowerCase() === requestedBy.trim().toLowerCase();
              const liveOnly = await getLiveOnly(null, broadcasterId);
              console.log("Liveonly? " + liveOnly);
              const isChannelLive = true //await isLive(broadcasterName);
              console.log("Is Live? " + isChannelLive);
              console.log("Is Broadcaster? " + isBroadcaster);
              //If Broadcaster requested, or it's not live only, or the channel is live anyways: Allow spotify action;
              let allowSpotifyActions = isBroadcaster || !liveOnly || isChannelLive;
              if (!allowSpotifyActions) {
                chatClient.say(broadcasterName, "/me @" + requestedBy + ", Can't skip songs when channel is offline due to specific setting");
              } else {
                const spotifyAuthToken = await getSpotifyToken(broadcasterName);
                skipSong(spotifyAuthToken, broadcasterName);
              }
            }
          }
          else if (MESSAGE_TYPE_VERIFICATION === req.headers[MESSAGE_TYPE]) {
            res.set('Content-Type', 'text/plain').status(200).send(notification.challenge);
          }
          else if (MESSAGE_TYPE_REVOCATION === req.headers[MESSAGE_TYPE]) {
              res.sendStatus(204);
              console.log(`${notification.subscription.type} notifications revoked!`);
              console.log(`reason: ${notification.subscription.status}`);
              console.log(`condition: ${JSON.stringify(notification.subscription.condition, null, 4)}`);
          }
          else {
              res.sendStatus(204);
              console.log(`Unknown message type: ${req.headers[MESSAGE_TYPE]}`);
          }
      }
      else {
          console.log('403');
          res.sendStatus(403);
      }
    } catch (err) {
      res.sendStatus(204);
    }
    
});

async function getAppAccessToken() {
  try {
    const response = await axios.post('https://id.twitch.tv/oauth2/token', 
      `client_id=${process.env.TWITCH_CLIENT}&client_secret=${process.env.TWITCH_SECRET}&grant_type=client_credentials`,   
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'   
        }
      }
    );
    return response.data.access_token; 
  } catch (error) {
    // Handle errors appropriately, maybe redirect or log
    console.error('Error fetching access token:', error);
    // You might want to re-throw the error or return a specific value to indicate failure
    throw error; 
  }
}
  
app.post("/create-subscription", async (req, res) => {
  const broadcasterUserId = req.body.broadcaster_user_id;
  const broadcasterName = req.body.broadcaster_user_name;
  const session = req.session;
  session.broadcasterId = broadcasterUserId;
  session.broadcasterName = broadcasterName;
  const accesstoken = await getAppAccessToken();
  console.log(accesstoken);
  executeSubscriptionCallWrapper(accesstoken, broadcasterUserId, res);
  /*
  const options = {
    hostname: 'id.twitch.tv',
    port: 443,
    path: '/oauth2/token',
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  };
  
  // Create the request body
  const data = "client_id="+process.env.TWITCH_CLIENT
  +"&client_secret="+process.env.TWITCH_SECRET
  +"&grant_type=client_credentials";
  

  // Create the HTTP request
  const request = https.request(options, (response) => {
    // Handle the response
    let responseBody = '';
    response.on('data', (chunk) => {
      responseBody += chunk;
    });
    response.on('end', () => {
      let jsonBody = JSON.parse(responseBody);
      let accesstoken = jsonBody.access_token;
      executeSubscriptionCallWrapper(accesstoken, broadcasterUserId, res);
    });
  });

  request.on('error', function(err) {
    res.redirect('https://ananasmusicbot.de/error');
  });
  // Write the request body
  request.write(data);
  // End the request
  request.end();
  */
});

async function skipSong(spotifyAuthToken, broadcasterUserName) {
  const axiosInstance = axios.create({
    headers: {
        Authorization: 'Bearer '+spotifyAuthToken,
    },
  });

  const skipRequest = {
    method: 'POST',
    url: 'https://api.spotify.com/v1/me/player/next'
  }
  axiosInstance(skipRequest)
    .then(skipResponse => {
      let responseStr = "/me Skipped to next song";
      chatClient.say(broadcasterUserName, responseStr);
    })
    .catch(error => {
      console.log(error);
  });
}

async function skipBackSong(spotifyAuthToken, broadcasterUserName) {
  const axiosInstance = axios.create({
  headers: {
      Authorization: 'Bearer '+spotifyAuthToken,
  },
  });

  const skipRequest = {
    method: 'POST',
    url: 'https://api.spotify.com/v1/me/player/previous'
  }
  axiosInstance(skipRequest)
    .then(skipResponse => {
      let responseStr = "/me Rewinded to previous song";
      chatClient.say(broadcasterUserName, responseStr);
    })
    .catch(error => {
      console.log(error);
  });
}

async function executeSubscriptionCall(token, broadcasterUserId) {
  console.log("Executing subscription call for channelid " + broadcasterUserId + " with token " + token);
  const subscription = {
    type: "channel.channel_points_custom_reward_redemption.add",
    version: "1",
    condition: {
      broadcaster_user_id: broadcasterUserId
    },
    transport: {
      method: "webhook",
      callback: process.env.TWITCH_EVENTSUB_URI,
      secret: process.env.SUBSCRIPTION_SECRET
    },
  };
  try {
    const response = await axios({
      method: 'POST',
      url: 'https://api.twitch.tv/helix/eventsub/subscriptions', // Complete URL
      headers: {
        Authorization: 'Bearer ' + token,
        'Client-Id': process.env.TWITCH_CLIENT,
        'Content-Type': 'application/json',
      },
      data: subscription, // Axios automatically stringifies JSON data
    });

    console.log("Subscription Created:", response.data);
    chatClient.say("ananasmusicbot", "/me Refreshed EventSub Subscription for channel " + broadcasterUserId);
    return true;
    // Handle the successful response (e.g., store the subscription ID)
  } catch (error) {
    console.error("Error Creating Subscription:", error);
    chatClient.say("ananasmusicbot", "/me Failed to refresh EventSub Subscription for channel " + broadcasterUserId);
    // Handle errors (e.g., log error details, retry)
    return false;
  }
}

async function executeSubscriptionCallWrapper(token, broadcasterUserId, res) {
  let success = await executeSubscriptionCall(token, broadcasterUserId);
  if (success) {
    res.redirect('https://ananasmusicbot.de/start');
    console.log("Subscription call was successful")
  } else {
    res.redirect('https://ananasmusicbot.de/error');
    console.log("Subscription call was NOT successful")
  }
}
    
app.get("/twitchauth", async (req, res) => {
  let code = req.query.code;
  
  let tempTokenData = await getTempAuthTokenByCode(code);
  let oauthToken = tempTokenData.access_token;
  let expiresIn = tempTokenData.expires_in;
  let refreshToken = tempTokenData.refresh_token;

  let userInfo = await getUserInfoByToken(oauthToken);
  console.log(userInfo);
  let username = null;
  let userid = null;
  if (userInfo.data !== undefined && userInfo.data !== null && userInfo.data.length > 0) {
    userid = userInfo.data[0].id;
    username = userInfo.data[0].login;
  }
  res.setHeader('X-Auth-Code', code);
  if (userid !== null && username !== null) {
    res.send(`
      <form action="/create-subscription" method="post">
        <input type="text" name="broadcaster_user_id" placeholder="Broadcaster User ID" value="${userid}">
        <input type="text" name="broadcaster_user_name" placeholder="Broadcaster channelname" value="${username}">
        <input type="hidden" name="code" value=`+code+`>
        <input type="hidden" name="oauthtoken" value=`+oauthToken+`>
        <input type="hidden" name="expiresIn" value=`+expiresIn+`>
        <input type="hidden" name="refreshToken" value=`+refreshToken+`>
        <input type="submit" value="Create Subscription">
      </form>
      `);
  } else {
    /*
    res.send(`
      <a href="https://www.streamweasels.com/tools/convert-twitch-username-to-user-id" target="_blank">Find your Twitch ID</a>
      <form action="/create-subscription" method="post">
        <input type="text" name="broadcaster_user_id" placeholder="Broadcaster User ID">
        <input type="text" name="broadcaster_user_name" placeholder="Broadcaster channelname">
        <input type="hidden" name="code" value=`+code+`>
        <input type="hidden" name="oauthtoken" value=`+oauthToken+`>
        <input type="hidden" name="expiresIn" value=`+expiresIn+`>
        <input type="hidden" name="refreshToken" value=`+refreshToken+`>
        <input type="submit" value="Create Subscription">
      </form>
      `);
    */
      res.redirect('https://ananasmusicbot.de/error');
  }
});

app.get('/', (req,res)=>{
  res.render('index.ejs');
});

app.get('/error', (req,res)=>{
  res.render('error.ejs');
});
  
  
app.get('/commands', (req,res)=>{
  res.render('commands.ejs');
});

app.get('/channels/:channelid/blacklisted-tracks', async (req, res) => {
  const promisePool = pool.promise();
  const channel_id = req.params.channelid;
  const channelname = req.query.channelname;
  let sql = "SELECT * FROM blacklisted_tracks where channel_id = ?";
  const [rows,fields] = await promisePool.query(sql, [channel_id]);
  let tracks = [];
  if (rows.length < 1) {
    console.log("No blacklisted tracks in database");
  } else {
    
    for (let i = 0; i < rows.length; i++) {
      let track = {
        name: rows[i].songname,
        artist: rows[i].artist,
        tracklink: "https://open.spotify.com/intl-de/track/" + rows[i].blocked_track_id
      }
      tracks.push(track);
    }
  }
  res.render('blacklisted-tracks.ejs', {
    tracks: tracks,
    channelname: channelname
  });
});

app.get('/channels/:channelid/blacklisted-users', async (req, res) => {
  const promisePool = pool.promise();
  const channel_id = req.params.channelid;
  const channelname = req.query.channelname;
  let sql = "SELECT * FROM blacklisted_users where channel_id = ?";
  const [rows,fields] = await promisePool.query(sql, [channel_id]);
  let users = [];
  if (rows.length < 1) {
    console.log("No blacklisted users in database");
  } else {
    
    for (let i = 0; i < rows.length; i++) {
      let user = {
        name: rows[i].blocked_user_name
      }
      users.push(user);
    }
  }
  res.render('blacklisted-users.ejs', {
    users: users,
    channelname: channelname
  });
});

app.get('/channels/:channelid/blacklisted-artists', async (req, res) => {
  const promisePool = pool.promise();
  const channel_id = req.params.channelid;
  const channelname = req.query.channelname;
  let sql = "SELECT * FROM blacklisted_artists where channel_id = ?";
  const [rows,fields] = await promisePool.query(sql, [channel_id]);
  let artists = [];
  if (rows.length < 1) {
    console.log("No blacklisted artists in database");
  } else {
    for (let i = 0; i < rows.length; i++) {
      let artist = {
        artist: rows[i].name,
        artistlink: "https://open.spotify.com/intl-de/artist/" + rows[i].blocked_artist_id
      }
      artists.push(artist);
    }
  }
  res.render('blacklisted-artists.ejs', {
    artists: artists,
    channelname: channelname
  });
});

app.get('/channels', async (req, res) => {
  const promisePool = pool.promise();
  let sql = "SELECT twitchlogin, twitchid FROM tokenstore";
  const [rows,fields] = await promisePool.query(sql);
  if (rows.length < 1) {
    console.log("No users in database");
    res.sendStatus(404);
  } else {
    let channels = [];
    for (let i = 0; i < rows.length; i++) {
      let channel = {
        channelname:rows[i].twitchlogin,
        channelid:rows[i].twitchid
      }
      channels.push(channel);
    }
    res.render('channels.ejs', {
      channels: channels
    });
  }
});


function getSecret() {
    return process.env.SUBSCRIPTION_SECRET;
}
  
// Build the message used to get the HMAC.
function getHmacMessage(request) {
    return (request.headers[TWITCH_MESSAGE_ID] + 
        request.headers[TWITCH_MESSAGE_TIMESTAMP] + 
        request.body);
}
  
// Get the HMAC.
function getHmac(secret, message) {
    return crypto.createHmac('sha256', secret)
    .update(message)
    .digest('hex');
}
  
// Verify whether our hash matches the hash that Twitch passed in the header.
function verifyMessage(hmac, verifySignature) {
    return crypto.timingSafeEqual(Buffer.from(hmac), Buffer.from(verifySignature));
}
  
function generateRandomString(length) {
  var text = '';
  var possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

  for (var i = 0; i < length; i++) {
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return text;
};




var httpServer = http.createServer(app);
if (!devMode) {
  
  const options = {
    key: fs.readFileSync('/etc/letsencrypt/live/ananasmusicbot.de/privkey.pem'),
    cert: fs.readFileSync('/etc/letsencrypt/live/ananasmusicbot.de/fullchain.pem'),
  };
  
  var httpsServer = https.createServer(options, app);
  httpsServer.listen(443);
}
httpServer.listen(81);
keepSubscriptionsAlive();


console.log("App started");

async function refreshConnection() {
  const sql = "SELECT * FROM blacklisted_users";
  pool.getConnection(function(conn_err, conn) {
    if (conn_err) {
      console.log(console_err);
      return false;
    }
    conn.query(sql, (query_err, query_result) => {
      if (query_err) {
        console.log("Query Error while trying to whitelist userid " + user);
        console.log(query_err);
      } else {
      chatClient.say("ananasmusicbot", "/me Refreshed DB connection");
      }
      pool.releaseConnection(conn);
    });
  });
}

//Restart every 2 hours
const shutdownJob = schedule.scheduleJob('0 1-23/2 * * * ', function(){
  console.log("Refreshing Database ConnectioN");
  refreshConnection();
});

const refreshJob = schedule.scheduleJob('*/15 * * * * ', function(){
  console.log("Refreshing EventSubs at " + new Date().toISOString());
  keepSubscriptionsAlive();
});

//End Servercode
chatClient.onMessage(async (channel, user, text, msg) => {
  const userInfo = msg.userInfo;
  const channel_id = msg.channelId;
  const isMod = userInfo.isMod;
  const isBroadcaster = userInfo.isBroadcaster;
  const isModUp = isBroadcaster || isMod || (channel.toUpperCase() === "ANANASXPRESS_" && user.toUpperCase() === "STREAMELEMENTS");
  text = text.trim();



  if(user === nick || !text.startsWith('!')) return;

  const args = text.split(' ');
  let command = (args[0]);

  let currTime = Math.floor(Date.now() / 1000);
  if (requestTimeoutMap.has(channel)) {
    let commandMap = requestTimeoutMap.get(channel);
    if (commandMap.has(command)) {
      let storedUnixTime = commandMap.get(command);
      let differenceInSeconds = currTime - storedUnixTime;

      if (differenceInSeconds <= 2) {
        console.log("Channel in cooldown");
        return;
      }
    }
  }

  const liveOnly = await getLiveOnly(null, channel_id);
  console.log("Liveonly? " + liveOnly);
  let isChannelLive = true;
  if (liveOnly) {
    isChannelLive = true //await isLive(channel)
  }
  console.log("Is Live? " + isChannelLive);
  console.log("Is Broadcaster? " + isBroadcaster);
  //If Broadcaster requested, or it's not live only, or the channel is live anyways: Allow spotify action;
  let allowSpotifyActions = isBroadcaster || !liveOnly || isChannelLive;

  console.log("Allow Spotify Actions? " + allowSpotifyActions);

  console.log("Handling command " + command + " in channel " + channel);

  let commandMap = new Map();
  commandMap.set(command, currTime);
  requestTimeoutMap.set(channel, commandMap);  
  switch (command) {
    case "!restart": {
      if (user === "ananasxpress_") {
        process.exit(1);
      }
    }
    case "!join":
      {
        if (channel === "ananasmusicbot") {
          chatClient.join(user);
          chatClient.say("ananasmusicbot", "/me Will join " + user);
          chatClient.say(user, "/me Spawned");
        }
        break;
      }
    case "!srcommands": {
      chatClient.say(channel, "/me Musicbot Commands: https://ananasmusicbot.de/commands")
      break;
    }
    case "!resume": {
      if (isModUp && allowSpotifyActions) {
        executeSpotifyAction(channel, "resume");
        break;
      } else if (!allowSpotifyActions && isModUp) {
        chatClient.say(channel, "/me The current settings of this channel don't allow spotify commands when channel is offline");
      }
    } case "!bluser": {
      if (isModUp) {
        if (args.length < 2) {
          chatClient.say(channel, "/me Not enough arguments provided");
        } else {
          blacklistUser(channel_id, args[1], channel);
        }
      }
      break;
    } case "!blusers": {
      if (isModUp) {
        blacklistedUsers(channel_id, channel);
      }
      break;
    } case "!wluser": {
      if (isModUp) {
        if (args.length < 2) {
          chatClient.say(channel, "/me Not enough arguments provided");
        } else {
          whitelistUser(channel_id, args[1], channel);
        }
      }
      break;
    } case "!bltrack": {
      if (isModUp) {
        if (args.length < 2) {
          chatClient.say(channel, "/me Not enough arguments provided");
        } else {
          blacklistTrack(channel_id, args[1], channel);
        }
      }
      break;
    } case "!wltrack": {
      if (isModUp) {
        if (args.length < 2) {
          chatClient.say(channel, "/me Not enough arguments provided");
        } else {
          whitelistTrack(channel_id, args[1], channel);
        }
      }
      break;
    } case "!bltracks": {
      if (isModUp) {
        blacklistedTracks(channel_id, channel);
      }
      break;
    } case "!blartists": {
      if (isModUp) {
        blacklistedArtists(channel_id, channel);
      }
      break;
    } case "!blartist": {
      if (isModUp) {
        if (args.length < 2) {
          chatClient.say(channel, "/me Not enough arguments provided");
        } else {
          blacklistArtist(channel_id, args[1], channel);
        }
      }
      break;
    } case "!wlartist": {
      if (isModUp) {
        if (args.length < 2) {
          chatClient.say(channel, "/me Not enough arguments provided");
        } else {
          whitelistArtist(channel_id, args[1], channel);
        }
      }
      break;
    }
     case "!mode": {
      if (isBroadcaster) {
        if (args.length < 2) {
          chatClient.say(channel, "/me Not enough arguments provided");
        } else {
          executeSpotifyAction(channel, channel_id, "mode", args);
        }
      }
      break;
    } case "!volume": {
      if (allowSpotifyActions) {
        if (args.length < 2) {
          executeSpotifyAction(channel, channel_id, "get_volume", args);
        } else {
            if (!isModUp) {
                break;
            }
            executeSpotifyAction(channel, channel_id, "volume", args);
        }  
      } else {
        chatClient.say(channel, "/me The current settings of this channel don't allow spotify commands when channel is offline");
      }
      break;
    }
    case "!playlist": {
      if (allowSpotifyActions) {
        executeSpotifyAction(channel, channel_id, "playlist", args);
      } else {
        chatClient.say(channel, "/me The current settings of this channel don't allow spotify commands when channel is offline");
      }
      break;
    }
    case "!q":
    case "!queue" : {
      if (allowSpotifyActions) {
        //Only one additional argument provided and that is a number between 1 and 10.
        let argIsNumberOneToTen = (args.length == 2 && isNumberFromOneToTen(args[1])) ? true : false;

        //More than one argument provided or one additional argument that is not a number between 1 and 10.
        let textArgProvided = (args.length > 2 || (args.length == 2 && !isNumberFromOneToTen(args[1]))) ? true : false;
        if (argIsNumberOneToTen) {
          executeSpotifyAction(channel, channel_id, "queue", args);
        } else if (textArgProvided) {
          if (isModUp) {
            executeSpotifyAction(channel, channel_id, "add", args);
          } else {
            executeSpotifyAction(channel, channel_id, "queue", null);
          }
        } else {
          executeSpotifyAction(channel, channel_id, "queue", null);
        }
      } else {
        chatClient.say(channel, "/me The current settings of this channel don't allow spotify commands when channel is offline");
      }
      break;
    }
    case "!rq":
    case "!rqueue" : {
      if (allowSpotifyActions) {
        //Only one additional argument provided and that is a number between 1 and 10.
        let argIsNumberOneToTen = (args.length == 2 && isNumberFromOneToTen(args[1])) ? true : false;
        //More than one argument provided or one additional argument that is not a number between 1 and 10.
        let textArgProvided = (args.length > 2 || (args.length == 2 && !isNumberFromOneToTen(args[1]))) ? true : false;
        if (argIsNumberOneToTen) {
          executeSpotifyAction(channel, channel_id, "reversequeue", args);
        } else {
          executeSpotifyAction(channel, channel_id, "reversequeue", null);
        }
      } else {
        chatClient.say(channel, "/me The current settings of this channel don't allow spotify commands when channel is offline");
      }
      break;
    }
    case "!song":
      if (allowSpotifyActions) {
        executeSpotifyAction(channel, channel_id, "song", null);
      } else {
        chatClient.say(channel, "/me The current settings of this channel don't allow spotify commands when channel is offline");
      }
      break;
    case "!songlink":
      if (allowSpotifyActions) {
        executeSpotifyAction(channel, channel_id, "songlink", null);
      } else {
        chatClient.say(channel, "/me The current settings of this channel don't allow spotify commands when channel is offline");
      }
      break;
    case "!maxlength":
      //Only one additional argument provided and that is a number between 1 and 10.
      if (isModUp) {
        if (args.length > 1) {
          try {
            console.log(args);
            let intNum = parseInt(args[1]);
            setMaxSongLength(channel, channel_id, intNum);
          } catch (error) {
            console.log(error);
            chatClient.say(channel, "/me Invalid argument provided. Needs amount in seconds");
          }
        } else {
          getMaxSongLength(channel, channel_id);
        }
      } else {
        getMaxSongLength(channel, channel_id);
      }
      break;
    case "!liveonly":
      //Only one additional argument provided and that is either "on" or "off"
      if (isBroadcaster) {
        if (args.length > 1) {
          try {
            let param = args[1].trim();
            if (param.toLowerCase() === "on") {
              turnOnLiveOnly(channel, channel_id);  
            } else if (param.toLowerCase() === "off") {
              turnOffLiveOnly(channel, channel_id);
            }
          } catch (error) {
            console.log(error);
            chatClient.say(channel, "/me Invalid argument provided. Needs 'on' or 'off'");
          }
        } else {
          getLiveOnly(channel, channel_id);
        }
      } else {
        getLiveOnly(channel, channel_id);
      }
      break;
    case "!play":
      if (allowSpotifyActions) {
        if (isModUp && args.length >= 2) {
          executeSpotifyAction(channel, channel_id, "play", args); 
        } else if (isModUp) {
          executeSpotifyAction(channel, channel_id, "resume", null); 
        } 
      } else {
        chatClient.say(channel, "/me The current settings of this channel don't allow spotify commands when channel is offline");
      }
      break;
    case "!pause":
      if (allowSpotifyActions) {  
        if (isModUp) {
          executeSpotifyAction(channel, channel_id, "pause", null);  
        }
      } else {
        chatClient.say(channel, "/me The current settings of this channel don't allow spotify commands when channel is offline");
      }
      break;
    case "!next":
    case "!skip":
      if (allowSpotifyActions) {
        if (isModUp) {
            executeSpotifyAction(channel, channel_id, "skip", null);
        }
      } else {
        chatClient.say(channel, "/me The current settings of this channel don't allow spotify commands when channel is offline");
      }
      break;
    case "!previous":
    case "!skipback":
      if (allowSpotifyActions) {
        if (isModUp) {
            executeSpotifyAction(channel, channel_id, "skipback", null);
        }
      } else {
        chatClient.say(channel, "/me The current settings of this channel don't allow spotify commands when channel is offline");
      }
      break;
    case "!ircbot": {
      chatClient.say(channel, process.env.VERSION + " Bot is here!");
      break;
    }
    case "!sourcecode": {
      chatClient.say(channel, "/me Interested in the code? https://github.com/AnanasPizza/AnanasMusicBot");
      break;
    }
  }
});


//Function for channelpoint subscription
async function sendSongToQueue(spotifyAuthToken, userInput, broadcasterName, requestedBy, channelId) {
  const regex = /track\/([^\?]+)/; // Your regex pattern
    
  let requestUri = "spotify:track:";
  const axiosInstance = axios.create({
    headers: {
      Authorization: 'Bearer '+spotifyAuthToken,
    },
  });
  if (userInput.startsWith('https://')) {
    if (!userInput.toUpperCase().includes('SPOTIFY')) {
      chatClient.say(broadcasterName, "/me @"+ requestedBy+", Only Spotify links please");
      return;
    }
    const match = regex.exec(userInput);
    
    if (match) {
      const trackId = match[1];   // The value captured in the first capture group
      let songBlacklisted = await isTrackBlacklisted(channelId, trackId);
      if (songBlacklisted) {
        chatClient.say(broadcasterName, "/me @"+ requestedBy+", This song is blacklisted here");
      } else {
        const infoRequest = {
          method: 'GET',
          url: 'https://api.spotify.com/v1/tracks/' + trackId
        }
        axiosInstance(infoRequest)
          .then(async infoResponse => {
            const songname = infoResponse.data.name;
            const artists = infoResponse.data.artists;
            const duration_ms = infoResponse.data.duration_ms;
            const maxSongLength = await getMaxSongLength(null, channelId);
            if (maxSongLength !== null && (maxSongLength * 1000) < duration_ms) {
              chatClient.say(broadcasterName, "/me Song is too long. Max. song length is " + maxSongLength + " seconds");
              return;
            }
            let artistBlacklisted = await isArtistBlacklisted(channelId, artists);
            if (artistBlacklisted) {
              let link = blacklistedArtistsLink(channelId, broadcasterName);
              chatClient.say(broadcasterName, "/me At least one artist of this song is blacklisted here. Check all blacklisted artists here: " + link);
              return;
            }
            const artist = infoResponse.data.artists[0].name;
            requestUri += trackId;
            const request = {
              method: 'POST',
              url: 'https://api.spotify.com/v1/me/player/queue',
              params: {
                uri: requestUri,
              }
            };
            axiosInstance(request)
              .then(response => {
                chatClient.say(broadcasterName, filter.clean("/me Added '" + songname + "' by '" + artist + "' to Spotify Queue, @" + requestedBy));
                  return;
                })
                .catch((queueError) => {
                  //if (error instanceof AxiosError) {
                  console.log(queueError);
                  return;
                });
            })
            .catch(infoerror => {
              console.log(infoerror);
              return;
            });
        }
      } else {
        chatClient.say(broadcasterName, "/me Could not extract trackid from url @"+requestedBy);
        return;
      }
  } else {
    console.log("Searching for song: " + userInput);
    const searchRequest = {
      method: 'GET',
      url: 'https://api.spotify.com/v1/search',
      params: {
        q: userInput,
        type: 'track',
        limit: 10
      }
    }
    axiosInstance(searchRequest)
      .then(async searchResponse => {
      try {
        if (searchResponse.status === 200) {
          const duration_ms = searchResponse.data.tracks.items[0].duration_ms;
          const maxSongLength = await getMaxSongLength(null, channelId);
          if (maxSongLength !== null && (maxSongLength * 1000) < duration_ms) {
            chatClient.say(broadcasterName, "/me Song is too long. Max. song length is " + maxSongLength + " seconds");
            return;
          }
          let trackId = searchResponse.data.tracks.items[0].id;
          let artists = searchResponse.data.tracks.items[0].artists;
          let songBlacklisted = await isTrackBlacklisted(channelId, trackId);
          let artistBlacklisted = await isArtistBlacklisted(channelId, artists);
          if (songBlacklisted) {
            chatClient.say(broadcasterName, "/me @"+ requestedBy+", This song is blacklisted here");
            return;
          } else if (artistBlacklisted) {
            let link = blacklistedArtistsLink(channelId, broadcasterName);
            chatClient.say(broadcasterName, "/me At least one artist of this song is blacklisted here. Check all blacklisted artists here: " + link);
            return;
          } else {
            let name = searchResponse.data.tracks.items[0].name;
            let artist = searchResponse.data.tracks.items[0].artists[0].name;
            requestUri += trackId;
            const queueRequest = {
              method: 'POST',
              url: 'https://api.spotify.com/v1/me/player/queue',
              params: {
                uri: requestUri,
              },
            };
            axiosInstance(queueRequest)
              .then(queueResponse => {
                chatClient.say(broadcasterName, filter.clean("/me Added '"+ name + "' by '" + artist + "' to Spotify Queue, @"+requestedBy));
                return;
              })
              .catch(queueError => {
                chatClient.say(broadcasterName, "/me Could not add song to queue");
                console.log("Error for userinput: " + userInput + " in channel " + broadcasterName);
                console.log(queueError);
                return;
              });
          }
        } else {
          chatClient.say(broadcasterName, "/me Could not find song");
          return;
        }
        
      } catch (err) {
        chatClient.say(broadcasterName, "/me Could not find song on Spotify");
        return;
      }
    })
    .catch(searchError => {
      chatClient.say(broadcasterName, "/me Could not find song on Spotify");
      console.log(searchError);
      return;
    });
  }
}


//Function for chatbot command
async function addSongToQueue(spotifyAuthToken, broadcasterUserName, channelid, userInput) {
  
  const regex = /track\/([^\?]+)/; // Your regex pattern
  
  let requestUri = "spotify:track:";
  const axiosInstance = axios.create({
    headers: {
      Authorization: 'Bearer ' + spotifyAuthToken,
    },
  });

  const isPlayingRquest = {
    method: 'GET',
    url: 'https://api.spotify.com/v1/me/player'
  }
  axiosInstance(isPlayingRquest)
      .then(async isPlayingResponse => {
        let hasActiveDevice = isPlayingResponse.data.device !== undefined && isPlayingResponse.data.device.is_active;
        let isPrivate = hasActiveDevice && isPlayingResponse.data.device.is_private_session;
        if(!hasActiveDevice) {
          chatClient.say(broadcasterUserName, "/me No active device.");
          //TODO: Queue internally if stream is live. 
          return;
        }
        if (isPrivate) {
          chatClient.say(broadcasterUserName, "/me Private Session");
          return;
        }
      
        if (userInput.startsWith('https://')) {
          if (!userInput.toUpperCase().includes('SPOTIFY')) {
            chatClient.say(broadcasterUserName, "/me Only Spotify links please");
            return;
          }
          const match = regex.exec(userInput);
          if (match) {
            const trackId = match[1];   // The value captured in the first capture group
            let songBlacklisted = await isTrackBlacklisted(channelid, trackId);
            if (songBlacklisted) {
             chatClient.say(broadcasterUserName, "/me This song is blacklisted here");
              return;
            }
      
            const infoRequest = {
              method: 'GET',
              url: 'https://api.spotify.com/v1/tracks/' + trackId
            }
            axiosInstance(infoRequest)
              .then(async infoResponse => {
                const duration_ms = infoResponse.data.duration_ms;
                const maxSongLength = await getMaxSongLength(null, channelid);
                if (maxSongLength !== null && (maxSongLength * 1000) < duration_ms) {
                  chatClient.say(broadcasterUserName, "/me Song is too long. Max. song length is " + maxSongLength + " seconds");
                  return;
                }
                const songname = infoResponse.data.name;
                const artist = infoResponse.data.artists[0].name;
                let artists = infoResponse.data.artists;
                let artistBlacklisted = await isArtistBlacklisted(channelid, artists);
                if (artistBlacklisted) {
                  let link = blacklistedArtistsLink(channelid, broadcasterUserName);
                  chatClient.say(broadcasterUserName, "/me At least one artist of this song is blacklisted here. Check all blacklisted artists here: " + link);
                  return;
                }
                requestUri += trackId;
                const request = {
                  method: 'POST',
                  url: 'https://api.spotify.com/v1/me/player/queue',
                  params: {
                    uri: requestUri,
                  }
                };
                axiosInstance(request)
                  .then(response => {
                   chatClient.say(broadcasterUserName, filter.clean("/me Added '" + songname + "' by '" + artist + "' to Queue"));
                  })
                  .catch((queueError) => {
                    console.log(queueError);
                  });
              })
              .catch(infoerror => {
                console.log(infoerror);
              });
          } else {
           chatClient.say(broadcasterUserName, "/me Could not extract trackid from url");
          }
        } else {
          const searchRequest = {
            method: 'GET',
            url: 'https://api.spotify.com/v1/search',
            params: {
              q: userInput,
              type: 'track',
              limit: 10
            }
          }
          axiosInstance(searchRequest)
           .then(async searchResponse => {
            try {
              if (searchResponse.status === 200) {
                const duration_ms = searchResponse.data.tracks.items[0].duration_ms;
                const maxSongLength = await getMaxSongLength(null, channelid);
                if (maxSongLength !== null && (maxSongLength * 1000) < duration_ms) {
                  chatClient.say(broadcasterUserName, "/me Song is too long. Max. song length is " + maxSongLength + " seconds");
                  return;
                }
                let trackId = searchResponse.data.tracks.items[0].id;
      
                let songBlacklisted = await isTrackBlacklisted(channelid, trackId);
                if (songBlacklisted) {
                 chatClient.say(broadcasterUserName, "/me This song is blacklisted here");
                  return;
                }
                let artists = searchResponse.data.tracks.items[0].artists;
                let artistBlacklisted = await isArtistBlacklisted(channelid, artists);
                if (artistBlacklisted) {
                  let link = blacklistedArtistsLink(channelid, broadcasterUserName);
                  chatClient.say(broadcasterUserName, "/me At least one artist of this song is blacklisted here. Check all blacklisted artists here: " + link);
                  return;
                }
      
                let name = searchResponse.data.tracks.items[0].name;
                let artistString = getArtistsString(searchResponse.data.tracks.items[0].artists)
                requestUri += trackId;
                const queueRequest = {
                  method: 'POST',
                  url: 'https://api.spotify.com/v1/me/player/queue',
                  params: {
                    uri: requestUri,
                  },
                };
                axiosInstance(queueRequest)
                  .then(queueResponse => {
                   chatClient.say(broadcasterUserName, "/me Added '"+ name + "' by " + artistString + " to Queue");
                  })
                  .catch(queueError => {
                    console.log(queueError);
                  });
              } else {
               chatClient.say(broadcasterUserName, "/me Could not find song");
              }
              
            } catch (err) {
              console.log(err);
             chatClient.say(broadcasterUserName, "/me Could not find song");
            }
          })
          .catch(searchError => {
            console.log(searchError);
          });
        }
      })
      .catch(isPlayingError => {
        console.log(isPlayingError);
        chatClient.say(broadcasterUserName, "/me No device is playing right now");
      });;
}

function getQueue(spotifyAuthToken, broadcasterUserName, queuesize) {
    const axiosInstance = axios.create({
      headers: {
        Authorization: 'Bearer '+spotifyAuthToken,
      },
    });

    const isPlayingRquest = {
      method: 'GET',
      url: 'https://api.spotify.com/v1/me/player'
    }
    axiosInstance(isPlayingRquest)
      .then(isPlayingResponse => {
        let hasActiveDevice = isPlayingResponse.data.device !== undefined && isPlayingResponse.data.device.is_active;
        let isPrivate = hasActiveDevice && isPlayingResponse.data.device.is_private_session;
        if(!hasActiveDevice) {
          chatClient.say(broadcasterUserName, "/me No active device");
          return;
        }
        if (isPrivate) {
          chatClient.say(broadcasterUserName, "/me Private Session");
          return;
        }

        const queueRequest = {
          method: 'GET',
          url: 'https://api.spotify.com/v1/me/player/queue'
        }
        const limit = queuesize != null ? queuesize : 5;
        if (limit > 10) {
          limit = 10;
        }
        let i = 1;
        axiosInstance(queueRequest)
          .then(queueResponse => {
            let responseStr = limit > 1 ? "Next " + limit + " songs: " : "Next song: ";
            const queue = queueResponse.data.queue;
            
            queue.forEach((queueItem) => {
              if (i <= limit) {
                responseStr += "'" + queueItem.name + "'🍍";  
              }
              i++;
            });
            if (responseStr.endsWith(" songs: ")) {
             chatClient.say(broadcasterUserName, "/me Nothing in Queue right now");  
            } else {
             chatClient.say(broadcasterUserName, "/me " + responseStr.slice(0,-2));
            }
          })
          .catch(error => {
            chatClient.say(broadcasterUserName, "/me Could not get songqueue");
          });
    });
  }

  function getReverseQueue(spotifyAuthToken, broadcasterUserName, queuesize) {
    const axiosInstance = axios.create({
      headers: {
        Authorization: 'Bearer '+spotifyAuthToken,
      },
    });

    const isPlayingRquest = {
      method: 'GET',
      url: 'https://api.spotify.com/v1/me/player'
    }
    axiosInstance(isPlayingRquest)
      .then(isPlayingResponse => {
        let hasActiveDevice = isPlayingResponse.data.device !== undefined && isPlayingResponse.data.device.is_active;
        let isPrivate = hasActiveDevice && isPlayingResponse.data.device.is_private_session;
        if(!hasActiveDevice) {
          chatClient.say(broadcasterUserName, "/me No active device");
          return;
        }
        if (isPrivate) {
          chatClient.say(broadcasterUserName, "/me Private Session");
          return;
        }

        let currTime = Date.now();

        const limit = queuesize != null ? queuesize : 5;
        if (limit > 10) {
          limit = 10;
        }
        let i = 1;

        const queueRequest = {
          method: 'GET',
          url: 'https://api.spotify.com/v1/me/player/recently-played?before=' + currTime + '&limit=' + limit
        }
        
        axiosInstance(queueRequest)
          .then(queueResponse => {
            let responseStr = limit > 1 ? "Last " + limit + " songs: " : "Last song: ";
            const queue = queueResponse.data.items;
            
            queue.forEach((queueItem) => {
              let track = queueItem.track;
              if (i <= limit) {
                responseStr += "'" + track.name + "'🍍";  
              }
              i++;
            });
            if (responseStr.endsWith(" songs: ")) {
             chatClient.say(broadcasterUserName, "/me Nothing played recently");  
            } else {
             chatClient.say(broadcasterUserName, "/me " + responseStr.slice(0,-2));
            }
          })
          .catch(error => {
            console.log(error);
            chatClient.say(broadcasterUserName, "/me Could not get songqueue");
          });
    });
  }

  function getVolume(spotifyAuthToken, broadcasterUserName) {
    const axiosInstance = axios.create({
      headers: {
        Authorization: 'Bearer ' + spotifyAuthToken,
      },
    });
  
    const isPlayingRquest = {
      method: 'GET',
      url: 'https://api.spotify.com/v1/me/player'
    }

    axiosInstance(isPlayingRquest)
    .then(isPlayingResponse => {
      let hasActiveDevice = isPlayingResponse.data.device !== undefined && isPlayingResponse.data.device.is_active;
      let isPrivate = hasActiveDevice && isPlayingResponse.data.device.is_private_session;
      if(!hasActiveDevice) {
        chatClient.say(broadcasterUserName, "/me No active device");
        return;
      }
      if (isPrivate) {
        chatClient.say(broadcasterUserName, "/me Private Session");
        return;
      }
      chatClient.say(broadcasterUserName, "/me Current Volume: " + isPlayingResponse.data.device.volume_percent + "%");
    });
  }

  function setVolume(spotifyAuthToken, broadcasterUserName, volume) {
      const axiosInstance = axios.create({
        headers: {
          Authorization: 'Bearer '+spotifyAuthToken,
        },
      });
    
      const volumeRequest = {
        method: 'PUT',
        url: 'https://api.spotify.com/v1/me/player/volume',
        params: {
          volume_percent: volume,
        }
      }
      axiosInstance(volumeRequest)
        .then(volumeResponse => {
          let responseStr = "/me Set volume to " + volume;
         chatClient.say(broadcasterUserName, responseStr);
        })
        .catch(error => {
          console.log(error);
         chatClient.say(broadcasterUserName, "/me Could not set music volume" + error);
        });
  }

  function changeVolume(spotifyAuthToken, broadcasterUserName, volume, operation) {

    const axiosInstance = axios.create({
      headers: {
        Authorization: 'Bearer ' + spotifyAuthToken,
      },
    });

    const isPlayingRquest = {
      method: 'GET',
      url: 'https://api.spotify.com/v1/me/player'
    }

    axiosInstance(isPlayingRquest)
    .then(isPlayingResponse => {
      let hasActiveDevice = isPlayingResponse.data.device !== undefined && isPlayingResponse.data.device.is_active;
      let isPrivate = hasActiveDevice && isPlayingResponse.data.device.is_private_session;
      if(!hasActiveDevice) {
        chatClient.say(broadcasterUserName, "/me No active device");
        return;
      }
      if (isPrivate) {
        chatClient.say(broadcasterUserName, "/me Private Session");
        return;
      }
      let curr_volume = isPlayingResponse.data.device.volume_percent;
      console.log(curr_volume);
      if (operation === "+") {
        console.log("Adding " + volume + "%");
        curr_volume = curr_volume + volume;
      } else if (operation === "-") {
        console.log("Subtracting " + volume + "%");
        curr_volume = curr_volume - volume;
      }

      if (curr_volume > 100) {
        curr_volume = 100;
      } else if (curr_volume < 0) {
        curr_volume = 0;
      }
      const volumeRequest = {
        method: 'PUT',
        url: 'https://api.spotify.com/v1/me/player/volume',
        params: {
          volume_percent: curr_volume,
        }
      }
      axiosInstance(volumeRequest)
        .then(volumeResponse => {
          let responseStr = "/me Set volume to " + curr_volume;
          chatClient.say(broadcasterUserName, responseStr);
        })
        .catch(error => {
          console.log(error);
         chatClient.say(broadcasterUserName, "/me Could not set music volume" + error);
        });
    });
}


function resume(spotifyAuthToken, broadcasterUserName) {
  const axiosInstance = axios.create({
      headers: {
          Authorization: 'Bearer '+spotifyAuthToken,
      },
      });
  
      const isPlayingRquest = {
        method: 'GET',
        url: 'https://api.spotify.com/v1/me/player'
      }
      axiosInstance(isPlayingRquest)
      .then(isPlayingResponse => {
        let isPlaying = isPlayingResponse.data.is_playing;
        let isPrivate = isPlayingResponse.data.is_private_session;
        if (isPrivate) {
         chatClient.say(broadcasterUserName, "/me Private Session");
          return;
        }
        if (!isPlaying) {
          const playRequest = {
            method: 'PUT',
            url: 'https://api.spotify.com/v1/me/player/play'
          }
          axiosInstance(playRequest)
          .then(playResponse => {
            let responseStr = "Resumed Playing";
           chatClient.say(broadcasterUserName, responseStr);
          }).catch(error => {
            console.log(error);
          });
        } else {
         chatClient.say(broadcasterUserName, "/me Already playing");
        }
      })
      .catch(error => {
        console.log(error);
      });     
}

function pause(spotifyAuthToken, broadcasterUserName) {
  const axiosInstance = axios.create({
      headers: {
          Authorization: 'Bearer '+spotifyAuthToken,
      },
      });
      const isPlayingRquest = {
        method: 'GET',
        url: 'https://api.spotify.com/v1/me/player'
      }
      axiosInstance(isPlayingRquest)
      .then(isPlayingResponse => {
        let hasActiveDevice = isPlayingResponse.data.device !== undefined && isPlayingResponse.data.device.is_active;
        let isPrivate = hasActiveDevice && isPlayingResponse.data.device.is_private_session;
        if(!hasActiveDevice) {
          chatClient.say(broadcasterUserName, "/me No active device");
          return;
        }
        if (isPrivate) {
          chatClient.say(broadcasterUserName, "/me Private Session");
          return;
        }
        if (isPlaying) {
          const pauseRequest = {
          method: 'PUT',
          url: 'https://api.spotify.com/v1/me/player/pause'
          }
          axiosInstance(pauseRequest)
          .then(pauseResponse => {
              let responseStr = "/me Paused";
             chatClient.say(broadcasterUserName, responseStr);
          })
          .catch(error => {
            console.log(error);  
          });
        } else {
         chatClient.say(broadcasterUserName, "/me Nothing is playing right now");
        }
      })
      .catch(error => {
        console.log(error);
      }); 
  }

async function play(spotifyAuthToken, broadcasterUserName, channelid, userInput) {
    const regex = /track\/([^\?]+)/; // Your regex pattern
  
  let requestUri = "spotify:track:";
  const axiosInstance = axios.create({
    headers: {
      Authorization: 'Bearer ' + spotifyAuthToken,
    },
  });

  const isPlayingRquest = {
    method: 'GET',
    url: 'https://api.spotify.com/v1/me/player'
  }
  axiosInstance(isPlayingRquest)
  .then(isPlayingResponse => {
    let hasActiveDevice = isPlayingResponse.data.device !== undefined && isPlayingResponse.data.device.is_active;
    let isPrivate = hasActiveDevice && isPlayingResponse.data.device.is_private_session;
    if(!hasActiveDevice) {
      chatClient.say(broadcasterUserName, "/me No active device");
      return;
    }
    if (isPrivate) {
      chatClient.say(broadcasterUserName, "/me Private Session");
      return;
    }
  });

  if (userInput.startsWith('https://')) {
    const match = regex.exec(userInput);
    if (match) {
      const trackId = match[1];   // The value captured in the first capture group
      let songBlacklisted = await isTrackBlacklisted(channelid, trackId);
      if (songBlacklisted) {
       chatClient.say(broadcasterUserName, "/me This song is blacklisted here");
        return;
      } else {
        const infoRequest = {
          method: 'GET',
          url: 'https://api.spotify.com/v1/tracks/' + trackId
        }
        axiosInstance(infoRequest)
          .then(async infoResponse => {
            const duration_ms = infoResponse.data.duration_ms;
            const maxSongLength = await getMaxSongLength(null, channelid);
            if (maxSongLength !== null && (maxSongLength * 1000) < duration_ms) {
              chatClient.say(broadcasterUserName, "/me Song is too long. Max. song length is " + maxSongLength + " seconds");
              return;
            }
            const songname = infoResponse.data.name;
            let artists = infoResponse.data.artists;
            let artistBlacklisted = await isArtistBlacklisted(channelid, artists);
            if (artistBlacklisted) {
              let link = blacklistedArtistsLink(channelid, broadcasterUserName);
              chatClient.say(broadcasterUserName, "/me At least one artist of this song is blacklisted here. Check all blacklisted artists here: " + link);
              return;
            }
            const artist = infoResponse.data.artists[0].name;
            requestUri += trackId;
            const innerRequestBody = {
              uris : [requestUri]
            }
            axiosInstance
              .put('https://api.spotify.com/v1/me/player/play', innerRequestBody)
              .then(response => {
               chatClient.say(broadcasterUserName, "/me Now playing '" + songname + "' by '" + artist + "'");
              })
              .catch((queueError) => {
                console.log(queueError);
              });
          })
          .catch(infoerror => {
            console.log(infoerror);
          });
      }
    } else {
     chatClient.say(broadcasterUserName, "/me Could not extract trackid from url");
    }
  } else {
    const searchRequest = {
      method: 'GET',
      url: 'https://api.spotify.com/v1/search',
      params: {
        q: userInput,
        type: 'track',
        limit: 10
      }
    }
    axiosInstance(searchRequest)
     .then(async searchResponse => {
      try {
        if (searchResponse.status == 200) {
          const duration_ms = searchResponse.data.tracks.items[0].duration_ms;
          const maxSongLength = await getMaxSongLength(null, channelid);
          if (maxSongLength !== null && (maxSongLength * 1000) < duration_ms) {
            chatClient.say(broadcasterUserName, "/me Song is too long. Max. song length is " + maxSongLength + " seconds");
            return;
          }

          let trackId = searchResponse.data.tracks.items[0].id;
          let songBlacklisted = await isTrackBlacklisted(channelid, trackId);
          let artists = searchResponse.data.tracks.items[0].artists;
          let artistBlacklisted = await isArtistBlacklisted(channelid, artists);
          if (songBlacklisted) {
            chatClient.say(broadcasterUserName, "/me This song is blacklisted here");
            return;
          } else if (artistBlacklisted) {
            let link = blacklistedArtistsLink(channelid, broadcasterUserName);
            chatClient.say(broadcasterUserName, "/me At least one artist of this song is blacklisted here. Check all blacklisted artists here: " + link);
            return;
          } else {
            let name = searchResponse.data.tracks.items[0].name;
            let artistString = getArtistsString(searchResponse.data.tracks.items[0]);
            requestUri += trackId;
            const innerRequestBody = {
              uris : [requestUri]
            }
            axiosInstance
              .put('https://api.spotify.com/v1/me/player/play', innerRequestBody)
              .then(playResponse => {
               chatClient.say(broadcasterUserName, filter.clean("/me Now playing '"+ name + "' by " + artistString));
              })
              .catch(playError => {
                console.log(playError);
              });
          }          
        } else {
         chatClient.say(broadcasterUserName, "/me Could not find song");
        }
        
      } catch (err) {
       chatClient.say(broadcasterUserName, "/me Could not find song");
      }
    })
    .catch(searchError => {
      console.log(searchError);
    });
  }
}

function whitelistUser(channel_id, user, channel) {
  //Make sure there is no SQL injection by using placeholders and input validation
  if (user.split(' ').length > 1) {
    chatClient.say(channel, "/me Invalid input");
  } else {
    let sql = "DELETE FROM blacklisted_users WHERE channel_id = ? AND blocked_user_name = ?";
    pool.getConnection(function(conn_err, conn) {
      if (conn_err) {
        console.log(console_err);
        return false;
      }
      conn.query(sql, [channel_id, user.toUpperCase()], (query_err, query_result) => {
        if (query_err) {
          console.log("Query Error while trying to whitelist userid " + user);
          console.log(query_err);
        } else {
        chatClient.say(channel, "/me User whitelisted");
        }
        pool.releaseConnection(conn);
      });
    });
  }
}

function blacklistUser(channel_id, user, channel) {
  //Make sure there is no SQL injection by using placeholders and input validation
  if (user.split(' ').length > 1) {
    chatClient.say(channel, "/me Invalid input");
  } else {
    let sql = "INSERT INTO blacklisted_users(channel_id, blocked_user_name) VALUES (?, ?)";
    pool.getConnection(function(conn_err, conn) {
      if (conn_err) {
        console.log(console_err);
        return false;
      }
      conn.query(sql, [channel_id, user.toUpperCase()], (query_err, query_result) => {
        if (query_err) {
          if (query_err.code === "ER_DUP_ENTRY") {
          chatClient.say(channel, "/me User already blacklisted");
          } else {
            console.log("Query Error while trying to blacklist userid " + user);
            console.log(query_err);
          }
        } else {
          console.log("Query result:");
        chatClient.say(channel, "/me User blacklisted");
        }
        pool.releaseConnection(conn);
      });
    });
  }
}

function whitelistTrack(channel_id, url, channel) {
  const regex = /track\/([^\?]+)/; // Your regex pattern
  const match = regex.exec(url);
  if (match) {
    const trackId = match[1];

    let sql = "DELETE FROM blacklisted_tracks WHERE channel_id = ? AND blocked_track_id = ?";
    pool.getConnection(function(conn_err, conn) {
      if (conn_err) {
        console.log(console_err);
        return false;
      }
      conn.query(sql, [channel_id, trackId], (query_err, query_result) => {
        if (query_err) {
          console.log("Query Error while trying to whitelist trackid " + trackId);
          console.log(query_err);
        } else {
         chatClient.say(channel, "/me Track whitelisted");
        }
        pool.releaseConnection(conn);
      });
    });
  } else {
    console.log("Could not extract trackid from url: " + url);
    return;
  }
}

async function blacklistTrack(channel_id, url, channel) {
  const regex = /track\/([^\?]+)/; // Your regex pattern
  const match = regex.exec(url);
  if (match) {
    const trackId = match[1];
    const spotifyAuthToken = await getSpotifyToken(channel);
    const infoRequest = {
      method: 'GET',
      url: 'https://api.spotify.com/v1/tracks/' + trackId
    }
    const axiosInstance = axios.create({
      headers: {
        Authorization: 'Bearer '+spotifyAuthToken,
      },
    });
    axiosInstance(infoRequest)
      .then(async infoResponse => {
        const songname = infoResponse.data.name;
        let artistVal = "";
        let artists = infoResponse.data.artists;
        for (let i = 0; i < artists.length; i++) {
          artistVal += artists[i].name;
          if (i < artists.length - 1) {
            artistVal += ", ";
          }
        }
        let sql = "INSERT INTO blacklisted_tracks(channel_id, blocked_track_id, songname, artist) VALUES (?, ?, ?, ?)";
        pool.getConnection(function(conn_err, conn) {
          if (conn_err) {
            console.log(console_err);
            return false;
          }
          conn.query(sql, [channel_id, trackId, songname, artistVal], (query_err, query_result) => {
            if (query_err) {
              if (query_err.code === "ER_DUP_ENTRY") {
                chatClient.say(channel, "/me Track already blacklisted");
              } else {
                console.log("Query Error while trying to blacklist trackid: " + trackId);
                console.log(query_err);
              }
            } else {
              chatClient.say(channel, "/me Track blacklisted");
            }
            pool.releaseConnection(conn);
          });
        });
      });
    } else {
    console.log("Could not extract trackid from url: " + url);
    return;
  }  
}


async function blacklistedUsers(channel_id, channel) {
  let link = "https://ananasmusicbot.de/channels/"+channel_id+"/blacklisted-users?channelname=" +channel;
  chatClient.say(channel, "/me Check all blacklisted users here: " + link);
}

function blacklistedArtists(channel_id, channel) {
  let link = "https://ananasmusicbot.de/channels/"+channel_id+"/blacklisted-artists?channelname=" +channel;
  chatClient.say(channel, "/me Check all blacklisted artists here: " + link);
}

function blacklistedArtistsLink(channel_id, channel) {
  return "https://ananasmusicbot.de/channels/"+channel_id+"/blacklisted-artists?channelname=" +channel;
}

function blacklistedTracks(channel_id, channel) {
  let link = "https://ananasmusicbot.de/channels/"+channel_id+"/blacklisted-tracks?channelname=" +channel;
  chatClient.say(channel, "/me Check all blacklisted tracks here: " + link);
}

function blacklistedTracksLink(channel_id, channel) {
  return "https://ananasmusicbot.de/channels/"+channel_id+"/blacklisted-tracks?channelname=" +channel;
}

function whitelistArtist(channel_id, url, channel) {
  const regex = /artist\/([^\?]+)/; // Your regex pattern
  const match = regex.exec(url);
  if (match) {
    const artistId = match[1];

    let sql = "DELETE FROM blacklisted_artists WHERE channel_id = ? AND blocked_artist_id = ?";
    pool.getConnection(function(conn_err, conn) {
      if (conn_err) {
        console.log(console_err);
        return false;
      }
      conn.query(sql, [channel_id, artistId], (query_err, query_result) => {
        if (query_err) {
          console.log("Query Error while trying to whitelist artistid " + artistId);
          console.log(query_err);
        } else {
         chatClient.say(channel, "/me Artist whitelisted");
        }
        pool.releaseConnection(conn);
      });
    });
  } else {
    console.log("Could not extract artistid from url: " + url);
    return;
  }
}

async function blacklistArtist(channel_id, url, channel) {
  console.log("In blacklist function");
  const regex = /artist\/([^\?]+)/; // Your regex pattern
  const match = regex.exec(url);
  if (match) {
    const artistId = match[1];
    const spotifyAuthToken = await getSpotifyToken(channel);
    const infoRequest = {
      method: 'GET',
      url: 'https://api.spotify.com/v1/artists/' + artistId
    }
    const axiosInstance = axios.create({
      headers: {
        Authorization: 'Bearer '+spotifyAuthToken,
      },
    });
    axiosInstance(infoRequest)
      .then(async infoResponse => {
        const artistname = infoResponse.data.name;
        let sql = "INSERT INTO blacklisted_artists(channel_id, blocked_artist_id, name) VALUES (?, ?, ?)";
        pool.getConnection(function(conn_err, conn) {
          if (conn_err) {
            console.log(console_err);
            return false;
          }
          conn.query(sql, [channel_id, artistId, artistname], (query_err, query_result) => {
            if (query_err) {
              if (query_err.code === "ER_DUP_ENTRY") {
              chatClient.say(channel, "/me Artist already blacklisted");
              } else {
                console.log("Query Error while trying to blacklist artist_id " + artistId);
                console.log(query_err);
              }
            } else {
              chatClient.say(channel, "/me Artist blacklisted");
            }
            pool.releaseConnection(conn);
          });
        });
      });
  } else {
    console.log("Could not extract artistid from url: " + url);
    return;
  }  
}



//Upcoming Feature
function mode(spotifyAuthToken, broadcasterUserName, userInput) {
  if (userInput.toUpperCase() === "BROADCASTERONLY") {
    //Update DB
  } else if (userInput.toUpperCase() === "STANDARD") {
    //Update DB
  }
}

function getSong(spotifyAuthToken, broadcasterUserName) {
    const axiosInstance = axios.create({
        headers: {
          Authorization: 'Bearer '+ spotifyAuthToken,
        },
    });
    
    console.log(spotifyAuthToken);
    const songRequest = {
      method: 'GET',
      url: 'https://api.spotify.com/v1/me/player'
    }
    axiosInstance(songRequest)
    .then(songResponse => {
      let hasActiveDevice = songResponse.data.device !== undefined && songResponse.data.device.is_active;
      let isPrivate = hasActiveDevice && songResponse.data.device.is_private_session;
      if(!hasActiveDevice) {
        chatClient.say(broadcasterUserName, "/me No active device");
        return;
      }
      if (isPrivate) {
        chatClient.say(broadcasterUserName, "/me Private Session");
        return;
      }
        let responseStr = "/me Currently playing: ";
        let isPlaying = songResponse.data.is_playing;
        let progress_ms = songResponse.data.progress_ms
        const songItem = songResponse.data.item;
        let duration = songItem.duration_ms;
        let currentTime = convertMillisecondsToMinuteSeconds(progress_ms);
        let totalTime = convertMillisecondsToMinuteSeconds(duration);

        let progressString = currentTime +" / " + totalTime;
        if (isPlaying && songItem != null) {
          let artistsString = getArtistsString(songItem.artists);
          responseStr += "'" + songItem.name + "' by " + artistsString;
          responseStr += " (" + progressString +")";
          if (songResponse.data.device !== undefined && songResponse.data.device.volume_percent !== undefined) {
            responseStr += " 🔊 " + songResponse.data.device.volume_percent + "%"
          }
        } else {
          responseStr = "/me No song is played currently";
        }
        chatClient.say(broadcasterUserName, responseStr);
    })
    .catch(error => {
        console.log("Error getting song: " + error);
        chatClient.say(broadcasterUserName, "Could not get currently playing song");
    });
  }

  function getArtistsString(artists) {
    if (artists.length === 1) {
      return "'" +artists[0].name + "'";
    } else {
      let result = "";
      for (let i = 0; i < artists.length; i++) {
        result += artists[i].name + ", ";
      }
      result = result.slice(0,-2);
      return result;
    }
  }

  function getSonglink(spotifyAuthToken, broadcasterUserName) {
    const axiosInstance = axios.create({
        headers: {
          Authorization: 'Bearer '+spotifyAuthToken,
        },
    });
    
    const songRequest = {
      method: 'GET',
      url: 'https://api.spotify.com/v1/me/player'
    }
    axiosInstance(songRequest)
    .then(songResponse => {
      let hasActiveDevice = songResponse.data.device !== undefined && songResponse.data.device.is_active;
      let isPrivate = hasActiveDevice && songResponse.data.device.is_private_session;
      if(!hasActiveDevice) {
        chatClient.say(broadcasterUserName, "/me No active device");
        return;
      }
      if (isPrivate) {
        chatClient.say(broadcasterUserName, "/me Private Session");
        return;
      }
        let responseStr = "/me Currently playing: ";
        let isPlaying = songResponse.data.is_playing;
        let progress_ms = songResponse.data.progress_ms
        const songItem = songResponse.data.item;
        let duration = songItem.duration_ms;
        let currentTime = convertMillisecondsToMinuteSeconds(progress_ms);
        let totalTime = convertMillisecondsToMinuteSeconds(duration);

        let progressString = currentTime +" / " + totalTime;
        if (isPlaying && songItem != null) {
          responseStr += "'" + songItem.name + "' by " + "'" +songItem.artists[0].name + "'";
          responseStr += " (" + progressString +")";
          if (songResponse.data.device !== undefined && songResponse.data.device.volume_percent !== undefined) {
            responseStr += " 🔊 " + songResponse.data.device.volume_percent + "%"
          }
          responseStr += " " + songItem.external_urls.spotify;
        } else {
          responseStr = "/me No song is played currently";
        }
        chatClient.say(broadcasterUserName, filter.clean(responseStr));
    })
    .catch(error => {
        console.log("Error getting song: " + error);
       chatClient.say(broadcasterUserName, "Could not get currently playing song");
    });
  }

  function getPlaylist(spotifyAuthToken, broadcasterUserName) {
    const axiosInstance = axios.create({
        headers: {
          Authorization: 'Bearer '+spotifyAuthToken,
        },
    });
    
    const contextRequest = {
      method: 'GET',
      url: 'https://api.spotify.com/v1/me/player'
    }
    axiosInstance(contextRequest)
    .then(contextResponse => {
        let hasActiveDevice = contextResponse.data.device !== undefined && contextResponse.data.device.is_active;
        let isPrivate = hasActiveDevice && contextResponse.data.device.is_private_session;
        if(!hasActiveDevice) {
          chatClient.say(broadcasterUserName, "/me No active device");
          return;
        }
        if (isPrivate) {
          chatClient.say(broadcasterUserName, "/me Private Session");
          return;
        }
        let context = contextResponse.data.context;
        if (context !== undefined && context !== null) {
          let type = context.type;
          let response = "Currently listening ";
          if (type === "playlist") {
            response += "to this playlist: " + context.external_urls.spotify;
          } else if (type === "album") {
            response += "to this album: " + context.external_urls.spotify;
          } else if (type === "artist") {
            response += "to this artist: " + context.external_urls.spotify;
          } else {
            chatClient.say(broadcasterUserName, "/me No playlist active right now");
            return;
          }
          chatClient.say(broadcasterUserName, response);
        }
    })
    .catch(error => {
        console.log("Error getting playlist: " + error);
       chatClient.say(broadcasterUserName, "/me Could not get currently active playlist. Sorry!");
    });
  }

  async function isUserBlacklisted(channel_id, username) {
    const promisePool = pool.promise();
    let sql = "SELECT * FROM blacklisted_users WHERE channel_id = ? AND blocked_user_name = ?";
    const [rows,fields] = await promisePool.query(sql, [channel_id, username.toUpperCase()]);
    return rows.length >= 1;
  }
  
  async function isTrackBlacklisted(channel_id, track_id) {
    const promisePool = pool.promise();
    let sql = "SELECT * FROM blacklisted_tracks WHERE channel_id = ? AND blocked_track_id = ?";
    const [rows,fields] = await promisePool.query(sql, [channel_id, track_id]);
    return rows.length >= 1;
  }
  
  
  async function isArtistBlacklisted(channel_id, artists) {
    const promisePool = pool.promise();
    let sql = "SELECT * FROM blacklisted_artists WHERE channel_id = ? AND blocked_artist_id = ?";
    for (let i = 0; i < artists.length; i++) {
      const [rows,fields] = await promisePool.query(sql, [channel_id, artists[i].id]);
      if (rows.length >= 1) {
        return true;
      }
    }    
    return false;
  }

  async function isSongTooLong(channel_id, millis) {
    const promisePool = pool.promise();
    let sql = "SELECT * FROM channel_settings WHERE channel_id = ? AND settings_key = ?";  
    const [rows,fields] = await promisePool.query(sql, [channel_id, "max_duration"]);
    if (rows.length >= 1) {
      let row = rows[1];
      let val = row["settings_val"];
      console.log(val);
      return parseInt(val) < (millis / 1000);
    }
    return false;
  }

  function setMaxSongLength(channel, channel_id, seconds) {
    let sql = "INSERT INTO channel_settings(channel_id, settings_key, settings_val) VALUES (?, ?, ?)";
    pool.getConnection(function(conn_err, conn) {
      if (conn_err) {
        console.log(console_err);
        return false;
      }
      conn.query(sql, [channel_id, "max_duration", seconds], (query_err, query_result) => {
        if (query_err) {
          if (query_err.code === "ER_DUP_ENTRY") {
            let updateSql = "UPDATE channel_settings SET settings_val = ? WHERE channel_id = ? AND settings_key = ?";
            conn.query(updateSql, [seconds, channel_id, "max_duration"], (new_query_err, new_query_result) => {
              if (new_query_err) {
                chatClient.say(channel, "/me Error when updating value");
              } else {
                chatClient.say(channel, "/me Updated value for maximum song length to " + seconds + " seconds");
              }
            });
          } else {
            console.log("Error when inserting settings value");
            console.log(query_err);
          }
        } else {
          chatClient.say(channel, "/me Set value for maximum song length to " + seconds + " seconds");
        }
        pool.releaseConnection(conn);
      });
    });  
  }

  async function getMaxSongLength(channel, channel_id) {
    const promisePool = pool.promise();
    let sql = "SELECT * FROM channel_settings WHERE channel_id = ? AND settings_key = ?";  
    const [rows,fields] = await promisePool.query(sql, [channel_id, "max_duration"]);
    if (rows.length >= 1) {
      let row = rows[0];
      let val = row["settings_val"];
      if (channel !== null) {
        chatClient.say(channel, "/me Max. song length is currently set to " + val + " seconds");
      }
      return val;
    }
    if (channel !== null) {
      chatClient.say(channel, "/me Max. song length is currently not set");
    }
    return null;
  }

  function turnOnLiveOnly(channel, channel_id) {
    let sql = "INSERT INTO channel_settings(channel_id, settings_key, settings_val) VALUES (?, ?, ?)";
    pool.getConnection(function(conn_err, conn) {
      if (conn_err) {
        console.log(console_err);
        return false;
      }
      conn.query(sql, [channel_id, "live_only", "ON"], (query_err, query_result) => {
        if (query_err) {
          if (query_err.code === "ER_DUP_ENTRY") {
            let updateSql = "UPDATE channel_settings SET settings_val = ? WHERE channel_id = ? AND settings_key = ?";
            conn.query(updateSql, ["ON", channel_id, "live_only"], (new_query_err, new_query_result) => {
              if (new_query_err) {
                chatClient.say(channel, "/me Error when updating value");
              } else {
                chatClient.say(channel, "/me Mode is now set to live only");
              }
            });
          } else {
            console.log("Error when inserting settings value");
            console.log(query_err);
          }
        } else {
          chatClient.say(channel, "/me Mode is now set to live only");
        }
        pool.releaseConnection(conn);
      });
    });  
  }

  function turnOffLiveOnly(channel, channel_id) {
    let sql = "INSERT INTO channel_settings(channel_id, settings_key, settings_val) VALUES (?, ?, ?)";
    pool.getConnection(function(conn_err, conn) {
      if (conn_err) {
        console.log(console_err);
        return false;
      }
      conn.query(sql, [channel_id, "live_only", "OFF"], (query_err, query_result) => {
        if (query_err) {
          if (query_err.code === "ER_DUP_ENTRY") {
            let updateSql = "UPDATE channel_settings SET settings_val = ? WHERE channel_id = ? AND settings_key = ?";
            conn.query(updateSql, ["OFF", channel_id, "live_only"], (new_query_err, new_query_result) => {
              if (new_query_err) {
                chatClient.say(channel, "/me Error when updating value");
              } else {
                chatClient.say(channel, "/me Mode is not set to live only anymore");
              }
            });
          } else {
            console.log("Error when inserting settings value");
            console.log(query_err);
          }
        } else {
          chatClient.say(channel, "/me Mode is not set to live only anymore");
        }
        pool.releaseConnection(conn);
      });
    });  
  }

  async function getLiveOnly(channel, channel_id) {
    const promisePool = pool.promise();
    let sql = "SELECT * FROM channel_settings WHERE channel_id = ? AND settings_key = ?";  
    const [rows,fields] = await promisePool.query(sql, [channel_id, "live_only"]);
    if (rows.length >= 1) {
      let row = rows[0];
      let val = row["settings_val"];
      if (val.toLowerCase().trim() === "on") {
        if (channel !== null) {
          chatClient.say(channel, "/me Mode is currently set to live only");
        }
        return true;
      } else if (val.toLowerCase().trim() === "off") {
        if (channel !== null) {
          chatClient.say(channel, "/me Mode is currently not set to live only");  
        }
        return false;
      } else {
        console.log("Value for live only currently set to " + val + ". Thats not a valid option");
        if (channel !== null) {
          chatClient.say(channel, "/me Something went wrong");
        }
        return false;
      }
    }
    if (channel !== null) {
      chatClient.say(channel, "/me Mode is currently not set. Default: Off");
    }
    return false;
  }


  async function executeSpotifyAction(channel, channelid, action, args) {
    let songRequestFromArgs = "";
    let additionalArg = null;
    if (args !== undefined && args !== null && args.length > 1) {
      additionalArg = args[1];
      const filteredArray = args.slice(1);
      songRequestFromArgs = filteredArray.join(' ');
    }
    const spotifyToken = await getSpotifyToken(channel);
    console.log("Got spotify token: " + spotifyToken);
    console.log("Now executing spotify action");
    switch(action) {
        case "add":
            addSongToQueue(spotifyToken, channel, channelid, songRequestFromArgs);
            break;
        case "queue":
            let queuesize = (args!== null && args.length > 1) ? args[1] : null;
            getQueue(spotifyToken, channel, queuesize);
            break;
        case "reversequeue":
            let reversequeuesize = (args!== null && args.length > 1) ? args[1] : null;
            getReverseQueue(spotifyToken, channel, reversequeuesize);
            break;
        case "get_volume":
            getVolume(spotifyToken, channel);
            break;
        case "volume": 
            if (args.length === 3) {
              let volume = parseInt(args[2]);
              changeVolume(spotifyToken, channel, volume, args[1]);
            } else {
              let volume = parseInt(args[1]);
              if (volume > 100) {
                chatClient.say(channel, "/me Max Value is 100");
                return;
              } else if (volume < 0) {
                chatClient.say(channel, "/me Min Value is 0");
                return;
              }
              setVolume(spotifyToken, channel, parseInt(args[1]));
            }
            break;
        case "song":
            getSong(spotifyToken, channel);
            break;
        case "songlink":
            getSonglink(spotifyToken, channel);
            break;
        case "skip":
            skipSong(spotifyToken, channel);
            break;
        case "skipback":
            skipBackSong(spotifyToken, channel);
            break;
        case "resume":
            resume(spotifyToken, channel);
            break;
        case "play":
            play(spotifyToken, channel, channelid, songRequestFromArgs);
            break;
        case "pause":
            pause(spotifyToken, channel);
            break;
        case "playlist":
            getPlaylist(spotifyToken, channel);
            break;
      }
    }

async function getSpotifyToken(channel) {
  console.log("Getting spotify token for channel " + channel);
  const tokenquery = `
      SELECT * FROM tokenstore
      WHERE LOWER(twitchlogin) = ?
      LIMIT 1
  `;
  const promisePool = pool.promise();
  const [rows,fields] = await promisePool.query(tokenquery, [channel.toLowerCase()]);
  if (rows.length > 0) {
    // The first result is stored in the `results[0]` object.
    const tokenrow = rows[0];
    console.log(tokenrow);
    let spotifyAuthToken = CryptoJS.AES.decrypt(tokenrow.spotifytoken, ENCRYPTION_PWD).toString(CryptoJS.enc.Utf8);
    let refreshToken = CryptoJS.AES.decrypt(tokenrow.spotifyrefresh, ENCRYPTION_PWD).toString(CryptoJS.enc.Utf8);
    let expirationSeconds = tokenrow.spotifyexpiration;
    let dateInMillisecs = new Date().getTime();
    let dateInSecs = Math.round(dateInMillisecs / 1000);
    if (dateInSecs < parseInt(expirationSeconds) -20 ) {
      return spotifyAuthToken;
    }

    let sql = "SELECT * FROM spotify_instance where id = ?";
    console.log("Query database for spotify instance client id and secret");
    const [spotify_rows,spotify_fields] = await promisePool.query(sql, [tokenrow.spotify_instance_id]);
    console.log(spotify_rows);
    if (spotify_rows.length > 0) {
      const spotifyrow = spotify_rows[0];
      console.log("SpotifyRow: " + spotifyrow);
      

      let res = await axios({
        url: 'https://accounts.spotify.com/api/token',
        method: 'POST',
        port: 443,
        timeout: 8000,
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Authorization: 'Basic ' + (new Buffer.from(spotifyrow.client_id + ':' + spotifyrow.client_secret).toString('base64'))
        },
        data: {
          'refresh_token': refreshToken,
          'grant_type': "refresh_token"
        }
      })
      console.log(res.data);
      let newAccesstoken = res.data.access_token;
      let newAccesstokenEnc = new String(CryptoJS.AES.encrypt(newAccesstoken, ENCRYPTION_PWD)).toString();
      let newExpiresin = res.data.expires_in;
      let dateInMillisecs = new Date().getTime();
      let dateInSecs = Math.round(dateInMillisecs / 1000);
      let newCalcExpiryDate = newExpiresin + dateInSecs - 10;
      const updateQuery = `
          UPDATE tokenstore
          SET spotifytoken = ?, spotifyexpiration = ?
          WHERE LOWER(twitchlogin) = ?
        `;
      console.log("Updating with query: " + updateQuery);
      const [rows,fields] = await promisePool.query(updateQuery, [newAccesstokenEnc, newCalcExpiryDate, channel.toLowerCase()]);
      return newAccesstoken;
    }
  }
}

async function getTwitchTokenByChannel(channel) {
  console.log("Getting twitch token for channel " + channel);
  const tokenquery = `
      SELECT * FROM tokenstore
      WHERE LOWER(twitchlogin) = ?
      LIMIT 1
  `;
  const promisePool = pool.promise();
  const [rows,fields] = await promisePool.query(tokenquery, [channel.toLowerCase()]);
  let recordExists = false;
  if (rows.length > 0) {
    recordExists = true;
    // The first result is stored in the `results[0]` object.
    const tokenrow = rows[0];
    console.log(tokenrow);
    let twitchAuthToken = CryptoJS.AES.decrypt(tokenrow.twitchtoken, ENCRYPTION_PWD).toString(CryptoJS.enc.Utf8);
    let expirationSeconds = tokenrow.twitchexpiration;
    let dateInMillisecs = new Date().getTime();
    let dateInSecs = Math.round(dateInMillisecs / 1000);
    if (dateInSecs < parseInt(expirationSeconds) -20 ) {
      return twitchAuthToken;
    }
  }

  //Refresh the Twitch Token
  
  const options = {
    hostname: 'id.twitch.tv',
    port: 443,
    path: '/oauth2/token',
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  };
    
  // Create the request body
  const data = "client_id="+process.env.TWITCH_CLIENT
  +"&client_secret="+process.env.TWITCH_SECRET
  +"&grant_type=client_credentials";
  

  // Create the HTTP request
  const request = https.request(options, (response) => {
    // Handle the response
    let responseBody = '';
    response.on('data', (chunk) => {
      responseBody += chunk;
    });
    response.on('end', async () => {
      let jsonBody = JSON.parse(responseBody);
      let accesstoken = jsonBody.access_token;
      let newAccesstokenEnc = new String(CryptoJS.AES.encrypt(accesstoken, ENCRYPTION_PWD)).toString();
      let expirationDate = jsonBody.expires_in;
      let newCalcExpiryDate = expirationDate + dateInSecs - 10;
      if (recordExists) {
        const updateQuery = `
        UPDATE tokenstore
        SET twitchtoken = ?, twitchexpiration = ?
        WHERE LOWER(twitchlogin) = ?
        `;
        const [rows,fields] = await promisePool.query(updateQuery, [newAccesstokenEnc, newCalcExpiryDate, channel.toLowerCase()]);
      } 
      return accesstoken;
    });
  });
  request.on('error', function(err) {
    console.log("Error when trying to get twitch token");
    console.log(err);
  });
  // Write the request body
  request.write(data);
  // End the request
  request.end();
}


async function getTwitchTokenByChannelId(channelid) {
  console.log("Getting twitch token for channel " + channelid);
  const tokenquery = `
      SELECT * FROM tokenstore
      WHERE LOWER(twitchid) = ?
      LIMIT 1
  `;
  const promisePool = pool.promise();
  const [rows,fields] = await promisePool.query(tokenquery, [channelid.toLowerCase()]);
  let recordExists = false;
  if (rows.length > 0) {
    recordExists = true;
    // The first result is stored in the `results[0]` object.
    const tokenrow = rows[0];
    console.log(tokenrow);
    let twitchAuthToken = CryptoJS.AES.decrypt(tokenrow.twitchtoken, ENCRYPTION_PWD).toString(CryptoJS.enc.Utf8);
    let expirationSeconds = tokenrow.twitchexpiration;
    let dateInMillisecs = new Date().getTime();
    let dateInSecs = Math.round(dateInMillisecs / 1000);
    if (dateInSecs < parseInt(expirationSeconds) -20 ) {
      return twitchAuthToken;
    }
  }

  //Refresh the Twitch Token
  
  const options = {
    hostname: 'id.twitch.tv',
    port: 443,
    path: '/oauth2/token',
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
  };
    
  // Create the request body
  const data = "client_id="+process.env.TWITCH_CLIENT
  +"&client_secret="+process.env.TWITCH_SECRET
  +"&grant_type=client_credentials";
  

  // Create the HTTP request
  const request = https.request(options, (response) => {
    // Handle the response
    let responseBody = '';
    response.on('data', (chunk) => {
      responseBody += chunk;
    });
    response.on('end', async () => {
      let jsonBody = JSON.parse(responseBody);
      let accesstoken = jsonBody.access_token;
      let newAccesstokenEnc = new String(CryptoJS.AES.encrypt(accesstoken, ENCRYPTION_PWD)).toString();
      let expirationDate = jsonBody.expires_in;
      let dateInMillisecs = new Date().getTime();
      let dateInSecs = Math.round(dateInMillisecs / 1000);
      let newCalcExpiryDate = expirationDate + dateInSecs - 10;
      if (recordExists) {
        const updateQuery = `
        UPDATE tokenstore
        SET twitchtoken = ?, twitchexpiration = ?
        WHERE LOWER(twitchid) = ?
        `;
        const [rows,fields] = await promisePool.query(updateQuery, [newAccesstokenEnc, newCalcExpiryDate, channelid.toLowerCase()]);
      } 
      return accesstoken;
    });
  });
  request.on('error', function(err) {
    console.log("Error when trying to get twitch token");
    console.log(err);
  });
  // Write the request body
  request.write(data);
  // End the request
  request.end();
}

async function isLive(channel) {
  const baseUrl = 'https://api.twitch.tv/helix';
  const token = await authProvider.getAccessTokenForIntent('chat');
  console.log(token);
  try {
    // Create the authorization header
    const headers = {
      'Client-ID': clientId,
      'Authorization': `Bearer ${token.accessToken}`
    };

    // Make the GET request to the streams endpoint
    const response = await axios.get(`${baseUrl}/streams`, {
      headers,
      params: {
        user_login: channel
      }
    });

    // Check if the channel is live based on the response data
    if (response.data.data.length > 0) {
      console.log(`${channel} is live!`);
      return true;
    } else {
      console.log(`${channel} is not live.`);
      return false;
    }
  } catch (error) {
    console.error('Error:', error);
    return true;
  }
}