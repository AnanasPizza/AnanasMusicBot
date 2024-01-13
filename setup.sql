-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 10.35.46.77:3306
-- Erstellungszeit: 12. Jan 2024 um 01:32
-- Server-Version: 8.0.33
-- PHP-Version: 8.2.11

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

-- --------------------------------------------------------

--
-- Tabellenstruktur für Tabelle `blacklisted_artists`
--

CREATE TABLE `blacklisted_artists` (
  `id` int NOT NULL,
  `channel_id` int NOT NULL,
  `blocked_artist_id` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

-- --------------------------------------------------------

--
-- Tabellenstruktur für Tabelle `blacklisted_tracks`
--

CREATE TABLE `blacklisted_tracks` (
  `id` int NOT NULL,
  `channel_id` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci NOT NULL,
  `blocked_track_id` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

-- --------------------------------------------------------

--
-- Tabellenstruktur für Tabelle `blacklisted_users`
--

CREATE TABLE `blacklisted_users` (
  `id` int NOT NULL,
  `channel_id` varchar(255) NOT NULL,
  `blocked_user_name` varchar(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

-- --------------------------------------------------------

--
-- Tabellenstruktur für Tabelle `bot_tokenstore`
--

CREATE TABLE `bot_tokenstore` (
  `twitch_id` bigint NOT NULL,
  `accessToken` varchar(500) NOT NULL,
  `expiresIn` int NOT NULL,
  `obtainmentTimestamp` bigint NOT NULL,
  `refreshToken` varchar(500) NOT NULL,
  `scope` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

-- --------------------------------------------------------

--
-- Tabellenstruktur für Tabelle `channel_settings`
--

CREATE TABLE `channel_settings` (
  `channel_name` varchar(255) NOT NULL,
  `settings_key` varchar(255) NOT NULL,
  `settings_val` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

-- --------------------------------------------------------

--
-- Tabellenstruktur für Tabelle `tokenstore`
--

CREATE TABLE `tokenstore` (
  `id` int NOT NULL,
  `twitchid` varchar(255) NOT NULL,
  `twitchlogin` varchar(255) NOT NULL,
  `spotifytoken` varchar(500) NOT NULL,
  `spotifyrefresh` varchar(500) NOT NULL,
  `spotifyexpiration` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3;

--
-- Indizes der exportierten Tabellen
--

--
-- Indizes für die Tabelle `blacklisted_artists`
--
ALTER TABLE `blacklisted_artists`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `unique_artist_channel` (`channel_id`,`blocked_artist_id`);

--
-- Indizes für die Tabelle `blacklisted_tracks`
--
ALTER TABLE `blacklisted_tracks`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `twitchid` (`channel_id`,`blocked_track_id`);

--
-- Indizes für die Tabelle `blacklisted_users`
--
ALTER TABLE `blacklisted_users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `channel_id` (`channel_id`,`blocked_user_name`);

--
-- Indizes für die Tabelle `bot_tokenstore`
--
ALTER TABLE `bot_tokenstore`
  ADD PRIMARY KEY (`twitch_id`);

--
-- Indizes für die Tabelle `channel_settings`
--
ALTER TABLE `channel_settings`
  ADD UNIQUE KEY `channel_name` (`channel_name`,`settings_key`);

--
-- Indizes für die Tabelle `tokenstore`
--
ALTER TABLE `tokenstore`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `twitchid` (`twitchid`),
  ADD UNIQUE KEY `twitchlogin` (`twitchlogin`);

--
-- AUTO_INCREMENT für exportierte Tabellen
--

--
-- AUTO_INCREMENT für Tabelle `blacklisted_artists`
--
ALTER TABLE `blacklisted_artists`
  MODIFY `id` int NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT für Tabelle `blacklisted_tracks`
--
ALTER TABLE `blacklisted_tracks`
  MODIFY `id` int NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT für Tabelle `blacklisted_users`
--
ALTER TABLE `blacklisted_users`
  MODIFY `id` int NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT für Tabelle `tokenstore`
--
ALTER TABLE `tokenstore`
  MODIFY `id` int NOT NULL AUTO_INCREMENT;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
