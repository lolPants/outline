// @flow
import passport from "@outlinewiki/koa-passport";
import Router from "koa-router";
import { Strategy as DiscordStrategy } from "passport-discord";
import accountProvisioner from "../../commands/accountProvisioner";
import env from "../../env";
import { DiscordInvalidGuildError } from "../../errors";
import passportMiddleware from "../../middlewares/passport";
import { StateStore } from "../../utils/passport";

const router = new Router();
const providerName = "discord";
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_GUILD_ID = process.env.DISCORD_GUILD_ID;

export const config = {
  name: "Discord",
  enabled: !!DISCORD_CLIENT_ID,
};

const scopes = ["identify", "email", "guilds"];

if (DISCORD_CLIENT_ID) {
  passport.use(
    new DiscordStrategy(
      {
        clientID: DISCORD_CLIENT_ID,
        clientSecret: DISCORD_CLIENT_SECRET,
        callbackURL: `${env.URL}/auth/discord.callback`,
        passReqToCallback: true,
        store: new StateStore(),
        scope: scopes,
      },
      async function (req, accessToken, refreshToken, profile, done) {
        try {
          const guild = profile.guilds.find(
            (guild) => guild.id === DISCORD_GUILD_ID
          );
          if (!guild) {
            throw new DiscordInvalidGuildError();
          }

          const result = await accountProvisioner({
            ip: req.ip,
            team: {
              name: guild.name,
              domain: guild.id,
              subdomain: guild.id,
              avatarUrl:
                guild.icon &&
                `https://cdn.discordapp.com/icons/${guild.id}/${guild.icon}.png`,
            },
            user: {
              name: profile.username,
              email: profile.email,
              avatarUrl:
                profile.avatar &&
                `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png`,
            },
            authenticationProvider: {
              name: providerName,
              providerId: guild.id,
            },
            authentication: {
              providerId: profile.id,
              accessToken,
              refreshToken,
              scopes,
            },
          });
          return done(null, result.user, result);
        } catch (err) {
          return done(err, null);
        }
      }
    )
  );

  router.get("discord", passport.authenticate(providerName));

  router.get("discord.callback", passportMiddleware(providerName));
}

export default router;
