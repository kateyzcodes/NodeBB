'use strict';

import * as winston from 'winston';
import * as meta from '../meta';
import * as emailer from '../emailer';
import * as db from '../database';
import * as groups from '../groups';
import * as privileges from '../privileges';

export default function UserModule(User: any) {
    User.bans = {};

    User.bans.ban = async function (uid: number, until: number, reason: string): Promise<any> {
    // "until" (optional) is a Unix timestamp in milliseconds
    // "reason" (optional) is a string
    until = until || 0;
    reason = reason || '';

    const now: number = Date.now();

    until = parseInt(until.toString(), 10);
    if (isNaN(until)) {
      throw new Error('[[error:ban-expiry-missing]]');
    }

    const banKey: string = `uid:${uid}:ban:${now}`;
    const banData: { uid: number; timestamp: number; expire: number; reason?: string } = {
    uid: uid,
    timestamp: now,
    expire: until > now ? until : 0,
    };
    if (reason) {
        banData.reason = reason;
    }

        // Leaving all other system groups to have privileges constrained to the "banned-users" group
    const systemGroups: string[] = groups.systemGroups.filter(group => group !== groups.BANNED_USERS);
    await groups.leave(systemGroups, uid);
    await groups.join(groups.BANNED_USERS, uid);
    await db.sortedSetAdd('users:banned', now, uid);
    await db.sortedSetAdd(`uid:${uid}:bans:timestamp`, now, banKey);
    await db.setObject(banKey, banData);
    await User.setUserField(uid, 'banned:expire', banData.expire);
    if (until > now) {
        await db.sortedSetAdd('users:banned:expire', until, uid);
    } else {
        await db.sortedSetRemove('users:banned:expire', uid);
    }

        // Email notification of ban
    const username: string | null = await User.getUserField(uid, 'username');
    const siteTitle: string = meta.config.title || 'NodeBB';

    const data: {
    subject: string;
    username: string | null;
    until: string | false;
    reason: string;
    } = {
    subject: `[[email:banned.subject, ${siteTitle}]]`,
    username: username,
    until: until ? new Date(until).toUTCString().replace(/,/g, '\\,') : false,
    reason: reason,
    };

    await emailer.send('banned', uid, data).catch((err: Error) => winston.error(`[emailer.send] ${err.stack}`));

    return banData;

    }

    User.bans.unban = async function (uids: number | number[]): Promise<void> {
        uids = Array.isArray(uids) ? uids : [uids];
        const userData = await User.getUsersFields(uids, ['email:confirmed']);
  
        await db.setObject(uids.map((uid: number) => `user:${uid}`), { 'banned:expire': 0 });
  
        /* eslint-disable no-await-in-loop */
        for (const user of userData) {
         const systemGroupsToJoin: string[] = [
          'registered-users',
          (parseInt(user['email:confirmed'], 10) === 1 ? 'verified-users' : 'unverified-users'),
        ];
        await groups.leave(groups.BANNED_USERS, user.uid);
        // An unbanned user would lose its previous "Global Moderator" status
        await groups.join(systemGroupsToJoin, user.uid);
        }
  
    await db.sortedSetRemove(['users:banned', 'users:banned:expire'], uids);
  };
  
    User.bans.isBanned = async function (uids: number | number[]): Promise<boolean | boolean[]> {
      const isArray: boolean = Array.isArray(uids);
      const uidsArray: number[] = isArray ? uids as number[] : [uids as number];
      const result: any[] = await User.bans.unbanIfExpired(uidsArray);
      return isArray ? result.map((r: any) => r.banned) : result[0].banned;
    };
  
    User.bans.canLoginIfBanned = async function (uid: number): Promise<boolean> {
        let canLogin: boolean = true;
      
        const { banned }: any = (await User.bans.unbanIfExpired([uid]))[0];
        // Group privilege overshadows individual one
        if (banned) {
          canLogin = await privileges.global.canGroup('local:login', groups.BANNED_USERS);
        }
        if (banned && !canLogin) {
          // Checking a single privilege of user
          canLogin = await groups.isMember(uid, 'cid:0:privileges:local:login');
        }
      
        return canLogin;
      };

      User.bans.unbanIfExpired = async function (uids: number | number[]): Promise<any[]> {
        // loading user data will unban if it has expired -barisu
        const userData: any[] = await User.getUsersFields(uids, ['banned:expire']);
        return User.bans.calcExpiredFromUserData(userData);
      };
      
      User.bans.calcExpiredFromUserData = async function (userData: any | any[]): Promise<any | any[]> {
        const isArray: boolean = Array.isArray(userData);
        userData = isArray ? userData : [userData];
        const banned: boolean[] = await groups.isMembers(userData.map((u: any) => u.uid), groups.BANNED_USERS);
        userData = userData.map((userData: any, index: number) => ({
          banned: banned[index],
          'banned:expire': userData && userData['banned:expire'],
          banExpired: userData && userData['banned:expire'] <= Date.now() && userData['banned:expire'] !== 0,
        }));
        return isArray ? userData : userData[0];
      };
      
      User.bans.filterBanned = async function (uids: number | number[]): Promise<number[]> {
        const isBanned: boolean | boolean[] = await User.bans.isBanned(uids);
      
        const filterFn = (uid: number, index: number) => {
          if (Array.isArray(isBanned)) {
            return !isBanned[index];
          } else {
            return !isBanned;
          }
        };
      
        if (Array.isArray(uids)) {
          return uids.filter(filterFn);
        }
      
        return [];
      };         

      User.bans.getReason = async function (uid: number | string): Promise<string> {
        if (parseInt(uid as string, 10) <= 0) {
          return '';
        }
        const keys: string[] = await db.getSortedSetRevRange(`uid:${uid}:bans:timestamp`, 0, 0);
        if (!keys.length) {
          return '';
        }
        const banObj: Record<string, any> = await db.getObject(keys[0]);
        return banObj && banObj.reason ? banObj.reason : '';
      };      

}