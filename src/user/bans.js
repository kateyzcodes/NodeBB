'use strict';
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const winston = __importStar(require("winston"));
const meta = __importStar(require("../meta"));
const emailer = __importStar(require("../emailer"));
const db = __importStar(require("../database"));
const groups = __importStar(require("../groups"));
const privileges = __importStar(require("../privileges"));
function UserModule(User) {
    User.bans = {};
    User.bans.ban = function (uid, until, reason) {
        return __awaiter(this, void 0, void 0, function* () {
            // "until" (optional) is a Unix timestamp in milliseconds
            // "reason" (optional) is a string
            until = until || 0;
            reason = reason || '';
            const now = Date.now();
            until = parseInt(until.toString(), 10);
            if (isNaN(until)) {
                throw new Error('[[error:ban-expiry-missing]]');
            }
            const banKey = `uid:${uid}:ban:${now}`;
            const banData = {
                uid: uid,
                timestamp: now,
                expire: until > now ? until : 0,
            };
            if (reason) {
                banData.reason = reason;
            }
            // Leaving all other system groups to have privileges constrained to the "banned-users" group
            const systemGroups = groups.systemGroups.filter(group => group !== groups.BANNED_USERS);
            yield groups.leave(systemGroups, uid);
            yield groups.join(groups.BANNED_USERS, uid);
            yield db.sortedSetAdd('users:banned', now, uid);
            yield db.sortedSetAdd(`uid:${uid}:bans:timestamp`, now, banKey);
            yield db.setObject(banKey, banData);
            yield User.setUserField(uid, 'banned:expire', banData.expire);
            if (until > now) {
                yield db.sortedSetAdd('users:banned:expire', until, uid);
            }
            else {
                yield db.sortedSetRemove('users:banned:expire', uid);
            }
            // Email notification of ban
            const username = yield User.getUserField(uid, 'username');
            const siteTitle = meta.config.title || 'NodeBB';
            const data = {
                subject: `[[email:banned.subject, ${siteTitle}]]`,
                username: username,
                until: until ? new Date(until).toUTCString().replace(/,/g, '\\,') : false,
                reason: reason,
            };
            yield emailer.send('banned', uid, data).catch((err) => winston.error(`[emailer.send] ${err.stack}`));
            return banData;
        });
    };
    User.bans.unban = function (uids) {
        return __awaiter(this, void 0, void 0, function* () {
            uids = Array.isArray(uids) ? uids : [uids];
            const userData = yield User.getUsersFields(uids, ['email:confirmed']);
            yield db.setObject(uids.map((uid) => `user:${uid}`), { 'banned:expire': 0 });
            /* eslint-disable no-await-in-loop */
            for (const user of userData) {
                const systemGroupsToJoin = [
                    'registered-users',
                    (parseInt(user['email:confirmed'], 10) === 1 ? 'verified-users' : 'unverified-users'),
                ];
                yield groups.leave(groups.BANNED_USERS, user.uid);
                // An unbanned user would lose its previous "Global Moderator" status
                yield groups.join(systemGroupsToJoin, user.uid);
            }
            yield db.sortedSetRemove(['users:banned', 'users:banned:expire'], uids);
        });
    };
    User.bans.isBanned = function (uids) {
        return __awaiter(this, void 0, void 0, function* () {
            const isArray = Array.isArray(uids);
            const uidsArray = isArray ? uids : [uids];
            const result = yield User.bans.unbanIfExpired(uidsArray);
            return isArray ? result.map((r) => r.banned) : result[0].banned;
        });
    };
    User.bans.canLoginIfBanned = function (uid) {
        return __awaiter(this, void 0, void 0, function* () {
            let canLogin = true;
            const { banned } = (yield User.bans.unbanIfExpired([uid]))[0];
            // Group privilege overshadows individual one
            if (banned) {
                canLogin = yield privileges.global.canGroup('local:login', groups.BANNED_USERS);
            }
            if (banned && !canLogin) {
                // Checking a single privilege of user
                canLogin = yield groups.isMember(uid, 'cid:0:privileges:local:login');
            }
            return canLogin;
        });
    };
    User.bans.unbanIfExpired = function (uids) {
        return __awaiter(this, void 0, void 0, function* () {
            // loading user data will unban if it has expired -barisu
            const userData = yield User.getUsersFields(uids, ['banned:expire']);
            return User.bans.calcExpiredFromUserData(userData);
        });
    };
    User.bans.calcExpiredFromUserData = function (userData) {
        return __awaiter(this, void 0, void 0, function* () {
            const isArray = Array.isArray(userData);
            userData = isArray ? userData : [userData];
            const banned = yield groups.isMembers(userData.map((u) => u.uid), groups.BANNED_USERS);
            userData = userData.map((userData, index) => ({
                banned: banned[index],
                'banned:expire': userData && userData['banned:expire'],
                banExpired: userData && userData['banned:expire'] <= Date.now() && userData['banned:expire'] !== 0,
            }));
            return isArray ? userData : userData[0];
        });
    };
    User.bans.filterBanned = function (uids) {
        return __awaiter(this, void 0, void 0, function* () {
            const isBanned = yield User.bans.isBanned(uids);
            const filterFn = (uid, index) => {
                if (Array.isArray(isBanned)) {
                    return !isBanned[index];
                }
                else {
                    return !isBanned;
                }
            };
            if (Array.isArray(uids)) {
                return uids.filter(filterFn);
            }
            return [];
        });
    };
    User.bans.getReason = function (uid) {
        return __awaiter(this, void 0, void 0, function* () {
            if (parseInt(uid, 10) <= 0) {
                return '';
            }
            const keys = yield db.getSortedSetRevRange(`uid:${uid}:bans:timestamp`, 0, 0);
            if (!keys.length) {
                return '';
            }
            const banObj = yield db.getObject(keys[0]);
            return banObj && banObj.reason ? banObj.reason : '';
        });
    };
}
exports.default = UserModule;
