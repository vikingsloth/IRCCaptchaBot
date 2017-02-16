#!/usr/bin/env python

import MySQLdb
import logging
from logging.handlers import RotatingFileHandler
from irc.bot import Channel, SingleServerIRCBot
from irc import connection
import md5
import socket
import json
import ssl
import re

from captcha import CaptchaDB
from geoip import GeoIP

class UserInfo(object):

    def __init__(self, nick, ident = None, host = None, chan = None, ip = None):
        self.nick = nick
        self.ident = ident
        self.host = host
        self.ip = ip
        self.chan = chan
        self.mynick = nick

    def set_ip(self, ip):
        self.ip = ip

class KABASConfig(object):
    DEFAULTS = {
        'bindaddr': '0.0.0.0',
        'captcha_url': None,
        'chancontrol': None,
        'channels': {},
        'password': None,
        'db_host': None,
        'db_name': None,
        'db_pass': None,
        'db_user': None,
        'ipv6': False,
        'msgcontrol': False,
        'nickname': None,
        'servers': [],
        'ssl': False,
        'users': [],
        'banned_countries': []
    }

    def __init__(self, filename = None, settings = None):
        if filename:
            settings = json.load(open(filename, 'r'))
        self.init_from_dict(settings)
        LOG.info("Loaded settings")

    def init_from_dict(self, settings):
        s = self.DEFAULTS
        s.update(settings)
        self.add_channels(s["channels"])
        self.bindaddr = s["bindaddr"]
        self.captcha_url = s["captcha_url"]
        self.chancontrol = s["chancontrol"]
        self.password = s["chancontrol"]
        self.db_host = s["db_host"]
        self.db_name = s["db_name"]
        self.db_pass = s["db_pass"]
        self.db_user = s["db_user"]
        self.ipv6 = s["ipv6"]
        self.msgcontrol = s["msgcontrol"]
        self.nickname = s["nickname"]
        self.servers = s["servers"]
        self.ssl = s["ssl"]
        self.users = s["users"]
        self.banned_countries = s["banned_countries"]

    def add_channel(self, name, captcha = "OFF", geoban = "OFF",
                    autovoice = "OFF"):
        config = {
            "captcha": captcha.upper(),
            "geoban": geoban.upper(),
            "autovoice": autovoice.upper()
        }
        self.chanconfig[name] = config

    def add_channels(self, chanconfig):
        for name,config in chanconfig.iteritems():
            self.add_channel(name, **config)


class KABASBot(SingleServerIRCBot):

    def __init__(self, settings, **connect_params):
        self.settings = settings
        server_list = settings.servers
        nickname = settings.nickname
        super(KABASBot, self).__init__(
            server_list, nickname, "KABAS Bot", **connect_params)
        self.db = CaptchaDB(
                settings.db_host,
                settings.db_user,
                settings.db_pass,
                settings.db_name)
        self.db.connect()
        self.reactor.execute_every(2, self.periodic_callback)
        self.reactor.execute_every(10, self.keepnick)
        self.mynick = settings.nickname
        self.orignick = settings.nickname
        self.geodb = GeoIP()
        self.initialized = False

    def check_solved_captchas(self):
        rows = self.db.archive_solved_captchas()
        for row in rows:
            ident_host = row[1]
            nick = row[2]
            ip = row[3]
            LOG.info("Solved captcha: %s %s", nick, ip)
            self.hook_solved_captcha(nick, ident_host)

    def periodic_callback(self):
        if self.initialized:
            self.check_solved_captchas()

    #### Utility functions
    def chan_is(self, channame, key, value):
        if not channame in self.settings.chanconfig:
            return False
        chanconfig = self.settings.chanconfig[channame]
        if not key in chanconfig:
            return False
        state = chanconfig[key]
        # state is already upper()
        if state == value.upper():
            return True
        else:
            return False

    def chan_is_autovoice(self, channame):
        return self.chan_is(channame, "autovoice", "ON")

    def chan_is_geoban(self, channame):
        return self.chan_is(channame, "geoban", "ON")

    def chan_is_captcha(self, channame):
        return self.chan_is(channame, "captcha", "SOFT") or \
               self.chan_is(channame, "captcha", "SECURE")

    def chan_is_secure(self, channame):
        return self.chan_is(channame, "captcha", "SECURE")

    def keepnick(self):
        if self.mynick != self.orignick:
            self.connection.nick(self.orignick)

    def update_captcha(self, user_key, nick):
        try:
            self.db.update_captcha(user_key, nick)
        except Exception as e:
            LOG.error("Failed to insert captcha for %s into DB: %s",
                      user_key, e)
            self.db.db.rollback()
            return

    def get_user_chans(self, nick):
        out = []
        for name in self.channels:
            chan = self.channels[name]
            if nick in chan._users:
                out.append(name)
        return out
                
    def hashkey(self, ident_host):
        h = md5.new(ident_host)
        return h.hexdigest()

    def captcha_url(self, user_key):
        return self.settings.captcha_url + "/?key=" + user_key

    def is_valid_ip(self, ip):
        if ip.count('.') == 3:
            try:
                socket.inet_pton(socket.AF_INET, ip)
            except socket.error:
                return False
        else:
            try:
                socket.inet_pton(socket.AF_INET6, ip)
            except socket.error:
                return False
        return True

    def is_banned_country(self, cc):
        return cc in self.settings.banned_countries

    #### Post-Event Calls ####
    def hook_solved_captcha(self, nick, ident_host):
        LOG.debug("Hook hook_solved_captcha")
        for chan in self.get_user_chans(nick):
            self.hook_excepted_action(nick, ident_host, chan)

    def hook_excepted_action(self, nick, ident_host, channame):
        LOG.debug("Hook hook_excepted_action")
        db = self.db
        db.update_exception(ident_host)
        chan = self.channels[channame]
        if self.chan_is_autovoice(channame) and \
           chan.is_oper(self.mynick) and \
           not chan.is_voiced(nick):
            LOG.info("Voicing %s in %s", nick, channame)
            self.connection.mode(channame, "+v %s" % nick)

    def hook_join_excepted(self, c, e, nick, ident_host):
        LOG.debug("Hook hook_join_excepted")
        self.hook_excepted_action(nick, ident_host, e.target)

    def hook_join_not_excepted(self, c, e, nick, ident_host):
        LOG.debug("Hook hook_join_not_excepted")
        db = self.db
        chan = self.channels[e.target]
        ui = chan._users[nick]
        host = ui.host
        if is_valid_ip(host):
            ui.ip = host
            self.hook_ip_lookup_chan(c, ui)
        else:
            LOG.debug("Checking whois for IP user=%s", nick)
            c.whois(nick)
        if self.seclevel != "OFF":
            LOG.info("Prompting %s!%s to solve captcha", nick, ident_host)
            user_key = hashkey(ident_host)
            try:
                db.insert_captcha(user_key, ident_host, nick)
            except MySQLdb.IntegrityError:
                LOG.error("User %s already has an unsolved captcha", ident_host)
                db.db.rollback()
                self.update_captcha(user_key, nick)
            except Exception as e:
                LOG.error("Failed to insert captcha for %s into DB: %s",
                          ident_host, e)
                db.db.rollback()
                return
            c.privmsg(nick,
                      "Your hostmask %s has not been confirmed for access to "
                      "%s. Solve this captcha to confirm you're not a "
                      "bot: %s" %
                      (ident_host, e.target, captcha_url(user_key)))

    def hook_ip_lookup_chan(self, c, ui):
        LOG.debug("Hook hook_ip_lookup_chan")
        if not self.chan_is_geoban(ui.chan):
            return
        geodb = self.geodb
        geo = geodb.lookup(ui.ip)
        if geo:
            cc = geo["cc"]
            LOG.info("IP lookup: %s!%s@%s(%s) %s country_code:%s", ui.nick,
                      ui.ident, ui.host, ui.ip, ui.chan, cc)
            if is_banned_country(cc):
                LOG.info("Banned country %s: %s!%s@%s(%s) from %s", cc, ui.nick,
                         ui.ident, ui.host, ui.ip, ui.chan)
                c.mode(ui.chan, "+b *!*@%s" % ui.host)
                c.kick(ui.chan, ui.nick, "Banned country: %s" % cc)

    def hook_control_msg(self, c, e, argv, reply):
        LOG.debug("Hook hook_control_privmsg")
        if len(argv) < 2:
            return
        cmd = argv[1]
        if cmd == "set":
            if len(argv) < 5:
                return
            channame = argv[2]
            param = argv[3]
            value = argv[4]
            if param not in self.settings.chanconfig[channame]:
                return
            self.settings.chanconfig[channame][param] = value.upper()
            c.privmsg(reply, "set %s %s = %s" % (channame, param, value))
        elif cmd == "join":
            if len(argv) < 3:
                return
            channame = argv[2]
            self.settings.add_channel(channame)
            c.privmsg(reply, "Joining channel %s" % channame)
            c.join(channame)
        elif cmd == "part":
            if len(argv) < 3:
                return
            channame = argv[2]
            c.privmsg(reply, "Parting channel %s" % channame)
            c.part(channame)

    #### Utils ####
    # Gets all the UserInfo classes from channels matching nick
    def get_userinfos(self, nick):
        out = []
        for name in self.channels:
            chan = self.channels[name]
            if nick in chan._users:
                userinfo = chan._users[nick]
                if not isinstance(userinfo, UserInfo):
                    # not really an error
                    LOG.error("UserInfo for %s not found. Creating", nick)
                    userinfo = UserInfo(nick)
                    chan._users[nick] = userinfo
                out.append(userinfo)
        return out

    #### Events #### 
    def on_pubmsg(self, c, e):
        LOG.debug("EVENT %s", e)
        if e.target.lower() == self.settings.chancontrol.lower():
            argv = e.arguments[0].split(" ")
            if argv[0] == ".cmd":
                reply = e.target
                self.hook_control_msg(c, e, argv, reply)

    def on_privmsg(self, c, e):
        LOG.debug("EVENT %s", e)
        for mask in self.settings.users:
            if re.match(mask, e.source):
                argv = e.arguments[0].split(" ")
                if argv[0] == ".cmd":
                    reply = e.source.nick
                    self.hook_control_msg(c, e, argv, reply)

    def get_version(self):
        return 'KABASBot 0.1'

    # USERINFO response with IP
    def on_338(self, c, e):
        LOG.debug("EVENT %s", e)
        if len(e.arguments) < 2:
            return
        nick = e.arguments[0]
        ip = e.arguments[1]
        if is_valid_ip(ip):
            for ui in self.get_userinfos(nick):
                ui.ip = ip
                self.hook_ip_lookup_chan(c, ui)
        else:
            LOG.error("Unable to determine IP from whois. Try changing servers")

    def on_join(self, c, e):
        nick, ident_host = e.source.split('!')
        if nick == self.mynick:
            # Ignore the bot
            return
        if e.target == self.settings.chancontrol:
            # Don't parse joins for the control chan
            return
        LOG.debug("EVENT %s", e)
        ident, host = e.source.split('@')
        chan = self.channels[e.target]
        userinfo = UserInfo(nick, ident, host, chan = e.target)
        chan.set_userdetails(nick, userinfo)
        db = self.db
        if db.is_excepted(ident_host):
            self.hook_join_excepted(c, e, nick, ident_host)
        else:
            self.hook_join_not_excepted(c, e, nick, ident_host)

    def on_nick(self, c, e):
        LOG.debug("EVENT %s", e)
        if e.source.nick == self.mynick:
            LOG.debug("My nick changed! Updating")
            self.mynick = e.target

    def on_nicknameinuse(self, c, e):
        LOG.error("Nick in use. Appending _")
        if not self.initialized and len(self.nick) < 9:
            self.mynick = self.mynick + '_'
            c.nick(self.mynick)

    def on_welcome(self, c, e):
        self.initialized = True
        for channel in self.settings.chanconfig.keys():
            LOG.info("Joining channel %s", channel)
            c.join(channel)

    def on_disconnect(self, c, e):
        self.initialized = False

if __name__ == '__main__':
    LOG = logging.getLogger('kabasbot-irc')
    LOG.setLevel(logging.DEBUG)
    logging.basicConfig(level=logging.DEBUG)
    handler = RotatingFileHandler(
            'irc.log', mode='a', maxBytes = 10*1024*1024, backupCount = 100)
    formatter = logging.Formatter(
            '%(asctime)-15s:%(levelname)-6s:%(message)s',
            '%Y.%m.%d-%I:%M:%s')
    handler.setFormatter(formatter)
    handler.setLevel(logging.DEBUG)
    LOG.addHandler(handler)

    # Override other library logging
    ROOTLOG = logging.getLogger()
    ROOTLOG.addHandler(handler)

    settings = KABASConfig("kabasbot-irc.cfg")

    if settings.ssl:
        wrapper = ssl.wrap_socket
    else:
        wrapper = connection.identity

    bot = KABASBot(
        settings = settings,
        connect_factory = connection.Factory(
            bind_address = (settings.bindaddr,0),
            ipv6 = settings.ipv6,
            wrapper = wrapper))
    bot.start()
        

