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

def hashkey(ident_host):
    h = md5.new(ident_host)
    return h.hexdigest()

def captcha_url(user_key):
    return settings["captcha_url"] + "/?key=" + user_key

def is_valid_ip(ip):
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

class KABASBot(SingleServerIRCBot):

    def __init__(self, server_list, nickname, chanlist, **connect_params):
        super(KABASBot, self).__init__(
            server_list, nickname, "KABAS Bot", **connect_params)
        self.chanlist = chanlist
        self.db = CaptchaDB(
                settings["db_host"],
                settings["db_user"],
                settings["db_pass"],
                settings["db_name"])
        self.db.connect()
        self.seclevel = settings["seclevel"]
        self.reactor.execute_every(2, self.periodic_callback)
        self.reactor.execute_every(10, self.keepnick)
        self.mynick = nickname
        self.orignick = nickname
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
        if chan.is_oper(self.mynick) and \
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

    def hook_control_msg(self, c, e, argv, reply):
        LOG.debug("Hook hook_control_privmsg")
        if len(argv) < 2:
            return
        cmd = argv[1]
        if cmd == "seclevel":
            if len(argv) < 3:
                return
            seclevel = argv[2].upper()
            if seclevel in [ "OFF", "SOFT", "SECURE" ]:
                self.seclevel = seclevel
                c.privmsg(reply, "KABASBot level set to %s" % seclevel)
            else:
                c.privmsg(reply, "Error, unknown level %s" % seclevel)
        elif cmd == "join":
            if len(argv) < 3:
                return
            channame = argv[2].upper()
            c.privmsg(reply, "Joining channel %s" % channame)
            c.join(channame)
        elif cmd == "part":
            if len(argv) < 3:
                return
            channame = argv[2].upper()
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
                    LOG.info("UserInfo for %s not found. Creating", nick)
                    userinfo = UserInfo(nick)
                    chan._users[nick] = userinfo
                out.append(userinfo)
        return out

    #### Events #### 
    def on_pubmsg(self, c, e):
        LOG.info("EVENT %s", e)
        if e.target.lower() == settings["chancontrol"].lower():
            argv = e.arguments[0].split(" ")
            if argv[0] == ".cmd":
                reply = e.target
                self.hook_control_msg(c, e, argv, reply)

    def on_privmsg(self, c, e):
        LOG.info("EVENT %s", e)
        for mask in settings["users"]:
            if re.match(mask, e.source):
                argv = e.arguments[0].split(" ")
                if argv[0] == ".cmd":
                    reply = e.source.nick
                    self.hook_control_msg(c, e, argv, reply)

    def get_version(self):
        return 'KABASBot 0.1'

    def on_338(self, c, e):
        LOG.info("EVENT %s", e)
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
        if e.target == settings["chancontrol"]:
            # Don't parse joins for the control chan
            return
        LOG.info("EVENT %s", e)
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
        LOG.info("EVENT %s", e)
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
        for channel in self.chanlist:
            LOG.info("Joining channel %s", channel)
            c.join(channel)

    def on_disconnect(self, c, e):
        self.initialized = False

# default config values. DO NOT CHANGE
settings = {
    'bindaddr': '0.0.0.0',
    'captcha_url': None,
    'chancontrol': None,
    'chanlist': [],
    'db_host': None,
    'db_name': None,
    'db_pass': None,
    'db_user': None,
    'ipv6': False,
    'msgcontrol': False,
    'nickname': None,
    'seclevel': "OFF",
    'servers': [],
    'ssl': False,
    'users': []
}

if __name__ == '__main__':
    LOG = logging.getLogger('captcha-irc')
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

    settings.update(json.load(open("captcha-irc.cfg", 'r')))
    LOG.info("Loaded settings")

    if settings["ssl"]:
        wrapper = ssl.wrap_socket
    else:
        wrapper = connection.identity

    bot = KABASBot(
        server_list = settings["servers"],
        nickname = settings["nickname"],
        chanlist = settings["chanlist"],
        connect_factory = connection.Factory(
            bind_address = (settings["bindaddr"],0),
            ipv6 = settings["ipv6"],
            wrapper = wrapper))
    bot.start()
        

