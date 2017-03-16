#!/usr/bin/env python

import MySQLdb
import logging
from logging.handlers import RotatingFileHandler
from irc.bot import Channel, SingleServerIRCBot, ServerSpec
from irc import connection, client
from jaraco.stream.buffer import LenientDecodingLineBuffer
import md5
import socket
import json
import ssl
import re

from captcha import CaptchaDB
from geoip import GeoIP
from dnsrbl import DNS

# irc.client workaround for decoding failures on UTF8
client.ServerConnection.buffer_class = LenientDecodingLineBuffer

class UserInfo(object):

    def __init__(self, chan, nick, ident = None, host = None, ip = None,
                 server = None, cc = None, real_name = None):
        self.nick = nick
        self.ident = ident
        self.host = host
        self.ip = ip
        self.chan = chan
        self.server = server
        self.cc = cc
        self.real_name = real_name
        self.mynick = nick

    def userhost(self):
        return str(self.nick) + "!" + str(self.ident) + "@" + str(self.host)

    def set_ip(self, ip):
        self.ip = ip


class KABASConfig(object):
    DEFAULTS = {
        'bindaddr': '0.0.0.0',
        'captcha_url': None,
        'statuschan': None,
        'channels': {},
        'db_host': None,
        'db_name': None,
        'db_pass': None,
        'db_user': None,
        'ipv6': False,
        'msgcontrol': False,
        'nickname': None,
        'ssl': False,
        'users': [],
        'banned_countries': [],
        'dnsbl': []
    }

    def __init__(self, filename = None, settings = None):
        if filename:
            settings = json.load(open(filename, 'r'))
        self.init_from_dict(settings)
        LOG.info("Loaded settings")

    def init_from_dict(self, settings):
        s = self.DEFAULTS
        s.update(settings)
        self.chanconfig = {}
        self.add_channels(s["channels"])
        self.bindaddr = s["bindaddr"]
        self.captcha_url = s["captcha_url"]
        self.statuschan = s["statuschan"]
        self.db_host = s["db_host"]
        self.db_name = s["db_name"]
        self.db_pass = s["db_pass"]
        self.db_user = s["db_user"]
        self.ipv6 = s["ipv6"]
        self.msgcontrol = s["msgcontrol"]
        self.nickname = s["nickname"]
        self.servers = []
        self.add_servers(s["servers"])
        self.ssl = s["ssl"]
        self.users = s["users"]
        self.banned_countries = s["banned_countries"]
        self.dnsrbl = s["dnsrbl"]
        
        # Normalize country codes
        for i in range(len(self.banned_countries)):
            self.banned_countries[i] = self.banned_countries[i].lower()

    def add_servers(self, servers):
        for server_config in servers:
            self.servers.append(ServerSpec(*server_config))

    def add_channel(self, name, captcha = "OFF", geoban = "OFF",
                    autovoice = "OFF", dnsrbl = "OFF"):
        config = {
            "captcha": captcha.lower(),
            "geoban": geoban.lower(),
            "autovoice": autovoice.lower(),
            "dnsrbl": dnsrbl.lower()
        }
        self.chanconfig[name.lower()] = config

    def add_channels(self, chanconfig):
        for name,config in chanconfig.iteritems():
            self.add_channel(name, **config)


class KABASBot(SingleServerIRCBot):

    def __init__(self, settings, **connect_params):
        self.settings = settings
        super(KABASBot, self).__init__(
            settings.servers, settings.nickname, "KABAS Bot", **connect_params)
        self.db = CaptchaDB(
                settings.db_host,
                settings.db_user,
                settings.db_pass,
                settings.db_name)
        self.db.connect()
        self.reactor.execute_every(1, self.periodic_callback)
        self.reactor.execute_every(2, self.check_solved_captchas)
        self.reactor.execute_every(10, self.keepnick)
        self.mynick = settings.nickname
        self.orignick = settings.nickname
        self.geodb = GeoIP()
        self.geocheck = {}
        self.dns = DNS()
        self.initialized = False

    #### Periodic functions
    def check_solved_captchas(self):
        if not self.initialized:
            return
        rows = self.db.archive_solved_captchas()
        for row in rows:
            ident_host = row[1]
            nick = row[2]
            ip = row[3]
            LOG.info("Solved captcha: %s %s", nick, ip)
            self.hook_solved_captcha(nick, ident_host)

    def check_dns_results(self):
        count = self.dns.processAnswers()
        LOG.debug("Finished %d/%d DNS queries" %
                  (count, count + self.dns.qlen()))

    def periodic_callback(self):
        if not self.initialized:
            return
        self.check_dns_results()

    #### Utility functions
    def chan_is(self, channame, key, value):
        channame = channame.lower()
        if not channame in self.settings.chanconfig:
            return False
        chanconfig = self.settings.chanconfig[channame]
        if not key in chanconfig:
            return False
        state = chanconfig[key]
        # state is already lower()
        if state == value.lower():
            return True
        else:
            return False

    def chan_is_dnsrbl(self, channame):
        return self.chan_is(channame, "dnsrbl", "ON")

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
        if not cc:
            return False
        return cc.lower() in self.settings.banned_countries

    def nick_in_chan(self, channame, nick):
        if channame in self.channels:
            chan = self.channels[channame]
            if nick in chan._users:
                return True
        return False

    def status_msg(self, msg):
        chan = self.settings.statuschan
        c = self.connection
        if not chan:
            return
        c.privmsg(chan, msg)

    # Update userinfo with arguments. Note that channel is not available here
    # because there is one userinfo class per channel and is set at the time
    # of creation
    def update_userinfo(self, nick, ident = None, host = None, ip = None,
                        server = None, cc = None, real_name = None):
        for ui in self.get_userinfos(nick):
            # Find the user in all channels being tracked and updated ui
            if ident:
                ui.ident = ident
            if host:
                ui.host = host
            if ip:
                ui.ip = ip
            if real_name:
                ui.real_name = real_name
            if cc:
                ui.cc = cc
            if ip and cc:
                self.hook_ip_lookup_chan(self.connection, ui)

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
                    userinfo = UserInfo(name, nick)
                    chan._users[nick] = userinfo
                out.append(userinfo)
        return out

    #### Post-Event Calls ####
    def hook_dnsrbl_lookup(self, nick, channame, ip):
        LOG.debug("Hook hook_dnsrbl_lookup")
        parts = ip.split(".")
        parts.reverse()
        rev = ".".join(parts)
        for dnsrbl in self.settings.dnsrbl:
            args = [dnsrbl, nick, channame, ip]
            qname = rev + "." + dnsrbl
            LOG.debug("DNS query %s", qname)
            self.dns.host(qname, self.hook_dnsrbl_answer, *args)

    def hook_dnsrbl_answer(self, answer, rbl, nick, channame, ip):
        LOG.debug("Hook hook_dnsrbl_answer")
        msg = "DNSRBL %s: %s %s %s" % (rbl, ip, nick, channame)
        LOG.info(msg)
        if not self.nick_in_chan(channame, nick):
            return
        c = self.connection
        c.mode(channame, "+b *!*@%s" % ip)
        c.kick(channame, nick, "Banned IP: %s" % rbl)
        c.privmsg(channame, "Banned IP: %s (%s) %s" % (nick, ip, rbl))

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
        channame = e.target
        chan = self.channels[channame]
        ui = chan._users[nick]
        host = ui.host
        if self.is_valid_ip(host):
            # Host is already an IP. Don't whois it
            ui.ip = host
            geodb = self.geodb
            cc = geodb.lookup(host)
            ui.cc = cc
            LOG.debug("Valid IP, skipping whois check for user=%s", nick)
            msg = "GeoIP: cc=%s %s!%s %s" % (cc, nick, ident_host, channame)
            self.status_msg(msg)
            self.hook_ip_lookup_chan(c, ui)
        else:
            LOG.debug("Checking whois for IP user=%s", nick)
            c.whois(nick)
        if self.chan_is_captcha(channame):
            # Channel setting has captcha prompting enabled
            LOG.info("Prompting %s!%s to solve captcha", nick, ident_host)
            user_key = self.hashkey(ident_host)
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
                      (ident_host, e.target, self.captcha_url(user_key)))

    def hook_ip_lookup_chan(self, c, ui):
        LOG.debug("Hook hook_ip_lookup_chan")
        if not self.chan_is_geoban(ui.chan):
            LOG.debug("Skipping geoban check for %s %s", ui.nick, ui.chan)
        elif self.is_banned_country(ui.cc):
            msg = "Banned country %s: %s!%s@%s(%s) from %s" % (ui.cc, ui.nick,
                    ui.ident, ui.host, ui.ip, ui.chan)
            LOG.info(msg)
            self.status_msg(msg)
            c.mode(ui.chan, "+b *!*@%s" % ui.host)
            c.kick(ui.chan, ui.nick, "Banned country: %s" % ui.cc)
            c.privmsg(ui.chan, "Banned country: %s (%s) %s" %
                      (ui.cc, ui.ip, ui.userhost()))
        elif self.chan_is_dnsrbl(ui.chan):
            self.hook_dnsrbl_lookup(ui.nick, ui.chan, ui.ip)

    def hook_control_msg(self, c, e, argv, reply):
        LOG.debug("Hook hook_control_privmsg")
        if len(argv) < 2:
            return
        cmd = argv[0][1:]
        if cmd == "set":
            if len(argv) < 4:
                return
            channame = argv[1]
            param = argv[2]
            value = argv[3]
            if param not in self.settings.chanconfig[channame]:
                return
            self.settings.chanconfig[channame][param] = value.lower()
            c.privmsg(reply, "set %s %s = %s" % (channame, param, value))
        elif cmd == "join":
            if len(argv) < 2:
                return
            channame = argv[1]
            self.settings.add_channel(channame)
            c.privmsg(reply, "Joining channel %s" % channame)
            c.join(channame)
        elif cmd == "part":
            if len(argv) < 2:
                return
            channame = argv[1]
            c.privmsg(reply, "Parting channel %s" % channame)
            c.part(channame)
        elif cmd == "check":
            if len(argv) < 2:
                return
            nick = argv[1]
            c.privmsg(reply, "Checking %s's IP" % nick)
            c.whois(nick)
            self.geocheck[nick] = reply
        elif cmd == "chancheck":
            if len(argv) < 2:
                return
            name = argv[1]
            if name not in self.channels:
                c.privmsg(reply, "Unknown channel %s", chan)
            chan = self.channels[name]
            towhois = []
            for nick,ui in chan._users.iteritems():
                if isinstance(ui, UserInfo) and ui.ip and ui.cc:
                    # Skip user we already checked
                    continue
                towhois.append(nick)
            c.privmsg(reply, "Whois %s: %d users missing userinfo out of %d" %
                      (name, len(towhois), len(chan._users)))
            for nick in towhois:
                c.whois(nick)
            c.privmsg(reply, "Whois %s: completed" % name)


    #### Events #### 
    def on_pubmsg(self, c, e):
        pass

    def on_privmsg(self, c, e):
        for mask in self.settings.users:
            if re.match(mask, e.source):
                argv = e.arguments[0].split(" ")
                # .cmd
                if argv[0][0] == ".":
                    reply = e.source.nick
                    self.hook_control_msg(c, e, argv, reply)

    def get_version(self):
        return 'KABASBot 0.1'

    # WHOIS IP
    def on_338(self, c, e):
        if len(e.arguments) < 2:
            LOG.debug("Protocol error parsing whois: %s", e)
            return
        nick = e.arguments[0]
        ip = e.arguments[1]
        reply = None
        if nick in self.geocheck:
            # If this was a manual query find out where it came from
            reply = self.geocheck.pop(nick)
        if self.is_valid_ip(ip):
            geodb = self.geodb
            cc = geodb.lookup(ip)
            msg = "GeoIP: cc=%s %s!?@%s" % (cc, nick, ip)
            self.status_msg(msg)
            LOG.info(msg)
            if reply:
                # Lookup request came from command. Reply to sender
                c.privmsg(reply, msg)
            self.update_userinfo(nick, ip = ip, cc = cc)
        else:
            LOG.error("GeoIP: Unable to determine IP from whois. "
                      "Try changing servers")
            if reply:
                c.privmsg(reply, "GeoIP: Unable to determine IP from whois")

    # WHOIS Server
    def on_whoisserver(self, c, e):
        # nick, server, server description
        if len(e.arguments) < 2:
            LOG.debug("Protocol error parsing whois: %s", e)
            return
        nick = e.arguments[0]
        server = e.arguments[1]
        self.update_userinfo(nick, server = server)

    # WHOIS User
    def on_whoisuser(self, c, e):
        # nick, ident, host, *, real_name
        if len(e.arguments) < 5:
            LOG.debug("Protocol error parsing whois: %s", e)
            return
        nick = e.arguments[0]
        ident = e.arguments[1]
        host = e.arguments[2]
        real_name = e.arguments[4]
        self.update_userinfo(nick, ident = ident, host = host,
                             real_name = real_name)

    def on_join(self, c, e):
        nick, ident_host = e.source.split('!')
        if nick == self.mynick:
            # Ignore the bot
            return
        if e.target == self.settings.statuschan:
            # Don't parse joins for the status chan
            return
        LOG.debug("EVENT %s", e)
        ident, host = e.source.split('@')
        chan = self.channels[e.target]
        userinfo = UserInfo(e.target, nick, ident, host)
        chan.set_userdetails(nick, userinfo)
        db = self.db
        if db.is_excepted(ident_host):
            self.hook_join_excepted(c, e, nick, ident_host)
        else:
            self.hook_join_not_excepted(c, e, nick, ident_host)

    def on_nick(self, c, e):
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
        

