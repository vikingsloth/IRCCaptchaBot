#!/usr/bin/env python

import logging
from tornado import httpserver, ioloop, web, gen, httpclient, template
from tornado.concurrent import run_on_executor
from concurrent.futures import ThreadPoolExecutor
import json
import urllib
import MySQLdb


class CaptchaBotHandler(web.RequestHandler):

    executor = ThreadPoolExecutor(4)

    def render_error(self, msg, public_msg = "Unknown", code = 500):
        LOG.error(msg)
        self.render("error.html", code = str(code), msg = public_msg)
        raise gen.Return()

    @run_on_executor
    def update_db(self, key):
        LOG.debug("Updating DB")
        try:
            db = MySQLdb.connect(
                settings["db_host"],
                settings["db_user"],
                settings["db_pass"],
                settings["db_name"])
        except Exception as e:
            self.render_error("Couldn't conect to mysql: %s" % e, "db connect")

        c = db.cursor()
        try:
            c.execute("UPDATE captcha SET completed=NOW(), post_ip=%s "
                      "WHERE user_key=%s", (self.request.remote_ip, key))
            db.commit()
        except Exception as e:
            self.render_error("Mysql query failed: %s" % e, "db error")

        LOG.debug("Done updating DB")

    @gen.coroutine
    def get(self):
        LOG.info(self.request)
        if "Cf-Connecting-Ip" in self.request.headers:
            self.request.remote_ip = self.request.headers["Cf-Connecting-Ip"]
        try:    
            key = self.get_argument("key")
        except web.MissingArgumentError:
            LOG.error("Client didn't provide key")
            self.render("get_index.html")
            return
        kwargs = {
            "key": key,
            "site_key": settings["captcha_sitekey"],
            "secret": settings["captcha_secret"]
        }
        self.render("get_captcha.html", **kwargs)

    @gen.coroutine
    def post(self):
        LOG.info(self.request)
        if "Cf-Connecting-Ip" in self.request.headers:
            self.request.remote_ip = self.request.headers["Cf-Connecting-Ip"]
        try:    
            key = self.get_argument("key")
            captcha_res = self.get_argument("g-recaptcha-response")
        except web.MissingArgumentError as e:
            LOG.error("POST missing arguments: %s", e)
            self.render("post.html", captcha_success = False)
            return
        client = httpclient.AsyncHTTPClient()
        url = "https://www.google.com/recaptcha/api/siteverify"
        params = {
            "secret": settings["captcha_secret"],
            "response": captcha_res,
            "remote_ip": self.request.remote_ip
        }
        post_data = urllib.urlencode(params)
        req = httpclient.HTTPRequest(url, method = 'POST', body = post_data)
        try:
            res = yield client.fetch(req)
            if res.code != 200:
                LOG.error("Captcha returned http code %d", res.code)
                self.render("post.html", captcha_success = False)
                return
            res_data = json.loads(res.body)
            if res_data["success"] is True:
                LOG.info("Captcha success")
                self.render("post.html", captcha_success = True)
                yield self.update_db(key)
            else:
                LOG.error("Captcha returned failed status")
                self.render("post.html", captcha_success = False)
        except Exception as e:
            self.render_error("Failed post to recaptcha: %s" % e, "recaptcha")


def make_app():
    uris = [
        (r"/", CaptchaBotHandler)
    ]
    app_settings = {
        "template_loader": template.Loader("templates"),
        "static_path": "static"
    }
    return web.Application(uris, **app_settings)

# Default settings DO NOT EDIT
settings = {
    "captcha_sitekey": None,
    "captcha_secret": None,
    "db_host": None,
    "db_user": None,
    "db_pass": None,
    "db_name": None,
    "cloudflare": False
}

if __name__ == "__main__":
    LOG = logging.getLogger('captchabot-web')
    LOG.setLevel(logging.DEBUG)
    logging.basicConfig(level=logging.DEBUG)
    handler = RotatingFileHandler(
            'web.log', mode='a', maxBytes = 10*1024*1024, backupCount = 100)
    formatter = logging.Formatter(
            '%(asctime)-15s:%(levelname)-6s:%(message)s',
            '%Y.%m.%d-%I:%M:%s')
    handler.setFormatter(formatter)
    handler.setLevel(logging.DEBUG)
    LOG.addHandler(handler)

    # Override other library logging
    ROOTLOG = logging.getLogger()
    ROOTLOG.addHandler(handler)

    settings.update(json.load(open("captchabot-web.cfg", 'r')))
    LOG.info("Loaded settings")

    app = make_app()
    server = httpserver.HTTPServer(app)
    server.bind(1499)
    server.start(0)
    loop = ioloop.IOLoop.current()
    loop.start()
