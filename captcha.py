import logging
import MySQLdb

class CaptchaDB(object):

    def __init__(self, host, user, passwd, db_name):
        self.user = user
        self.passwd = passwd
        self.host = host
        self.db_name = db_name
        self.db = None
        self.cursor = None

    def connect(self):
        self.db = MySQLdb.connect(self.host, self.user, self.passwd,
                self.db_name)
        self.cursor = self.db.cursor()

    def close(self):
        self.db.close()
        self.db = None
        self.cursor = None

    def delete_old_captcha(self):
        c = self.cursor
        c.execute("DELETE FROM captcha WHERE completed = 0 AND "
                  "start < NOW() - INTERVAL 60 MINUTE")
        self.db.commit()

    def insert_captcha(self, user_key, ident_host, nick):
        c = self.cursor
        c.execute("INSERT INTO captcha (user_key,ident_host,nick) "
                  "VALUES (%s, %s, %s)", (user_key, ident_host, nick))
        self.db.commit()

    def update_captcha(self, user_key, nick):
        c = self.cursor
        c.execute("UPDATE captcha SET nick=%s, start=NOW() WHERE user_key=%s",
                  (nick, user_key))
        self.db.commit()

    def archive_solved_captchas(self):
        c = self.cursor
        c.execute("SELECT * FROM captcha WHERE completed > 0")
        if c.rowcount == 0:
            return []
        rows = c.fetchall()
        c.execute("INSERT INTO captcha_archive (user_key,ident_host,nick,"
                  "post_ip,start,completed) SELECT user_key,ident_host,nick,"
                  "post_ip,start,completed FROM captcha WHERE completed > 0")
        c.execute("INSERT INTO exceptions SELECT ident_host,user_key,"
                  "NOW(),NOW() FROM captcha WHERE completed > 0")
        c.execute("DELETE FROM captcha WHERE completed > 0")
        self.db.commit()
        return rows

    def insert_exception(self, ident_host, user_key):
        c = self.cursor
        c.execute("INSERT INTO exceptions (ident_host,user_key,last) "
                  "VALUES (%s, %s, NOW())", (ident_host, user_key))
        self.db.commit()

    def update_exception(self, ident_host):
        c = self.cursor
        c.execute("UPDATE exceptions SET last = NOW() WHERE ident_host = %s",
                  (ident_host,))
        self.db.commit()

    def add_exception(self, ident_host, user_key):
        c = self.cursor
        c.execute("INSERT INTO exceptions (ident_host, user_key, last) "
                  "VALUES (%s, %s, NOW())", (ident_host, user_key))
        self.db.commit()

    def is_excepted(self, ident_host):
        c = self.cursor
        c.execute("SELECT 1 FROM exceptions WHERE ident_host = %s LIMIT 1",
                  (ident_host,))
        if c.rowcount > 0:
            c.fetchall()
            return True
        else:
            return False
