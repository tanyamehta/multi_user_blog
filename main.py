#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import re
import random
import hashlib
import hmac
import time
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = \
    jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                       autoescape=True)
secret = 'fart12345'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class Base(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie', '%s = %s; Path = /' % (name, cookie_val))

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header(
            'Set-Cookie', 'user_id = ; Path = /')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):

    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(), name=name, pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)


EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Sign(Base):

    def get(self):
        self.render('Sign-form.html')

    def post(self):
        er = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username, email=self.email)

        if not valid_username(self.username):
            params['error_username'] = 'Username is invalid.'
            er = True
        if not valid_password(self.password):
            params['error_password'] = 'Password is invalid.'
            er = True
        elif self.password != self.verify:
            params['error_verify'] = "Password didn't match."
            er = True
        if not valid_email(self.email):
            params['error_email'] = 'Email is invalid.'
            er = True
        if er:
            self.render('Sign-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Sign):

    def done(self):
        user = User.by_name(self.username)
        if user:
            msg = 'Sorry!! The user already exists.'
            self.render('Sign-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            self.login(u)
            self.redirect('/welcome')


class Welcome(Base):

    def get(self):

        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/register')


class Login(Base):

    def get(self):
        if self.user:
            return self.redirect('/welcome')
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        user = User.login(username, password)
        if user:
            self.login(user)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(Base):

    def get(self):
        self.logout()
        self.redirect('/blog')


class Unlike(db.Model):

    uid = db.StringProperty(required=True)
    pid = db.StringProperty(required=True)

    @classmethod
    def count(cls, pi, ui):
        key = Unlike.all().filter('uid = ', ui).filter('pid = ', pi)
        return key.count()

    @classmethod
    def countLike(cls, pi):
        key = Unlike.all().filter('pid = ', pi)
        return key.count()


class Like(db.Model):

    uid = db.StringProperty(required=True)
    pid = db.StringProperty(required=True)

    @classmethod
    def count(cls, pi, ui):
        key = Like.all().filter('uid = ', ui).filter('pid = ', pi)
        return key.count()

    @classmethod
    def countLike(cls, pi):
        key = Like.all().filter('pid = ', pi)
        return key.count()


class Post(db.Model):

    title = db.StringProperty(required=True)
    art = db.TextProperty(required=True)
    user_id = db.StringProperty(required=True)
    create = db.DateTimeProperty(auto_now_add=True)


class Comment(db.Model):

    text = db.TextProperty(required=True)
    uid = db.StringProperty(required=True)
    pid = db.StringProperty(required=True)
    uname = db.StringProperty(required=True)
    time = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def com(cls, pid):
        c = Comment.all().filter('pid =', pid)
        return c

    @classmethod
    def by_author(cls, author_id):
        key = \
            db.GqlQuery(
                'select * from Comment where pid = :1 order by time desc',
                author_id)
        return key


class MainHandler(Base):

    def render_front(self):
        post = \
            db.GqlQuery('select * from Post order by create desc limit 10'
                        )
        self.render('blog.html', post=post)

    def get(self):
        self.render_front()


class NewPost(Base):

    def get(self):
        if self.user:
            self.render('login.html')
        else:
            self.redirect('/login')

    def post(self):
        if not self.user:
            return self.redirect('/login')
        title = self.request.get('title')
        art = self.request.get('art')
        error = ''

        if not title or not art:

            self.render('login.html', title=title, art=art,
                        error='Please add Both title and art and submit'
                        )
        else:

            obj = Post(title=title, art=art,
                       user_id=str(self.user.key().id()))
            obj.put()
            self.redirect('/%s' % obj.key().id())


class unlikeRecent(Base):
    def get(self, id):
        key = db.Key.from_path('Post', int(id))
        post = db.get(key)
        if not post:
            return self.redirect('/login')
        countLikes = Like.countLike(str(post.key().id()))
        countUnlikes = Unlike.countLike(str(post.key().id()))
        comment_get = db.GqlQuery(
            "select * from Comment where pid = '%s'" % str(post.key().id()))
        if not self.user:
            return self.redirect('/login')
        key = db.Key.from_path('Post', int(id))
        post = db.get(key)
        if not post:
            return self.redirect('/login')
        countLikes = Like.countLike(str(post.key().id()))
        countUnlikes = Unlike.countLike(str(post.key().id()))

        comment_get = Comment.com(str(post.key().id()))
        if not self.user:
                self.redirect("/login")

        elif post.user_id == str(self.user.key().id()):
                return self.redirect('/%s' % post.key().id())
        else:
                if Unlike.count(
                    str(post.key().id()),
                    str(
                        self.user.key().id())) == 1:

                    return self.redirect('/%s' % post.key().id())
                else:
                    obj = Unlike(
                        pid=str(post.key().id()),
                        uid=str(
                            self.user.key().id()))
                    obj.put()
                    time.sleep(0.1)
                    self.redirect("/%s" % post.key().id())


class delRecent(Base):
    def get(self, id):
        key = db.Key.from_path('Post', int(id))
        post = db.get(key)
        if not post:
            return self.redirect('/login')
        countLikes = Like.countLike(str(post.key().id()))
        countUnlikes = Unlike.countLike(str(post.key().id()))
        comment_get = db.GqlQuery(
            "select * from Comment where pid = '%s'" % str(post.key().id()))
        if not self.user:
            return self.redirect('/login')
        key = db.Key.from_path('Post', int(id))
        post = db.get(key)
        if not post:
            return self.redirect('/login')
        countLikes = Like.countLike(str(post.key().id()))
        countUnlikes = Unlike.countLike(str(post.key().id()))

        comment_get = Comment.com(str(post.key().id()))

        if self.user and (post.user_id == str(self.user.key().id())):
                post.delete()
                time.sleep(0.1)
                self.redirect('/blog')
        else:
                return self.redirect('/%s' % post.key().id())


class likeRecent(Base):
    def get(self, id):
        key = db.Key.from_path('Post', int(id))
        post = db.get(key)
        if not post:
            return self.redirect('/login')
        countLikes = Like.countLike(str(post.key().id()))
        countUnlikes = Unlike.countLike(str(post.key().id()))
        comment_get = db.GqlQuery(
            "select * from Comment where pid = '%s'" % str(post.key().id()))
        if not self.user:
            return self.redirect('/login')
        key = db.Key.from_path('Post', int(id))
        post = db.get(key)
        if not post:
            return self.redirect('/login')
        countLikes = Like.countLike(str(post.key().id()))
        countUnlikes = Unlike.countLike(str(post.key().id()))

        comment_get = Comment.com(str(post.key().id()))
        if not self.user:
                self.redirect("/login")

        elif post.user_id == str(self.user.key().id()):
                return self.redirect('/%s' % post.key().id())

        else:
                if Like.count(
                    str(post.key().id()),
                    str(
                        self.user.key().id())) >= 1:

                    return self.redirect('/%s' % post.key().id())
                else:
                    obj = Like(
                        pid=str(post.key().id()),
                        uid=str(
                            self.user.key().id()))
                    obj.put()
                    time.sleep(0.1)
                    self.redirect("/%s" % post.key().id())


class editRecent(Base):
    def get(self, id):
        key = db.Key.from_path('Post', int(id))
        post = db.get(key)
        if not post:
            return self.redirect('/login')
        countLikes = Like.countLike(str(post.key().id()))
        countUnlikes = Unlike.countLike(str(post.key().id()))
        comment_get = db.GqlQuery(
            "select * from Comment where pid = '%s'" % str(post.key().id()))
        if not self.user:
            return self.redirect('/login')
        key = db.Key.from_path('Post', int(id))
        post = db.get(key)
        if not post:
            return self.redirect('/login')
        countLikes = Like.countLike(str(post.key().id()))
        countUnlikes = Unlike.countLike(str(post.key().id()))

        comment_get = Comment.com(str(post.key().id()))
        if not self.user:
                self.redirect('/login')
        if self.user and post.user_id == str(self.user.key().id()):
                self.redirect('/edit/%s' % post.key().id())
        else:
                return self.redirect('/%s' % post.key().id())


class Recent(Base):
    def get(self, id):
        key = db.Key.from_path('Post', int(id))
        post = db.get(key)
        if not post:
            return self.redirect('/login')
        countLikes = Like.countLike(str(post.key().id()))
        countUnlikes = Unlike.countLike(str(post.key().id()))
        comment_get = \
            db.GqlQuery("select * from Comment where pid = '%s'"
                        % str(post.key().id()))
        self.render('Post1.html', post=post, countLikes=countLikes,
                    countUnlikes=countUnlikes, comment_get=comment_get)

    def post(self, id):
        if not self.user:
            self.redirect('/login')
        key = db.Key.from_path('Post', int(id))
        post = db.get(key)
        if not post:
            return self.redirect('/login')
        countLikes = Like.countLike(str(post.key().id()))
        countUnlikes = Unlike.countLike(str(post.key().id()))

        comment_get = Comment.com(str(post.key().id()))
        if self.request.get('delete'):
            return self.redirect('/delRecent/%s' % post.key().id())

        if self.request.get('edit'):
            return self.redirect('/editRecent/%s' % post.key().id())

        if self.request.get('unlike'):
            return self.redirect('/unlikeRecent/%s' % post.key().id())

        if self.request.get('like'):
            return self.redirect('/likeRecent/%s' % post.key().id())
        if self.request.get('comment'):
            if not self.user:
                self.redirect('/login')
            else:
                comment = self.request.get('comm')
                if not comment:
                    self.render(
                        'Post1.html',
                        post=post,
                        error='Cant submit a blank comment!',
                        countLikes=countLikes,
                        countUnlikes=countUnlikes,
                        comment_get=comment_get,
                        )
                else:
                    obj = Comment(text=comment,
                                  uid=str(self.user.key().id()),
                                  pid=str(post.key().id()),
                                  uname=str(self.user.name))
                    obj.put()
                    time.sleep(0.1)
                    self.redirect('/%s' % post.key().id())


class CommentEdit(Base):

    def get(self, id):
        ckey = db.Key.from_path('Comment', int(id))
        comment = db.get(ckey)
        self.render('Commentedit.html', comment=comment)

    def post(self, id):

        ckey = db.Key.from_path('Comment', int(id))
        comment = db.get(ckey)
        if not comment:
            return self.redirect('/login')
        newcomment = self.request.get('comm')
        if self.user and comment.uid == str(self.user.key().id()):
            comment.text = newcomment
            comment.put()
            time.sleep(0.1)
            self.redirect('/%s' % comment.pid)
        else:
            self.render('Commentedit.html', comment=comment,
                        error='Cant submit blank comment.')


class CommentDelete(Base):

    def get(self, id):
        ckey = db.Key.from_path('Comment', int(id))
        comment = db.get(ckey)
        if not comment:
            return self.redirect('/login')
        self.render('Commentdelete.html', comment=comment)

    def post(self, id):

        ckey = db.Key.from_path('Comment', int(id))
        comment = db.get(ckey)
        if not comment:
            return self.redirect('/login')
        newcomment = self.request.get('comm')
        if self.user and comment.uid == str(self.user.key().id()):
            comment.delete()
            time.sleep(0.1)
            self.redirect('/%s' % comment.pid)
        else:
            self.render('Commentdelete.html', comment=comment,
                        error='Cant submit blank comment.')


class Edit(Base):

    def get(self, id):
        key = db.Key.from_path('Post', int(id))
        post = db.get(key)
        self.render('edit.html', post=post)

    def post(self, id):
        key = db.Key.from_path('Post', int(id))
        post = db.get(key)
        if not post:
            return self.redirect('/login')
        title = self.request.get('title')
        art = self.request.get('art')

        if self.user and (
            post.user_id == str(
                self.user.key().id())) and title and art:
            post.title = title
            post.art = art
            post.put()
            time.sleep(0.1)
            self.redirect('/%s' % post.key().id())
        else:
            self.render('edit.html', post=post,
                        error='User cant submit blank .')


class Start(Base):
    def get(self):
        self.redirect('/blog')


app = webapp2.WSGIApplication([
    ('/', Start),
    ('/Sign', Sign),
    ('/welcome', Welcome),
    ('/register', Register),
    ('/login', Login),
    ('/logout', Logout),
    ('/blog', MainHandler),
    ('/newpost', NewPost),
    ('/([0-9]+)', Recent),
    ('/edit/([0-9]+)', Edit),
    ('/Commentedit/([0-9]+)', CommentEdit),
    ('/Commentdelete/([0-9]+)', CommentDelete),
    ('/delRecent/([0-9]+)', delRecent),
    ('/editRecent/([0-9]+)', editRecent),
    ('/likeRecent/([0-9]+)', likeRecent),
    ('/unlikeRecent/([0-9]+)', unlikeRecent)
    ], debug=True)
