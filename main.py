#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import webapp2
import jinja2
import random

import hashlib
import hmac

from string import letters

from google.appengine.ext import db

secret = 'D98SwsNVCbL6ZT?'

messages = \
    {'wb': "Welcome back! Be sure to comment on my posts"
     "if you have anything to say! I'd love to hear from you!",
     'cbs': 'Come back soon!', 'wl': 'Welcome to the community!'}
actions = {'li': 'logged in',
           'lo': 'logged out',
           'su': 'registering'}

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = \
    jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                       autoescape=True)


# ---------------------/
# --Global Functions--/
# -------------------/

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


def users_key(group='default'):
    return db.Key.from_path('users', group)


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


# -----
# --Security functions
# -----

def make_secure(val):
    return '{}-{}'.format(val, hmac.new(secret, val).hexdigest())


def check_secure(secure_val):
    val = secure_val.split('-')[0]
    if secure_val == make_secure(val):
        return val


# -----
# --Pw_hash
# -----

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '{}-{}'.format(salt, h)


def make_salt(length=5):
    for x in xrange(length):
        return ''.join(random.choice(letters))


# -----
# --pw_checking
# -----

def valid_pw(name, password, h):
    salt = h.split('-')[0]
    return h == make_pw_hash(name, password, salt)


# ---------------------/
# --Handler-----------/
# -------------------/

class BlogHandler(webapp2.RequestHandler):

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render(self, template, **kw):

        # Always pass u-id with render if cookie exists

        uid = self.read_cookie('user-id')
        self.write(self.render_str(template, user=User.name_by_id(uid),
                   **kw))

    # -----
    # --Cookie Handling
    # -----

    def make_cookie(self, name, val):
        cookie = make_secure(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '{}={}; Path=/'.format(name, cookie)
        )

    def read_cookie(self, name):
        cookie = self.request.cookies.get(name)
        if cookie and check_secure(cookie):
            cookie_val = cookie.split('-')[0]
            return cookie_val

    # -----
    # --Authentication
    # -----

    def get_user(self):
        return User.by_id(self.read_cookie('user-id'))

    def login(self, user):
        self.make_cookie('user-id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header(
            'Set-Cookie',
            'user-id=; Path=/')


# ---------------------/
# --db.Models---------/
# -------------------/

class Post(db.Model):

    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    user = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    likes = db.IntegerProperty(default=0)

    def _render_text(self):
        self.content.replace('\n', '<br>')

    def render(self, user):
        self._render_text()
        return render_str('post.html', post=self, user=user)


class Comment(db.Model):

    user = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    content = db.StringProperty(required=True, multiline=True)
    post_id = db.IntegerProperty()

    def _render_text(self):
        self.content.replace('\n', '<br>')

    def render(self, user):
        self._render_text()
        return render_str('comment.html', user=user, comment=self)


class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()
    exist_key = db.StringProperty()
    liked_posts = db.ListProperty(int)

    # Returns actual username from id

    @classmethod
    def name_by_id(cls, uid):
        if uid:
            return cls.get_by_id(int(uid), parent=users_key()).name
        else:
            return None

    # Returns User

    @classmethod
    def by_id(cls, uid):
        if uid:
            return cls.get_by_id(int(uid), parent=users_key())
        else:
            return None

    # Returns User

    @classmethod
    def by_name(cls, name):
        user = cls.all().filter('name =', name).get()
        return user

    # Returns Bool for existing name using exist_key

    @classmethod
    def exist(cls, name):
        exist = cls.all().filter('exist_key =', name.lower()).get()
        if exist:
            return True
        else:
            return False

    # Returns User class to register with

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(), name=name, pw_hash=pw_hash,
                    email=email, exist_key=name.lower())

    # Returns user if password matches

    @classmethod
    def login(cls, name, pw):
        user = cls.by_name(name)
        if user and valid_pw(name, pw, user.pw_hash):
            return user
        else:
            return None

    # Reads user-id and returns name

    @classmethod
    def current(cls):
        uid = self.read_cookie('user-id')
        return User.name_by_id(uid)


# ---------------------/
# --Pages-------------/
# -------------------/

class MainPage(BlogHandler):

    def get(self):
        posts = \
            db.GqlQuery('select * from Post order by created desc limit 10'
                        )
        self.render('home.html', posts=posts)


class BlogHome(BlogHandler):

    def get(self):
        posts = \
            db.GqlQuery('select * from Post order by created desc limit 10'
                        )
        self.render('home.html', posts=posts)


class PostPage(BlogHandler):

    def get(self, post_id):
        query = \
            'select * from Comment where post_id={} order by created'\
            'desc limit 10'.format(int(post_id))

        pkey = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(pkey)
        comments = db.GqlQuery(query)

        if not post:
            self.redirect("/404")
            return
        else:
            post.link = '/blog/{}'.format(post_id)

        self.render('singlepost.html', post_id=post_id, post=post,
                    comments=comments)

    def post(self, post_id):
        query = \
            'select * from Comment where post_id={} order by created'\
            'desc limit 10'.format(int(post_id))

        content = str(self.request.get('comText'))
        name = self.get_user().name
        error = ''
        pkey = db.Key.from_path('Post', int(post_id), parent=blog_key())

        if content and name:
            c = Comment(parent=blog_key(), user=name, content=content,
                        post_id=int(post_id))
            c.put()

            comments = db.GqlQuery(query)
            post = db.get(pkey)

            self.render('singlepost.html', post=post, comments=comments)
        else:
            comments = db.GqlQuery(query)
            post = db.get(pkey)
            error = "You can't submit an empty comment!"
            self.render('singlepost.html', post=post,
                        comments=comments, error=error)


class NewPost(BlogHandler):

    def get(self):
        self.render('newpost.html')

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content').replace('\n', '<br>')
        user = self.get_user()

        if subject and content and user:
            p = Post(parent=blog_key(), user=user.name, subject=subject,
                     content=content)
            p.put()
            link = '/blog/{}'.format(p.key().id())

            self.redirect(link)
        elif user is None:
            self.redirect('/login')
        else:
            error = 'Subject and content, please!'
            self.render('newpost.html', subject=subject,
                        content=content, error=error)


# -----
# --Login pages
# -----

class SignUp(BlogHandler):

    def get(self):
        self.render('signup.html')

    def post(self):
        user = self.request.get('user')
        password = self.request.get('password')
        vPassword = self.request.get('vPassword')
        email = self.request.get('email')
        error = ''

        if password == vPassword:
            if user:
                if User.by_name(user) or User.exist(user):
                    error = 'Username already exists. :('
                    self.render('signup.html', userf=user,
                                emailf=email, errorf=error)
                elif len(password) < 8:
                    error = \
                        'Password not secure enough; please make'\
                        'it AT LEAST 8 characters!'
                    self.render('signup.html', userf=user,
                                emailf=email, errorf=error)
                else:
                    u = User.register(user, password, email)
                    u.put()
                    user = User.login(user, password)
                    self.login(u)
                    self.redirect('/thanks?action=su&message=wl')
            else:
                error = 'Please enter a username!'
                self.render('signup.html', userf=user, emailf=email,
                            errorf=error)
        else:
            error = "Passwords don't match!"
            self.render('signup.html', userf=user, emailf=email,
                        errorf=error)


class Login(BlogHandler):

    def get(self):
        self.render('login.html')

    def post(self):
        user = self.request.get('userf')
        password = self.request.get('passwordf')
        error = ''

        user = User.login(user, password)
        if user:
            self.login(user)
            self.redirect('/success?action=li&message=wb')
        else:
            error = 'Invalid login'
            self.render('login.html', userf=user, errorf=error)


class Logout(BlogHandler):

    def get(self):
        self.logout()
        self.redirect('/success?action=lo&message=cbs')


# -----
# --Redirect pages
# -----

class Thanks(BlogHandler):

    def get(self):
        action = self.request.get('action')
        message = self.request.get('message')

        self.render('thanks.html', action=actions[action],
                    message=messages[message])


class Success(BlogHandler):

    def get(self):
        action = self.request.get('action')
        message = self.request.get('message')
        self.render('success.html', action=actions[action],
                    message=messages[message])


class NotFound(BlogHandler):

    def get(self):
        self.render('404.html')
        return

# -----
# --Comment Action Handlers
# -----


class EditComment(BlogHandler):

    def get(self, com_id):
        ckey = db.Key.from_path('Comment', int(com_id),
                                parent=blog_key())
        comment = db.get(ckey)

        # Check if comment exists then redirect if not
        if not comment:
            self.redirect('/404')
            return

        link = '/blog/' + str(comment.post_id)
        content = comment.content
        self.render('editcom.html', comment=content, link=link)

    def post(self, com_id):
        ckey = db.Key.from_path('Comment', int(com_id),
                                parent=blog_key())
        comment = db.get(ckey)

        # Check if comment exists then redirect if not
        if not comment:
            self.redirect('/404')
            return

        comment.content = self.request.get('comText')
        link = '/blog/' + str(comment.post_id)

        try:
            user = User.by_id(self.read_cookie('user-id'))

            # Check if user exists and redirect if not
            if user is None:
                self.redirect('/404')
                return

            if user.name == comment.user:
                comment.put()
                self.redirect(link)
            else:
                error = \
                    "Sorry you aren't the original commenter! "\
                    "Stop trying to hack people bro!"
                self.render('editcom.html', comment=comment,
                            error=error)
        except:
            self.redirect(link)


class DeleteComment(BlogHandler):

    def get(self, com_id):
        ckey = db.Key.from_path('Comment', int(com_id),
                                parent=blog_key())
        comment = db.get(ckey)

        # Check if comment exists then redirect if not
        if not comment:
            self.redirect('/404')
            return

        self.render('verify.html', comment=comment)

    def post(self, com_id):
        response = self.request.get('response')
        ckey = db.Key.from_path('Comment', int(com_id),
                                parent=blog_key())
        comment = db.get(ckey)

        # Check if comment exists then redirect if not
        if not comment:
            self.redirect('/404')
            return

        link = '/blog/' + str(comment.post_id)

        try:
            user = User.by_id(self.read_cookie('user-id'))

            # Check if user exists and redirect if not
            if user is None:
                self.redirect('/404')
                return

            if user.name == comment.user:
                comment.delete()
                self.redirect(link)
            else:
                self.redirect(link)
        except:
            self.redirect(link)


# -----
# --Post Action Handlers
# -----

class EditPost(BlogHandler):

    def get(self, post_id):
        pkey = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(pkey)

        # Check if post exists and redirect if not
        if post is None:
            self.redirect('/404')
            return

        link = '/blog/' + post_id
        content = post.content
        self.render('editpost.html', content=content, link=link)

    def post(self, post_id):
        pkey = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(pkey)

        # Check if post exists and redirect if not
        if post is None:
            self.redirect('/404')
            return

        post.content = self.request.get('postText')
        post.content = post.content.replace('\n', '<br>')
        link = '/blog/' + post_id

        try:
            user = User.by_id(self.read_cookie('user-id'))

            # Check if user exists and redirect if not
            if user is None:
                self.redirect('/404')
                return

            if user.name == post.user:
                post.put()
                self.redirect(link)
            else:
                error = \
                    "Sorry you aren't the original poster! "\
                    "Stop trying to hack people bro!"
                self.render('editpost.html', content=content,
                            error=error)
        except:
            self.redirect(link)


class DeletePost(BlogHandler):

    def get(self, post_id):
        pkey = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(pkey)

        # Check if post exists and redirect if not
        if post is None:
            self.redirect('/404')
            return

        self.render('deletepost.html', post=post)

    def post(self, post_id):
        response = self.request.get('response')
        pkey = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(pkey)

        # Check if post exists and redirect if not
        if post is None:
            self.redirect('/404')
            return

        link = '/blog'

        try:
            user = User.by_id(self.read_cookie('user-id'))

            # Check if user exists and redirect if not
            if user is None:
                self.redirect('/404')
                return

            if user.name == post.user:
                post.delete()
                self.redirect(link)
            else:
                self.redirect(link)
        except:
            self.redirect(link)


class LikePost(BlogHandler):

    def get(self, post_id):
        pkey = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(pkey)
        user = self.get_user()
        liked = user.liked_posts
        link = '/blog/' + post_id

        if user.name == post.user:
            self.render("whoops.html")
            return

        # Checks whether or not user has already liked post
        if not int(post_id) in liked:
            user.liked_posts.append(int(post_id))
            post.likes += 1
            post.put()
            user.put()
        elif int(post_id) in liked:
            user.liked_posts.remove(int(post_id))
            post.likes -= 1
            post.put()
            user.put()

        self.redirect(link)


app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/login', Login),
    ('/logout', Logout),
    ('/signup', SignUp),
    ('/thanks', Thanks),
    ('/success', Success),
    ('/blog', BlogHome),
    ('/blog/newpost', NewPost),
    ('/blog/([0-9]+)', PostPage),
    ('/blog/([0-9]+)/edit', PostPage),
    ('/comment/edit/([0-9]+)', EditComment),
    ('/comment/delete/([0-9]+)', DeleteComment),
    ('/blog/edit/([0-9]+)', EditPost),
    ('/blog/delete/([0-9]+)', DeletePost),
    ('/blog/like/([0-9]+)', LikePost),
    ('/404', NotFound)
    ], debug=True)
