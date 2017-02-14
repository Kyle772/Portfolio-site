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
import logging
import random

from string import letters
import hashlib
import hmac

from google.appengine.ext import db
from google.appengine.api import mail
from secret import secret

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = \
    jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                       autoescape=True)
    
messages = \
    {'wb': "Welcome back!",
     'cbs': 'Come back soon!', 'wl': 'Welcome to the community!',
     'rd': 'Please use the buttons above to navigate!'}
actions = {'li': 'logged in',
           'lo': 'logged out',
           'su': 'registering',
           'dl': 'deleted an item!'}

# ---------------------/
# --Global Functions--/
# -------------------/

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)
    
class Handler(webapp2.RequestHandler):
    
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render(self, template, **kw):
        user = self.get_user()
        self.write(self.render_str(template, user=user, **kw))
        
    def debug(self, text):
        logging.info(str(text))
    
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
# --DB----------------/
# -------------------/

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
            return cls.get_by_id(int(uid)).name
        else:
            return None

    # Returns User

    @classmethod
    def by_id(cls, uid):
        if uid:
            return cls.get_by_id(int(uid))
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
        return User(name=name, pw_hash=pw_hash, exist_key=name.lower())

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

class ModalDB(db.Model):
    mainImage = db.StringProperty()
    images = db.ListProperty(item_type=str)
    head = db.StringProperty(required=True)
    sub = db.StringProperty(required=True)
    main = db.TextProperty(required=True)
    cat = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    
    def _render_text(self):
        self.main.replace('\n', '<br>')
    
    def render(self):
        self._render_text()
        return self.render('portfolio.html', modal=self)
    
    @classmethod
    def render_txt(cls, text):
        return text.replace('\n', '<br>')
        
        
class NewModal(Handler):
    def get(self):
        if self.get_user():
            self.render('newitem.html')
        else:
            error = "Sorry! You need to login to do that!"
            self.redirect("/login")
    
    def post(self):
        images = self.request.get_all('images')
        mainImage = self.request.get('mainImage')
        head = self.request.get('head')
        sub = self.request.get('sub')
        main = self.request.get('main')
        cat = self.request.get('cat')
        error = ""
        
        self.debug("checking vars")
        if head and sub and main:
            self.debug("head, sub, and main exist")
            m = ModalDB(images=images,
                        mainImage=mainImage,
                        head=head,
                        sub=sub,
                        main=main,
                        cat=cat
                        )
            m._render_text()
            m.put()
            link = '/portfolio/{}'.format(m.key().id())
            self.redirect(link)
            
        else:
            error="One of the files doesn't exist"
            self.render('newitem.html',
                        images=images,
                        mainImage=mainImage,
                        head=head,
                        sub=sub,
                        main=main,
                        cat=cat,
                        error=error)

class EditModal(Handler):
    def get(self, port_id):
        if self.get_user():
            mkey = db.Key.from_path('ModalDB', int(port_id))
            modal = db.get(mkey)
            self.render('edititem.html', modal=modal, edit=True)
        else:
            self.redirect("/login")
        
    def post(self, port_id):
        images = self.request.get_all('images')
        mainImage = self.request.get('mainImage')
        head = self.request.get('head')
        sub = self.request.get('sub')
        main = self.request.get('main')
        cat = self.request.get('cat')
        error = ""
        
        self.debug("checking vars")    
        if head and sub and main and mainImage:
            mkey = db.Key.from_path('ModalDB', int(port_id))
            m = db.get(mkey)
            m.head = head
            m.sub = sub
            m.main = main
            m.mainImage = mainImage
            m.put()
            link = '/portfolio/{}'.format(m.key().id())
            self.redirect(link)
        elif head and sub and main:
            mkey = db.Key.from_path('ModalDB', int(port_id))
            m = db.get(mkey)
            m.head = head
            m.sub = sub
            m.main = main
            m.put()
            link = '/portfolio/{}'.format(m.key().id())
            self.redirect(link)
        else:
            error="Please fill out ALL required fields!"
            self.render('newitem.html',
                        images=images,
                        head=head,
                        sub=sub,
                        main=main,
                        cat=cat,
                        error=error)

class DeleteModal(Handler):
    def get(self, port_id):
        user = self.get_user()
        if user:
            mkey = db.Key.from_path('ModalDB', int(port_id))
            modal = db.get(mkey)
            modal.delete()
            self.redirect("/success?action=dl&message=rd")
        else:
            self.redirect("/login")
            
# -----
# --Login pages
# -----
            
class SignUp(Handler):

    def get(self):
        self.render('register.html')

    def post(self):
        user = self.request.get('user')
        password = self.request.get('password')
        vPassword = self.request.get('vPassword')
        error = ''

        if password == vPassword:
            self.debug("Passwords match")
            if user:
                if User.by_name(user) or User.exist(user):
                    error = 'Username already exists. :('
                    self.render('register.html', error=error)
                elif len(password) < 8:
                    error = \
                        'Password not secure enough; please make'\
                        'it AT LEAST 8 characters!'
                    self.render('register.html', error=error)
                else:
                    u = User.register(user, password)
                    u.put()
                    user = User.login(user, password)
                    self.login(u)
                    self.redirect('/thanks?action=su&message=wl')
            else:
                error = 'Please enter a username!'
                self.render('register.html', error=error)
        else:
            error = "Passwords don't match!"
            self.render('register.html', error=error)


class Login(Handler):

    def get(self):
        self.render('login.html')

    def post(self):
        user = self.request.get('user')
        password = self.request.get('password')
        error = ''

        user = User.login(user, password)
        if user:
            self.login(user)
            self.redirect('/success?action=li&message=wb')
        else:
            error = 'Invalid login'
            self.render('login.html', error=error)


class Logout(Handler):

    def get(self):
        self.logout()
        self.redirect('/success?action=lo&message=cbs')
            
# -----
# --Redirect pages
# -----

class Thanks(Handler):

    def get(self):
        action = self.request.get('action')
        message = self.request.get('message')

        self.render('thanks.html', action=actions[action],
                    message=messages[message])


class Success(Handler):

    def get(self):
        action = self.request.get('action')
        message = self.request.get('message')
        self.render('success.html', action=actions[action],
                    message=messages[message])


class NotFound(Handler):

    def get(self):
        self.render('404.html')
        return
            
# ---------------------/
# --Pages-------------/
# -------------------/
    
class MainPage(Handler):
    def get(self):
        self.render("portfolio.html")
        
class Resume(Handler):
    def get(self):
        self.render("resume.html")

class Portfolio(Handler):
    def get(self):
        items = \
            db.GqlQuery('select * from ModalDB order by created desc limit 10'
                        )
        self.render('portfolio.html', items=items)

class Modal(Handler):
    def get(self, port_id):
        mkey = db.Key.from_path('ModalDB', int(port_id))
        modal = db.get(mkey)
        items = \
            db.GqlQuery('select * from ModalDB order by created desc limit 10'
                        )
        self.debug(items)
        self.render('portfolio.html', port_id=int(port_id), modal=modal, items=items)
        
class Contact(Handler):
    def get(self):
        self.render('contact.html')
        
    def post(self):
        subj = self.request.get('subj')
        body = self.request.get('body')
        sender_address = self.request.get('email')
        
        mail.send_mail(sender=sender_address,
                   to="Contact@KyleDiggs.com",
                   subject=subj,
                   body=body)

app = webapp2.WSGIApplication([
    ('/', Portfolio),
    ('/contact', Contact),
    ('/login', Login),
    ('/logout', Logout),
    ('/register', SignUp),
    ('/success', Success),
    ('/resume', Resume),
    ('/portfolio', Portfolio),
    ('/portfolio/([0-9]+)', Modal),
    ('/portfolio/new', NewModal),
    ('/portfolio/([0-9]+)/delete', DeleteModal),
    ('/portfolio/([0-9]+)/edit', EditModal),
    ('/thanks', Thanks)
    ], debug=True)
