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
from admins import admins as admins

from string import letters
import hashlib
import hmac

from google.appengine.ext import webapp
from google.appengine.ext import db
import google.appengine.api.mail as mail
from secret import secret

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = \
    jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                       autoescape=True)
    
messages = \
    {'wb': "Welcome back!",
     'cbs': 'Come back soon!', 'wl': 'Welcome to the community!',
     'rd': 'Please use the buttons above to navigate!',
     'tc': 'I will be in touch soon!',
     'ts': 'Your testimonial is bring processed! Mention this '\
     'testimonial for a discount on your next order!'}
actions = {'li': 'logged in',
           'lo': 'logged out',
           'su': 'registering',
           'dl': 'deleted an item',
           'em': 'sent an email',
           't': 'left a review'}

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
        if user:
            username = user.name
        else:
            username = ''
        navTab = self.get_navTab()
        self.write(self.render_str(template, user=user, navTab=navTab, username=username, admins=admins, **kw))
        
    def debug(self, text):
        logging.info(str(text))
    
    def admin_check(self, path=""):
        """
        Checks for admin and then 
            -returns True/False
            -renders path as html file if path exists
            
        depending on redir
        """
        usr = ''
        try:
            usr = self.get_user().name.lower()
            if str(usr) in admins:
                if path:
                    self.render(path)
                else: 
                    return True
            else:
                self.debug("Not signed in as admin: {}".format(usr))
                if path:
                    self.redirect('/404')
                else:
                    return False
        except:
            if not usr:
                self.debug("No user")
            elif path:
                self.redirect('/404')
            else:
                return None
    
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
    
    def get_navTab(self):
        s = str(self.request.path)
        return s

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
        
class TestimonialDB(db.Model):
    image = db.StringProperty()
    company = db.StringProperty()
    name = db.StringProperty()
    rating = db.IntegerProperty()
    review = db.StringProperty()
    link = db.StringProperty()
    verified = db.BooleanProperty()
    created = db.DateTimeProperty(auto_now_add=True)
    
    @classmethod
    def by_id(cls, uid):
        if uid:
            return cls.get_by_id(int(uid))
        else:
            return None
    
    
    
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
        
        if head and sub and main:
            m = ModalDB(images=images,
                        mainImage=mainImage,
                        head=head,
                        sub=sub,
                        main=main,
                        cat=cat
                        )
            m._render_text()
            m.put()
            link = '/portfolio/{}/{}'.format(cat.lower(), m.key().id())
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
    def get(self, home, port_id):
        if self.get_user():
            mkey = db.Key.from_path('ModalDB', int(port_id))
            modal = db.get(mkey)
            self.render('edititem.html', modal=modal, edit=True)
        else:
            self.redirect("/login")
        
    def post(self, home, port_id):
        images = self.request.get_all('images')
        mainImage = self.request.get('mainImage')
        head = self.request.get('head')
        sub = self.request.get('sub')
        main = self.request.get('main')
        cat = self.request.get('cat')
        error = ""
        
        mkey = db.Key.from_path('ModalDB', int(port_id))
        m = db.get(mkey)
            
        if images:
            m.images = images
        if head:
            m.head = head
        if sub:
            m.sub = sub
        if main:
            m.main = main
        if mainImage:
            m.mainImage = mainImage
        m.put()
        
        link = '/portfolio/{}/{}'.format(cat, m.key().id())
        self.redirect(link)
        
        if not main or not sub or not head:
            error="Please fill out ALL required fields!"
            self.render('newitem.html',
                        images=images,
                        head=head,
                        sub=sub,
                        main=main,
                        cat=cat,
                        error=error)

class DeleteModal(Handler):
    def get(self, home, port_id):
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
        if False:
            self.redirect('/404')
        else:
            self.render('register.html')

    def post(self):
        user = self.request.get('user')
        password = self.request.get('password')
        vPassword = self.request.get('vPassword')
        error = ''

        if password == vPassword:
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
            
# ---------------------/
# --Pages-------------/
# -------------------/
    
class MainPage(Handler):
    def get(self):
        self.render("portfolio.html", multipage=True)
        
class Resume(Handler):
    def get(self):
#        cards = 
        self.render("resume.html")
        
class Store(Handler):
    def get(self):
        self.render("store.html")

class Portfolio(Handler):
    order = ["about", "logo", "web", "print", "graphics"]
    links = {
        "next": "", 
        "prev": "",
        "current": ""
    }
    
    def getLinks(self, page_cat):
        page_cat = page_cat.lower()
        current = self.order.index(page_cat)
        prv = current - 1
        nxt = current + 1
        if nxt >= len(self.order):
            nxt = 0
        self.links["next"] = self.order[nxt]
        self.links["prev"] = self.order[prv]
        self.links["current"] = self.order[current]
        return self.links["current"]
    
    def get(self, page_cat="about"):
        current = self.getLinks(page_cat)
        items = ""
        direction = self.request.get('dir')
        
        if page_cat == "about":
            pass
        else:
            items = db.GqlQuery('select * from ModalDB where cat = :1', page_cat)

        self.render('portfolio.html', items=items, direction=direction, multipage=True, links=self.links, page=page_cat)
        
class Pricing(Handler):
    def get(self):
        self.render('pricing.html')
        
    def post(self):
        name = self.request.get('name')
        rating = self.request.get('rating')
        body = self.request.get('body')
        project = self.request.get('project')
        return_address = self.request.get('email')
        sender_address = "Contact-form@website-157906.appspotmail.com"
        subj = "Testimonial Inbound!"
        
        content = str("{}\n{}\n{}\n{}\n\n{}").format(name, return_address, project, rating, body) 
        
        if name and body and rating and project and return_address:
            mail.send_mail(sender=sender_address,
                       to="Contact@KyleDiggs.com",
                       subject=subj,
                       body=content)
            self.redirect('/thanks?action=su&message=ts')
        else: 
            error="It looks like you didn't fill out one of the sections!"
            self.render('pricing.html', error=error, name=name, rating=rating, body=body, project=project, email=return_address)

class Modal(Handler):
    order = []
    links = {
        "next": "", 
        "prev": "",
        "current": ""
    }
    
    def popList(self, items):
        lst = []
        for item in items:
            lst.append(str(item.key().id()))
            
        return lst
            
    
    def getLinks(self, home, port_id):
        items = db.GqlQuery('select * from ModalDB where cat = :1', home)
        
        self.order = self.popList(items)

        current = self.order.index(port_id)
        prv = current - 1
        nxt = current + 1
        if nxt >= len(self.order):
            nxt = 0
        self.links["next"] = self.order[nxt]
        self.links["prev"] = self.order[prv]
        self.links["current"] = self.order[current]
        
        return self.links["current"]
    
    def get(self, home, port_id):
        mkey = db.Key.from_path('ModalDB', int(port_id))
        modal = db.get(mkey)
        direction = self.request.get('dir')
        links = self.getLinks(home, port_id)
        items = \
            db.GqlQuery('select * from ModalDB order by created desc limit 10'
                        )
        self.render('portfolio.html', home=home, direction=direction, multipage=True, links=self.links, port_id=int(port_id), modal=modal, items=items)
        
class Contact(Handler):
    def get(self):
        self.render('contact.html')
        
    def post(self):
        name = self.request.get('name')
        subj = self.request.get('subj')
        body = self.request.get('body')
        return_address = self.request.get('email')
        sender_address = "Contact-form@website-157906.appspotmail.com"
        content = str("{}\n{}\n\n{}").format(name, return_address, body) 
        
        if name and subj and body and return_address:
            mail.send_mail(sender=sender_address,
                       to="Contact@KyleDiggs.com",
                       subject=subj,
                       body=content)
            self.redirect('/success?action=em&message=tc')
        else:
            error = "One or more sections weren't filled out!"
            self.render('contact.html', error=error, name=name, subj=subj, body=body, email=return_address)

class Dashboard(Handler):
    def get(self):
        self.admin_check("dash.html")
            
class Testimonials(Handler):
    def get(self, TID=''):
        if self.admin_check():
            t = db.GqlQuery('select * from TestimonialDB order by created desc')
            if not TID == '':
                ts = TestimonialDB.by_id(TID)
                self.debug("Verified?: {}".format(ts.verified))
                self.render("/dash/testimonials.html", TID=TID,
                        image=ts.image, company=ts.company, name=ts.name,
                        rating=ts.rating, review=ts.review, link=ts.link,
                        verified=ts.verified, testimonials=t)
            else:
                self.render("/dash/testimonials.html", testimonials=t)
        else:
            self.redirect("/404")
        
    def post(self, TID=''):
        image = self.request.get("image")
        company = self.request.get("company")
        name = self.request.get("name")
        rating = int(self.request.get("rating"))
        review = self.request.get("review")
        link = self.request.get("link")
        verified = self.request.get("verified")
        
        if self.admin_check():
            pass
        else:
            self.redirect("/404")
            
        
        if verified == "on":
            verified = True
        else:
            verified = False
        
        if not TID == '':
            #Editing
            if company and name and rating and review:
                ts = TestimonialDB.by_id(TID)
                if image:
                    ts.image = image
                ts.company = company
                ts.name = name
                ts.rating = rating
                ts.review = review
                ts.link = link
                self.debug("Verified?: {}".format(verified))
                ts.verified = verified
                ts.put()
                
                self.redirect('/success?action=t&message=ts')
            else:
                #Error 
                error="You're missing one of the required sections!"
                self.render("/dash/testimonials.html",
                            image=image, company=company, name=name,
                            rating=rating, review=review, link=link,
                            error=error)
        elif image and company and name and rating and review:
            #Placing
            ts = TestimonialDB(image=image, company=company, name=name,
                              rating=rating, review=review, link=link,
                              verified=verified)
            ts.put()
            self.redirect('/success?action=t&message=ts')
        else:
            #Error
            error="You're missing one of the required sections!"
            self.render("/dash/testimonials.html",
                        image=image, company=company, name=name,
                        rating=rating, review=review, link=link,
                        error=error)
            
        
            
app = webapp2.WSGIApplication([
    ('/', Portfolio),
    ('/pricing', Pricing),
    ('/contact', Contact),
    ('/login', Login),
    ('/logout', Logout),
    ('/register', SignUp),
    ('/success', Success),
    ('/resume', Resume),
    ('/dashboard', Dashboard),
    ('/dashboard/testimonials', Testimonials),
    ('/dashboard/testimonials/edit/([0-9]+)', Testimonials),
    ('/portfolio/new', NewModal),
    ('/portfolio', Portfolio),
    ('/portfolio/([\w]+)/([0-9]+)', Modal),
    ('/portfolio/([\w]+)/([0-9]+)/delete', DeleteModal),
    ('/portfolio/([\w]+)/([0-9]+)/edit', EditModal),
    ('/portfolio/([\w]+)', Portfolio),
    ('/store', Store),
    ('/thanks', Thanks),
    ('/404', NotFound),
    ('/.*', NotFound)
    ], debug=True)
