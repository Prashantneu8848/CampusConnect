import flask
from flask import Flask
from flask import render_template, flash, redirect
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import sessionmaker
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired
from config import Config
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.debug = True
app.config.from_object(Config)
engine = create_engine('sqlite:///database.db', echo=True)
Base = declarative_base()
Session = sessionmaker(bind=engine)
bcrypt = Bcrypt(app)

app.config.update(dict(
    SECRET_KEY="powerful secretkey",
    WTF_CSRF_SECRET_KEY="a csrf secret key"
))

with app.app_context():
    flask.username = ''


class User(Base):
    __tablename__ = 'users'

    firstname = Column(String)
    lastname = Column(String)
    username = Column(String, primary_key=True)
    phone = Column(String)
    major = Column(String)
    password = Column(String)

    def __repr__(self):
        return "<User(name='%s', lastname='%s', phone ='%s')>" % (
            self.name, self.lastname, self.phone)

class Login(Base):
    __tablename__ = 'login'

    username = Column(String, primary_key=True)
    password = Column(String)

    def __repr__(self):
        return "<User(username='%s', password='%s')>" % (
            self.username, self.password)

Base.metadata.create_all(engine)

@app.route('/')
def mainpage():
    session = Session()
    with app.app_context():
        if flask.username:
            #Find user information

            user = session.query(User).filter_by(username=flask.username).first()

            flask.user = user
            return render_template('base.html', title='Main', firstname=user.firstname, lastname=user.lastname)
        else:
            return redirect('/login')




class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    session = Session()
    if form.validate_on_submit():
        # Query the database based on the username and password
        old_login = session.query(Login).filter_by(username=form.username.data).first()

        if old_login:

            if bcrypt.check_password_hash(old_login.password, form.password.data):

                with app.app_context():
                    flask.username = form.username.data
                    return redirect('/')

    return render_template('login.html', title='Sign In', form=form)

class SignUpForm(FlaskForm):
    firstname = StringField('firstname', validators=[DataRequired()])
    lastname = StringField('lastname', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    password = StringField('Password', validators=[DataRequired()])
    phone = StringField('Phone', validators=[DataRequired()])
    major = StringField('Major', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

@app.route('/signup', methods=['GET','POST'])
def SignUp():
    form = SignUpForm()
    session = Session()
    if form.validate_on_submit():
        # Query the database to post the information
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, firstname=form.firstname.data, password=hashed_password,
                        lastname=form.lastname.data, phone=form.phone.data, major=form.major.data)
        new_login = Login(username=form.username.data, password=form.password.data)
        session.add(new_user)
        session.add(new_login)
        try:
            session.commit()
        except:
            return redirect('/signup')

        success = True

        if success:
            with app.app_context():
                flask.username = form.username.data
            return redirect('/')
 
    return render_template('signup.html', title='Sign Up', form=form)


class SearchForm(FlaskForm):
    firstname = StringField('firstname')
    lastname = StringField('lastname')
    major = StringField('Major')
    submit = SubmitField('Search')


@app.route('/search', methods=['GET','POST'])
def Search():
    form = SearchForm()
    session = Session()
    if form.validate_on_submit():
        # Query the database to post the information
        form_major = form.major.data
        form_name = form.firstname.data
        form_lastname = form.lastname.data

        users = session.query(User)
        if form_name:
            users = users.filter_by(firstname=form_name)
        elif form_lastname:
            users = users.filter_by(lastname=form_lastname)
        else:
            users = users.filter_by(major=form_major)
        
        users_string = ''
        for user in users:
            users_string = users_string + user.firstname + ' '
        return users_string
    return render_template('search.html', title='Search', form=form)
