from flask import Flask, render_template,redirect,url_for,request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField,TextAreaField,SubmitField
from wtforms.validators import InputRequired,Email,Length
from wtforms.fields.html5 import DateField
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import LoginManager , UserMixin ,login_user,login_required,logout_user,current_user
from flask_mail import Mail,Message
from validate_email import validate_email
import string
import random
import smtplib



app = Flask(__name__)
app.config['SECRET_KEY'] = "thisisrescuemission"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'bvenkataprudhvi@gmail.com'
app.config['MAIL_PASSWORD'] = '8008921412'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

Bootstrap(app)
db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin ,db.Model):
	id = db.Column(db.Integer,primary_key = True)
	username  = db.Column(db.String(15),unique =True)
	email = db.Column(db.String(50),unique=True)
	password = db.Column(db.String(80))
	

class Slam(db.Model):
	id = db.Column(db.Integer,primary_key = True)
	urname = db.Column(db.String(30))
	Myname =db.Column(db.String(30))
	Mymail = db.Column(db.String(50))
	Birthday =db.Column(db.Date,index = True)
	Memmom = db.Column(db.String(10000))
	Likes = db.Column(db.String(5000))
	Dontlikes = db.Column(db.String(10000))
	Aboutme = db.Column(db.String(10000))


db.create_all()
db.session.commit()


@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))



class LoginForm(FlaskForm):
	username = StringField('username',validators = [InputRequired() , Length(min = 4,max = 15)])
	password = PasswordField('password', validators = [ InputRequired(), Length(min =8 , max = 80)])
	#remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
	email  = StringField('email',validators = [InputRequired() , Email( message = 'Invalid Mail') , Length(max = 50)])
	username = StringField('username',validators = [InputRequired() , Length(min = 4,max = 15)])
	#password = PasswordField('password', validators = [ InputRequired(), Length(min =8 , max = 80)])

class SlamForm(FlaskForm):
	urname = StringField('Writing For',validators=[InputRequired()])
	Myname = StringField('Myname', validators=[InputRequired()])
	Mymail = StringField('Mymail', validators=[InputRequired() ,Email('invalid mail') ])
	Birthday = DateField('Birthday',format ='%Y-%m-%d')
	Memmom = TextAreaField('Memorable moments', validators=[InputRequired()])
	Likes = TextAreaField('Likes',validators=[InputRequired()])
	Dontlikes = TextAreaField('Don`t likes',validators=[InputRequired()])
	Aboutme = TextAreaField('Aboutme',validators=[InputRequired()])


class ChangeMail(FlaskForm):
	oldmail  = StringField('oldmail',validators = [InputRequired() , Email( message = 'Invalid Mail') , Length(max = 50)])
	newmail = StringField('newmail',validators = [InputRequired() , Email( message = 'Invalid Mail') , Length(max = 50)])

class ChangePassword(FlaskForm):
	oldpassword = StringField('oldpassword',validators = [InputRequired() , Length(min = 8,max = 80)])
	newpassword = StringField('newpassword',validators = [InputRequired() , Length(min = 8,max = 80)])

class ForgotPassword(FlaskForm):
	username = StringField('username',validators = [InputRequired() , Length(min = 4,max = 15)])

""""
class SendTheMail:
	@staticmethod
	def send_email(user, pwd, recipient, subject, body):
		gmail_user = user
		gmail_pwd = pwd
		FROM = user
		TO = recipient if type(recipient) is list else [recipient]
		SUBJECT = subject
		TEXT = body
		# Prepare actual message
		message = '''From: %s\nTo: %s\nSubject: %s\n\n%s
		'''% (FROM, ", ".join(TO), SUBJECT, TEXT)
		try:
			server = smtplib.SMTP("smtp.gmail.com", 587)
			server.ehlo()
			server.starttls()
			server.login(gmail_user, gmail_pwd)
			server.sendmail(FROM, TO, message)
			server.close()
			print 'successfully sent the mail'
		except:
			print "failed to send mail"

"""

class checkslams:
	@staticmethod
	def _no():
		_for_len = Slam.query.filter_by(urname =current_user.username).all()
		_slams = len(_for_len)
		return _slams
		

class QuerySlams:
	@staticmethod
	def query():
		_query_data  = Slam.query.filter_by(urname =current_user.username).all()
		return _query_data

class RandomPassGen:
	@staticmethod
	def id_generator(size=10, chars=string.ascii_uppercase + string.digits):
		return ''.join(random.choice(chars) for _ in range(size))



@app.route('/login' , methods = ['GET','POST'])
def login():
	form = LoginForm()

	if form.validate_on_submit():
		user = User.query.filter_by(username = form.username.data).first()
		err= ''
		if user:
			if form.password.data == user.password:#check_password_hash(user.password ,form.password.data ):
				login_user(user)
				return redirect(url_for('index'))
			else:
				return render_template('login.html', form = form,err = "invalid password")

		return render_template('login.html',form = form , err = 'invalid username')

	return render_template('login.html',form = form)



@app.route('/signup', methods = ['GET','POST'])
def signup():
	form = RegisterForm()

	if form.validate_on_submit():
		err= ''
		#hashed_password = generate_password_hash(form.password.data , method = 'sha256')
		validate = User.query.filter_by(username = form.username.data).first()
		another_validate = User.query.filter_by(email = form.email.data).first()
		if validate:
			return render_template('signup.html',form = form,err = 'user already exists, try another name')
		elif another_validate:
			return render_template('signup.html',form = form,Aerr = 'Mail already Exists')
		else:
			randpasssign = RandomPassGen.id_generator()
			msg = Message('SlamBook Password', sender = 'bvenkataprudhvi@gmail.com', recipients = [form.email.data])
			new_user  = User(username = form.username.data,email = form.email.data,password = randpasssign)
			db.session.add(new_user)
			msg.body = "Password"
			msg.html = "<h3 style = 'color:blue'>The password you Requested For is :<span style='color:red'><strong>%s</span></h3><br><h3><strong>please Login</strong><span><a href = 'http://127.0.0.1:5000/login' style = 'text-decoration:none'>click here</a></span</h3>"%randpasssign
			mail.send(msg)
			db.session.commit()
			return redirect(url_for('login'))

	return render_template('signup.html',form = form)



@app.route('/slambook', methods =['GET','POST'])
def slambook():
	form = SlamForm()
	if request.method == 'POST':

		if form.validate_on_submit():
			naya_user = Slam(urname = form.urname.data,Myname = form.Myname.data,Mymail = form.Mymail.data,Birthday = form.Birthday.data,Memmom = form.Memmom.data,Likes = form.Likes.data,Dontlikes = form.Dontlikes.data,Aboutme = form.Aboutme.data)
			db.session.add(naya_user)
			db.session.commit()
			return render_template('thankyou.html')
	else:
		if request.args:
			form.urname.data = request.args.get('urname')
			return render_template('form.html',form = form)
	return render_template('form.html',form = form)


@app.route('/')
@app.route('/index')
@login_required
def index():
	_slams = checkslams._no()
	slamurl = "127.0.0.1:5000/slambook?urname=%s" %current_user.username
	return render_template('index.html',count = _slams ,name = current_user.username,slamurl = slamurl)

	

@app.route('/dashboard')
@login_required
def dashboard():
	intels = QuerySlams.query()
	_no_of_slams = len(intels)
	return render_template('dashboard.html',intels = intels,name = current_user.username,count = _no_of_slams)




@app.route('/myprofile')
@login_required
def myprofile():
	slamcount = checkslams._no()
	return render_template('profile.html', name = current_user.username, count = slamcount)





@app.route('/ChangeMail' , methods = ['GET', 'POST'])
@login_required
def Changemail():
	intels = QuerySlams.query()
	_no_of_slams = len(intels)
	form = ChangeMail()
	if form.validate_on_submit():
		user = User.query.filter_by(username = current_user.username).first()
		if not User.query.filter_by(email = form.newmail.data).first():
			if user.username == current_user.username and user.email == form.oldmail.data:
				user.email = form.newmail.data
				db.session.commit()
				return render_template('ChangeMail.html',form = form,msg = "mail successfully updated",name = current_user.username,count = _no_of_slams)
			else:
				return render_template('ChangeMail.html',form = form, Anmsg = "Sorry ! Wrong old mail or already existed",name = current_user.username,count = _no_of_slams)
		else:
			return render_template('ChangeMail.html',form = form, Anmsg = "Sorry ! Wrong old mail or already existed",name = current_user.username,count = _no_of_slams)

	return render_template('ChangeMail.html',form =form,name = current_user.username,count = _no_of_slams)



@app.route('/ChangePassword',methods = ['GET', 'POST'])
@login_required
def Changepassword():
	intels = QuerySlams.query()
	_no_of_slams = len(intels)
	form = ChangePassword()
	if form.validate_on_submit():
		user = User.query.filter_by(username = current_user.username).first()
		if form.oldpassword.data == user.password: #check_password_hash(user.password ,form.oldpassword.data ):
			#hashed_password = generate_password_hash(form.newpassword.data , method = 'sha256')
			user.password = form.newpassword.data
			db.session.commit()
			return render_template('ChangePassword.html', form =form, msg = 'password changed successfully',name = current_user.username,count = _no_of_slams)
		else:
			return render_template('ChangePassword.html', form =form, Anmsg = 'Sorry! Wrong old password',name = current_user.username,count = _no_of_slams)

		
	return render_template('ChangePassword.html', form =form,name = current_user.username,count = _no_of_slams)



@app.route('/events')
@login_required
def events():
	bday_ev = QuerySlams.query()
	slamcount = checkslams._no()
	return render_template('events.html',name = current_user.username,count = slamcount,event_data = bday_ev)



@app.route('/forgotpass',methods = ['GET','POST'])
def forgotpass():
	form = ForgotPassword()
	if form.validate_on_submit():
		user = User.query.filter_by(username = form.username.data).first()
		if user and user.username:
			randpass = RandomPassGen.id_generator()
			print randpass
			msg = Message('SlamBook Password', sender = 'bvenkataprudhvi@gmail.com', recipients = [user.email])
			user.password = randpass
			db.session.commit()
			msg.body = "Password"
			msg.html = "<h3 style = 'color:blue'>The password you Requested For is :<span style='color:red'><strong>%s</span></h3><br><h3><strong>please Login</strong><span><a href = 'http://127.0.0.1:5000/login' style = 'text-decoration:none'>click here</a></span</h3>"%randpass

			mail.send(msg)
			return render_template('forgotpass.html',form = form,msg = 'Mail has been Sent to your registered Mail')
		else:
			return render_template('forgotpass.html',form = form,Anmsg = "User Didnt Exist")

	return render_template('forgotpass.html',form =form)


@app.errorhandler(404)
def own_404_page(error):
	return redirect(url_for('errorhandle'))

@app.route('/errorhandle')
def errorhandle():
	return render_template('errorhandle.html')


@app.route('/logout')
def logout():
	logout_user()
	return redirect(url_for('login'))



    app.run(debug=True)
