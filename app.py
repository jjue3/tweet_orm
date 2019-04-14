from flask import Flask, render_template, request, redirect, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy.sql import func	
from flask_bcrypt import Bcrypt
import re
 
app = Flask(__name__)
app.secret_key = 'secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///twitter.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
email_rex = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
name_rex = re.compile(r'^[a-zA-Z]+$')    
password_rex = re.compile(r'^(?=.*[\d])(?=.*[A-Z])(?=.*[a-z])(?=.*[@#$])[\w\d@#$]{6,24}$')

twitter = db.Table('twitter',
    db.Column('users_id', db.Integer, db.ForeignKey('users.id'), primary_key=True),
    db.Column('tweets_id', db.Integer, db.ForeignKey('tweets.id'), primary_key=True))     

class Users(db.Model):			
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(255))
    last_name = db.Column(db.String(255))
    email = db.Column(db.String(255))
    password = db.Column(db.String(555))
    created_at = db.Column(db.DateTime, server_default=func.now()) 
    updated_at = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now())
    tweets_from_user = db.relationship('Tweets', secondary=twitter, backref='users_who_tweet', cascade='all')

class Tweets(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, server_default=func.now())  
    updated_at = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now())    
    users_who_tweeted = db.relationship('Users', secondary=twitter, backref='tweet_from_users', cascade='all')

@app.route('/') #Renders Login Page
def index():
    return render_template('index.html')    

@app.route('/', methods=['POST']) #Registration page
def registration():
    is_valid = True
    # mysql = connectToMySQL('reg')       
    # query = 'SELECT * FROM users WHERE email=%(email)s;'
    # data = {
    #     "email" : request.form['email']
    # }
    # existing_email = mysql.query_db(query, data)
    if len(request.form['first_name']) < 2 or not name_rex.match(request.form['first_name']): #Check to see if first name is long enough or if it has a number
        is_valid = False
        flash("Please enter your first name")
        return redirect('/')
    if len(request.form['last_name']) < 2 or not name_rex.match(request.form['last_name']): #Check to see if last name is long enough or if it has a number
        is_valid = False
        flash("Please enter your last name")
        return redirect('/')
    if not email_rex.match(request.form['email']): #Check if the email has the requirements
        is_valid = False
        flash("Please enter an email")
        return redirect('/')        
    # if existing_email: #Check if the email exists in the database
    #     is_valid = False
    #     flash("Email already in use")
    #     # print('false')
    #     return redirect('/')
    if not password_rex.match(request.form['password']): #Checks if passward has more than 6 characters, has symbols @#$, and has a capital
        is_valid = False
        flash("Please enter a password")
        return redirect('/')
    if request.form['password'] != request.form['passwordc']: #Check if the confirmation password matches the entered password
        is_valid = False
        flash("Password does not match") 
        return redirect('/')
    if is_valid: #addes to the database
        flash("Successfully added!")
        passwordhash = bcrypt.generate_password_hash(request.form['password'])
        new_instance_of_a_user = Users(
            first_name = request.form["first_name"],
            last_name = request.form["last_name"],
            email = request.form["email"],
            password = passwordhash)
        db.session.add(new_instance_of_a_user)
        db.session.commit()
        return redirect('/dashboard')    
    
#         mysql = connectToMySQL('reg')         
#         query = "INSERT INTO reg.users (first_name, last_name, email, password, created_at) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s, NOW());"
#         userlog = mysql.query_db(query, data)
#         db.session['email']= request.form['email']
#         db.session['name'] = request.form['first_name']
#         session['id']= userlog
#         return redirect('/dashboard')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if len(request.form['email'])<1: #Checks if anything there is anything in the email field
        flash("Please enter email")
        return redirect('/')
    if len(request.form['password'])<1: #Checks if anything there is anything in the password field
        flash("Please enter password")
        return redirect('/')
    request_email = request.form['email']
    passwordhash = bcrypt.generate_password_hash(request.form['password'])
    print(passwordhash)
    print('LOOOOOOOOOOOOOOOOOOOOK HERE')
    registered_user = Users.query.filter_by(email=request_email, password=passwordhash).first()
    print(registered_user)
    print('THHHHHHHHIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIS')
    if registered_user is None:
        flash("Email/Password is incorrect")
        return redirect('/')      
    else:
        return redirect('/dashboard')      
#     mysql = connectToMySQL('reg')       
#     query = 'SELECT * FROM users WHERE email=%(email)s;'
#     data = {
#         "email" : request.form['email']
#         }
#     query_result = mysql.query_db(query, data)
    # if not query_result: #Checks if there is anything in the database   
    #     flash('Email/Password is incorrect')
    #     return redirect('/')
#     pw_hash = query_result[0]["password"]
#     password_check = bcrypt.check_password_hash(pw_hash,request.form['password'])
#     if query_result: #Checks if it matches the database
#         if password_check:
#             session['name'] = query_result[0]["first_name"]
#             session['id'] = query_result[0]["id"]
#             # print(session['name'])
#             return redirect('/dashboard')


# @app.route('/tweets/<tweets_id>/add_like', methods=['POST']) #Add likes
# def addlike(tweets_id):
#     session['tweets_id']= tweets_id
#     mysql = connectToMySQL('reg')  
#     query = 'SELECT * FROM likes WHERE user_id =%(user_id)s AND tweet_id =%(tweet_id)s;'    
#     data = {
#         "user_id" : session['id'],
#         "tweet_id" : session['tweets_id']
#         }  
#     creater_id = mysql.query_db(query, data)
#     if creater_id:
#         return redirect('/dashboard') 
#     else:
#         mysql = connectToMySQL('reg')       
#         query = "INSERT INTO likes (user_id, tweet_id, created_at) VALUES (%(user_id)s, %(tweet_id)s, NOW());"
#         data = {
#             "user_id" : session['id'],
#             "tweet_id" : session['tweets_id']
#             }
#         mysql.query_db(query, data)
#         return redirect('/dashboard')


# @app.route('/tweets/<tweets_id>/delete', methods=['GET','POST']) #Deletes Messages
# def delete(tweets_id):
#     session['tweets_id']= tweets_id
#     mysql = connectToMySQL('reg')  
#     query = 'SELECT * FROM tweets WHERE user_id =%(user_id)s AND id =%(id)s;'    
#     data = {
#         "user_id" : session['id'],
#         "id" : session['tweets_id']
#         }  
#     creater_id = mysql.query_db(query, data)
#     if creater_id:
#         mysql = connectToMySQL('reg')
#         query = 'DELETE FROM tweets WHERE user_id =%(user_id)s AND id =%(id)s;'
#         data = {
#         "user_id" : session['id'],
#         "id" : session['tweets_id']
#         }  
#         mysql.query_db(query, data)        
#         flash("Deleted Post")
#         return redirect('/dashboard')
#     else:
#         flash("Not your tweet")    
#         return redirect('/dashboard')  

@app.route('/tweets/<tweets_id>/edit', methods=['GET','POST']) #Renders Edit Page
def edit(tweets_id):
#     name = session['name']
#     session['tweets_id']= tweets_id
#     tweets_id = session['tweets_id']
#     mysql = connectToMySQL('reg')  
#     query = 'SELECT * FROM tweets WHERE user_id =%(user_id)s AND id =%(id)s;'    
#     data = {
#         "user_id" : session['id'],
#         "id" : session['tweets_id']
#         }  
#     creater_id = mysql.query_db(query, data)
#     if creater_id:
#         return render_template('edit.html', tweets_id=tweets_id, name=name)
#     else:
#         flash("Not your tweet")    
        return redirect('/dashboard') 

@app.route('/tweets/<tweets_id>/update', methods=['GET','POST']) #Update Message
def update(tweets_id):
#     session['tweets_id']= tweets_id
#     # print(session['tweets_id'])
#     # print('wooooooooooooooow')
#     # print(tweets_id)
#     if len(request.form['message'])>255 or len(request.form['message'])<1:
#         flash('Invalid amount of characters')
#         return redirect('/tweets/<tweets_id>/edit')
#     else:
#         # print("This is working now aren't you happy!!!!!!!")
#         mysql = connectToMySQL('reg')
#         query = 'UPDATE tweets SET content =%(content)s, updated_at = NOW() WHERE id =%(id)s;'
#         data = {
#             "content" : request.form['message'],
#             "id" : session['tweets_id']
#             }  
#         mysql.query_db(query, data)        
#         flash("Edit Post")
        return redirect('/dashboard')

# @app.route('/tweets/<users_id>/follow', methods=['GET','POST'])
# def follows(users_id):
#     session['followee'] = users_id
#     session['follower'] = session['id']
#     mysql = connectToMySQL('reg')  
#     query = 'SELECT * FROM followers WHERE follower_id =%(follower_id)s AND followee_id =%(followee_id)s;'    
#     data = {       
#         "follower_id" : session['follower'],
#         "followee_id" : session['followee']
#         }  
#     following = mysql.query_db(query, data)
#     if following:
#         flash('Already following')
#         # print('I AMMMMMMMM RUNNING')
#         return redirect('/dashboard') 
#     else:
#         mysql = connectToMySQL('reg')       
#         query = "INSERT INTO followers (follower_id, followee_id, created_at) VALUES (%(follower_id)s, %(followee_id)s, NOW());"
#         data = {
#             "follower_id" : session['follower'],
#             "followee_id" : session['followee']
#             }
#         mysql.query_db(query, data)
#         flash('Followed!')
#         return redirect('/dashboard')


@app.route('/logout') #Clears the session
def logout():
    session.clear()
    # print(session)
    return redirect('/')         

@app.route('/dashboard') #Displays all messages
def dashboardren(): 
    # name = session['name']
    # session['followee'] = users_id
    # session['follower'] = session['id']
#     mysql = connectToMySQL('reg')  
#     query = 'SELECT * FROM followers WHERE follower_id =%(follower_id)s AND followee_id =%(followee_id)s;'    
#     data = {       
#         "follower_id" : session['follower'],
#         "followee_id" : session['followee']
#         }  
#     following = mysql.query_db(query, data)
#     if following:
#         mysql = connectToMySQL('reg') 
#         query = 'SELECT * FROM tweets WHERE user_id =%(user_id)s AND user_id =%(user_id)s ORDER BY id DESC;'    
#         data = {       
#         "user_id" : session['follower'],
#         "user_id" : session['followee']
#         } 
#         tweets = mysql.query_db(query, data)  
#         return render_template('dashboard.html', tweets = tweets, name = name)
  
# @app.route('/tweets/create', methods=['POST']) #Creates and posts messages in the database
# def createpost():
#     if len(request.form['message'])>255 or len(request.form['message'])<1:
#         flash('Invalid amount of characters')
#         return redirect('/dashboard')
#     else: 
#         new_instance_of_a_tweet = Tweet(
#             message = request.form["message"]) 
#         db.session.add(new_instance_of_a_tweet)
#         db.session.commit()   
#         mysql = connectToMySQL('reg')       
#         query = "INSERT INTO tweets (content, user_id, created_at) VALUES (%(content)s, %(user_id)s, NOW());"
#         data = {
#             "content" : request.form["message"],
#             "user_id" : session['id']
#             }
#         mysql.query_db(query, data)
#         # print(session['id'])
#         # print(request.form['message'])
        flash('Posted!')
        return redirect('/dashboard')

@app.route('/users') #renders all users page
def userslist():
    list_of_all_user_as_user_instances = User.query.all()
    users = list_of_all_user_as_user_instances
    return render_template('users.html', users = users, name = name)    

# @app.route('/dashboard')
# def arelogged():        
#     if not session['name']:
#         return redirect('/')
#     else:    
#         return redirect('/dashboard')
    
if __name__ == "__main__":
    app.run(debug=True)
