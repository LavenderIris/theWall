from flask import Flask, render_template, request, redirect, flash, session
import os, binascii, re, md5
from mysqlconnection import MySQLConnector
app = Flask(__name__)
mysql = MySQLConnector(app,'mydb')

app.secret_key = "ThisIsSecret!2"
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
NO_NUM_REGEX = re.compile(r'.*[0-9]+.*')
PASSWORD_VALID_L_N_REGEX=re.compile(r'.*[A-Z]+.*\d+.*')
PASSWORD_VALID_N_L_REGEX=re.compile(r'.*\d+.*[A-Z].*')
ALL_LETTERS_REGEX = re.compile(r'[A-Za-z]+')

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/logoff')
def log_off():
    session.clear()
    session['logged_in']=False
    return redirect('/')

@app.route('/register', methods=['POST'])
def isValid():

    print "Request form",request.form
    # check if we have content
    
    data = {
        'first_name':  request.form['first_name'],
        'last_name':  request.form['last_name'],
        'email': request.form['email'],
        'password': request.form['password'],
        'confirm_password': request.form['confirm_password']
    }
    # next step, let's go and salt and hash password later for storage
    flash_error = False

    # check for blank
    if len(data['first_name'])<=2:
        flash("First name doesn't have enough letters", "ERROR: invalid first name")
        print 'NOT ENOUGH LETTERS FIRST NAME'
        flash_error = True
    else: # something there to check
        if not (ALL_LETTERS_REGEX.match(data['first_name'])):
            flash("First Name is not all letters", "ERROR: invalid entry")
            flash_error = True
    if len(data['last_name'])==0:
        flash("Last name doesn't have enough letters","ERROR: invalid last name")
        flash_error = True
    else: # something there to check
        if not (ALL_LETTERS_REGEX.match(data['last_name'])):
            flash("Last Name is not all letters", "ERROR: invalid entry")
            flash_error = True
    if len(data['password'])==0:
        flash("Password is blank","ERROR: blank entry")
        flash_error = True
    elif len(data['password'])<=8:
        flash("Password needs to be more than 8 characters", "ERROR: Invalid password")
        flash_error = True
    elif len(data['password']) >8:
        #check if the password and confirm password match
        if (data['password']!=data['confirm_password']):
            flash("Passwords do not match", "ERROR: Passwords do not match")
            flash_error = True
        # check if the password is valid
        if not (PASSWORD_VALID_L_N_REGEX.match(data['password'])) and not (PASSWORD_VALID_N_L_REGEX.match(data['password'])) :
            flash("Password needs at least one uppercase letter and number",'ERROR: Invalid password' )
            flash_error = True
    if len(data['confirm_password'])==0:
        flash("Confirm Password is blank","ERROR: blank entry")
        flash_error = True
    if len(data['email'])==0:
        flash("Email is blank","ERROR: blank entry")
        flash_error = True
    else:  # there is something there to check
        if not ( EMAIL_REGEX.match(data['email']) ):
            flash("invalid email", "ERROR: invalid entry")
            flash_error = True
    
   
    # let's check for duplicate emails in our system
    if flash_error == False:
        my_query = 'SELECT * FROM users WHERE email=:email'
        results = mysql.query_db(my_query, data)
       
        if (len(results)>0):
            flash("Invalid input"," ERROR: invalid input")
            flash_error = True
           
    print "let's get here", flash_error
    # no errors, so let's redirect to the wall
    if (flash_error == False):
        print "success!"
        salt = binascii.b2a_hex(os.urandom(15))
        hashed_pw = md5.new(data['password'] + salt).hexdigest()
        data['salt']= salt
         # here's the encrypted password
        data['password']=hashed_pw
        data['salt']=salt

        # My query to insert
        query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at, salt) VALUES (:first_name,:last_name, :email, :password, NOW(), NOW(), :salt)"
        mysql.query_db(query, data)
        print "Salt, hashed_password", salt, hashed_pw

        return redirect('/')

    return redirect('/')

@app.route('/login', methods=['POST'])
def login():
    mydata = { 'email': request.form['email'],
               'password': request.form['password']}
    print "form", request.form
    query = "SELECT * FROM users WHERE email=:email"
    result =  mysql.query_db(query, mydata)

    print "result", result
    # no results
    if len(result)==0:
        flash("Login not found in our records", "ERROR: Record doesn't exist")
        return redirect('/') 
    # we assume we get only one result because only entry per email
    print "RESULT SALT", result[0]['salt']

    # test if the emails we have on file are the same
    test_password = md5.new(mydata['password'] + result[0]['salt']).hexdigest()
    if test_password == result[0]['password']:
        print "Passwords match"
        session['logged_in']=True
        # print "RESULTS SO FAR", result[0]
        session['user_id']=result[0]['id']
        session['first_name']=result[0]['first_name']
        session['last_name']=result[0]['last_name']
        session['email']=result[0]['email']
        session['created_at']=result[0]['created_at']
        return redirect('/show_board')
    else :
        print "FAIL"
        flash("Passwords do not match our records", "ERROR: incorrect password")
    
    return redirect('/')

@app.route('/show_board')
def show_board():
    query = "SELECT messages.id, CONCAT(users.first_name,' ' ,users.last_name) AS full_name, messages.message, DATE_FORMAT(messages.updated_at, '%m %d %Y %l:%i %p') AS updated_at FROM messages JOIN users ON messages.user_id=users.id ORDER BY messages.updated_at DESC"
    results = mysql.query_db(query)
    query = "SELECT comments.message_id, CONCAT(users.first_name,' ' ,users.last_name) AS full_name, comments.comment, DATE_FORMAT(comments.updated_at, '%m %d %Y %l:%i %p') AS updated_at FROM comments JOIN users ON comments.user_id=users.id ORDER BY comments.updated_at ASC"
    comments  = mysql.query_db(query)
  
    return render_template('messageboard.html',  all_messages = results, all_comments = comments)



@app.route('/add_message', methods=['POST'])
def add_message():
    # need to display the messages below
    data = {
        'message': request.form['message'],
        'user_id':session['user_id']
    }
    query = 'INSERT INTO messages (user_id, message, created_at, updated_at) VALUES (:user_id, :message, NOW(), NOW() )'
    mysql.query_db(query, data)   
    return redirect('/show_board')

@app.route('/add_comment', methods=['POST'])
def add_comment():
   
    data = {
        'comment': request.form['comment'],
        'message_id': request.form['message_id'],
        'user_id': session['user_id']
    }
    query = 'INSERT INTO comments (message_id, user_id, comment, created_at, updated_at) VALUES (:message_id, :user_id, :comment, NOW(), NOW() )'
    mysql.query_db(query, data)
    return redirect('/show_board')

app.run(debug=True)