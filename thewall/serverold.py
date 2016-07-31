from flask import Flask, request, redirect, render_template, session, flash
from mysqlconnection import MySQLConnector
import re
# imports the Bcrypt module
from flask.ext.bcrypt import Bcrypt

#check for email completeness
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "SecretKeyDont"
mysql = MySQLConnector(app, 'mydb')

def get_messages_by_user():
    get_messages = "SELECT messages.id, messages.message, messages.created_at, users.id, users.first_name, users.last_name FROM messages LEFT JOIN users ON messages.user_id = users.id ORDER BY messages.created_at DESC"
    messages = mysql.fetch(get_messages)
    return messages

def get_comments():
    get_comments = "SELECT comments.id, comments.comment, comments.created_at, users.first_name, users.last_name FROM comments LEFT JOIN messages ON comments.message_id = messages.id LEFT JOIN users ON comments.user_id = users.id"
    comments = mysql.fetch(get_comments)
    return comments

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login/logincheck', methods=['POST'])
def check_login():
    #Check email
    if str(request.form['email']) == '':
        flash('Email cannot be blank', 'loginEmailError')
        pass
    elif not emailRegex.match(request.form['email']):
        flash('That combination does not exist', 'loginEmailError')
        pass
    else:
        session['email'] = str(request.form['email'])

    #Check password
    if request.form['password'] == '':
        flash('Password cannot be blank', 'loginPasswordError')
        pass
    else:
        session['password'] = str(request.form['password'])
        login_query = "SELECT * FROM users WHERE email = :email LIMIT 1"
        login_data = { 'email': session['email'] }
        user = mysql.query_db(login_query, login_data)
        if not user:
            flash("No combination of that user name and password exists", "red")
            return redirect('/')
        else:
            if bcrypt.check_password_hash(user[0]['password'], password):
                session['user_id'] = user[0]['id']
                return redirect("/user/{}".format(session['user_id']))
            else:
                flash("No combination of that user name and password exists", "red")
                return redirect('/')

@app.route('/register', methods=['POST'])
def register():
    first_name=request.form['first_name']
    last_name=request.form['last_name']
    email=request.form['email']
    password=request.form['password']
    password_confirm=request.form['password_confirm']
    pw_hash=0
    if password == password_confirm:
        pw_hash = bcrypt.generate_password_hash(password)
    if len(email) < 1:
        flash("Email cannot be blank")
        return redirect('/')
    elif not EMAIL_REGEX.match(email):
        flash("Invalid Email Address!")
        return redirect('/')
    elif len(first_name) < 1:
        flash("First name cannot be blank")
        return redirect('/')
    elif len(last_name) < 1:
        flash("Last name cannot be blank")
        return redirect('/')
    elif len(password) < 1:
        flash("Password cannot be blank")
        return redirect('/')
    elif password != password_confirm:
        flash("Passwords must match")
        return redirect('/')
    else:
        query = "INSERT INTO registration (email, first_name, last_name, password, created_at, updated_at) VALUES (:email, :first_name, :last_name, :password, NOW(), NOW())"
        data = {
                'email': email,
                'first_name': first_name,
                'last_name': last_name,
                'password': pw_hash
            }
        mysql.query_db(query, data)
        return redirect('/success')

@app.route('/success')
def success():
    return render_template('login.html')


@app.route('/create')
def create_user():
    return render_template('create_user.html')

@app.route('/user/<user_id>')
def user_logged(user_id):
    #query = "SELECT * FROM users WHERE id = {}".format(user_id)
    query_wall = "SELECT users.*, comments.*, messages.* FROM users JOIN comments ON users.id = comments.user_id JOIN comments AS comments_messages messages.id = comments.message_id JOIN messages ON users.id = messages.user_id WHERE users.id = {}".format(user_id)
    # Then define a dictionary with key that matches :variable_name in query.
    #data = {'id': user_id}
    data_wall = {'users.id': user_id}
    # Run query with inserted data.
    user = mysql.query_db(query_wall, data_wall)
    print user
    return render_template('index.html', user = mysql.query_db(query, data))

@app.route('/logoff')
def reset():
	session.pop('user_id')
	return redirect('/')

@app.route('/login')
def login():
    return render_template('login.html')


app.run(debug=True)
