from flask import Flask, request, redirect, render_template, session, flash
from mysqlconnection import MySQLConnector
import re
# imports the Bcrypt module
from flask.ext.bcrypt import Bcrypt

# check for email completeness
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "SecretKeyDont"
mysql = MySQLConnector(app, 'mydb')


@app.route('/')
def login_register():
    return render_template('index1.html')


@app.route('/login' methods=['POST'])
def login():
    # Check email
    if str(request.form['email']) == '':
        flash('Email cannot be blank', 'loginEmailError')
        pass
    elif not emailRegex.match(request.form['email']):
        flash('That combination does not exist', 'loginEmailError')
        pass
    else:
        session['email'] = str(request.form['email'])

    # Check password
    if request.form['password'] == '':
        flash('Password cannot be blank', 'loginPasswordError')
        pass
    else:
        session['password'] = str(request.form['password'])
        login_query = "SELECT * FROM users WHERE email = :email LIMIT 1"
        login_data = {'email': session['email']}
        user = mysql.query_db(login_query, login_data)
        if not user:
            flash("No combination of that user name and password exists", "red")
            return redirect('/')
        else:
            if bcrypt.check_password_hash(user[0]['password'], password):
                session['user_id'] = user[0]['id']
                return redirect('/wall')
            else:
                flash("No combination of that user name and password exists", "red")
                return redirect('/')


@app.route('/create', methods=['POST'])
def create():
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    email = request.form['email']
    password = request.form['password']
    password_confirm = request.form['password_confirm']
    pw_hash = 0
    errors = 0
    if password == password_confirm:
        pw_hash = bcrypt.generate_password_hash(password)
    if len(email) < 1:
        flash("Email cannot be blank")
        errors += 1
        pass
    elif not EMAIL_REGEX.match(email):
        flash("Invalid Email Address!")
        errors += 1
        pass
    elif len(first_name) < 1:
        flash("First name cannot be blank")
        errors += 1
        pass
    elif len(last_name) < 1:
        flash("Last name cannot be blank")
        errors += 1
        pass
    elif len(password) < 1:
        flash("Password cannot be blank")
        errors += 1
        pass
    elif password != password_confirm:
        flash("Passwords must match")
        errors += 1
        pass
    if errors > 0:
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
        flash("User was inserted!")
        return redirect('/')


@app.route('/logoff')
def logoff():
    session.pop('user_id')
    session.pop('password')
    session.pop('email')
        return redirect('/')


@app.route('/wall')
def wall():
    return render_template('/wall.html', user_id=session['user_id'], message_by_user=get_messages_by_user(), comments_by_user=get_comments_by_user(), comments_by_messages=get_comments_by_message())


def get_messages_by_user():
    get_messages = "SELECT messages.id, messages.message, messages.created_at, users.id, users.first_name, users.last_name FROM messages LEFT JOIN users ON messages.user_id = users.id ORDER BY messages.created_at DESC"
    messages = mysql.fetch(get_messages)
    return messages


def get_comments_by_user():
    get_comments = "SELECT comments.id, comments.comment, comments.created_at, users.first_name, users.last_name FROM comments LEFT JOIN messages ON comments.message_id = messages.id LEFT JOIN users ON comments.user_id = users.id ORDER BY comments.created_at DESC"
    comments = mysql.fetch(get_comments)
    return comments


def get_comments_by_message():
    # Hopefully this makes sense. I've been messing with this portion for a while
    # Set two varibles to pull the queries from the two other defs
    messages = get_messages_by_user()
    comments = get_comments_by_user()
    # Get the comment list dictionary and messages with comments list
    # initialized
    comments_list = {}
    messages_with_comments = []

    # for loop to look through it all and assign the variables to the
    # dictionary
    for comment in comments:
        info = {
            "comment_id": comment['id'],
            "created_at": comment['created_at'],
            "first_name": comment['first_name'],
            "last_name": comment['last_name'],
            "comment": comment['comment']
        }
        # if the comment id is in the list, append the comment to the
        # dictionary
        if comment['id'] in comments_list:
            comments_list[comment['id']].append(info)
        else:
            comments_list[comment['id']] = [info]
    # Same as before but this time for messages
    for message in messages:
        message_by_user = {
            "created_at": message['created_at'],
            "message_id": message['id'],
            "first_name": message['first_name'],
            "last_name": message['last_name'],
            "message": message['message']
        }
        # If the message id is in the comments list pull the comment out by the
        # id and then append it to the dictionary
        if message['id'] in comments_list:
            message_by_user['comments'] = comments_list[['id']]
        messages_with_comments.append(message_by_user)
    # return the data with it hopefully encapsulated
    return messages_with_comments

app.run(debug=True)
