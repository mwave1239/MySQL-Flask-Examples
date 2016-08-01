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
    return render_template('index.html')

@app.route('/create')
def createuser ():
    return render_template('create_user.html')

@app.route('/createuser', methods=['POST'])
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
        return redirect('/create')
    else:
        query = "INSERT INTO users (email, first_name, last_name, password, created_at, updated_at) VALUES (:email, :first_name, :last_name, :password, NOW(), NOW())"
        data = {
            'email': email,
            'first_name': first_name,
            'last_name': last_name,
            'password': pw_hash
        }
        mysql.query_db(query, data)
        flash("User was inserted!")
        return redirect('/')

@app.route('/login')
def loginuser():
    return render_template('login.html')

@app.route('/login_user', methods=['POST'])
def login():
    email = request.form['email_login']
    password = request.form['password_check']
    user_id = session['user_id']
    login_query = "SELECT * FROM users WHERE email = :email LIMIT 1"
    login_data = { 'email': email }
    user = mysql.query_db(login_query, login_data)
    if not user:
        flash("No combination of that user name and password exists", "red")
        return redirect('/login')
    else:
        if bcrypt.check_password_hash(user[0]['password'], password):
            session['user_id'] = user[0]['userid']
            session['first_name'] = user[0]['first_name']
            session['last_name'] = user[0]['last_name']
            session['email'] = user[0]['email']
            return redirect('/wall')
        else:
            flash("No combination of that user name and password exists", "red")
            return redirect('/login')


@app.route('/logoff')
def logoff():
    session.pop('user_id')
    session['first_name']
    session['last_name']
    session.pop('email')
    session['user_id'] = ''
    session['first_name'] = ''
    session['last_name'] = ''
    session['email'] = ''
    return redirect('/')


@app.route('/wall')
def wall():
    user_id = session['user_id']
    query = "SELECT * FROM users"
    users = mysql.query_db(query)
    return render_template('wall.html', messages = get_messages_by_user(), comments = get_comments_by_user(), user_id = session['user_id'], users=users)

@app.route('/wall/<user_id>')
def wall_for_others(user_id):
    friend_id = user_id
    get_messages = "SELECT messages.messageid, messages.message, messages.created_at, users.userid, users.first_name, users.last_name FROM messages LEFT JOIN users on messages.user_id = users.userid WHERE messages.user_id = {} ORDER BY messages.created_at DESC".format(friend_id)
    get_messages_data = {
        'users.id': user_id
    }
    get_comments = "SELECT comments.comment, comments.message_id, messages.messageid, comments.created_at, users.userid, users.first_name, users.last_name FROM comments LEFT JOIN messages on comments.message_id = messages.messageid LEFT JOIN users on users.userid = comments.users_userid WHERE messages.messageid = comments.message_id ORDER BY comments.created_at ASC"
    query = "SELECT * FROM users"
    return render_template('wall.html', messages = mysql.query_db(get_messages, get_messages_data), comments = mysql.query_db(get_comments), users = mysql.query_db(query), user_id = friend_id)

@app.route('/insert/message', methods=['POST'])
def insert_message():
    message = request.form['message']
    user_id = session['user_id']
    message_insert = "INSERT INTO messages (message, created_at, updated_at, user_id) VALUES(:message, NOW(), NOW(), :user_id)"
    message_data = {
        'message': request.form['message'],
        'user_id': user_id
    }
    mysql.query_db(message_insert, message_data)
    return redirect('/wall')

@app.route('/insert/comment/<messageid>', methods=['POST'])
def showcommentedit(messageid):
    comment = request.form['comment']
    message = request.form['message_id']
    user_id = session['user_id']
    comment_insert = "INSERT INTO comments (comment, created_at, updated_at, users_userid, message_id) VALUES(:comment, NOW(), NOW(), :users_userid, :messages_id)"
    comment_data = {
        'comment': comment,
        'users_userid': user_id,
        'messages_id': message
    }
    mysql.query_db(comment_insert, comment_data)
    return redirect('/wall')

@app.route('/delete/message/<messageid>')
def delete_comment(messageid):
    return render_template('delete.html', messageid=messageid)

# @app.route('/delete')
# def delete():


def get_messages_by_user():
    user_id = session['user_id']
    get_messages = "SELECT messages.messageid, messages.message, messages.created_at, users.userid, users.first_name, users.last_name FROM messages LEFT JOIN users on messages.user_id = users.userid WHERE messages.user_id = {} ORDER BY messages.created_at DESC".format(user_id)
    get_messages_data = {
        'users.id': user_id
    }
    messages = mysql.query_db(get_messages, get_messages_data)
    print messages
    return messages


def get_comments_by_user():
    user_id = session['user_id']
    get_comments = "SELECT comments.comment, comments.message_id, messages.messageid, comments.created_at, users.userid, users.first_name, users.last_name FROM comments LEFT JOIN messages on comments.message_id = messages.messageid LEFT JOIN users on users.userid = comments.users_userid WHERE messages.messageid = comments.message_id ORDER BY comments.created_at ASC"
    comments = mysql.query_db(get_comments)
    print comments
    return comments

app.run(debug=True)
