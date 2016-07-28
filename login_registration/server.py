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

@app.route('/')
def index():
    return render_template('index.html')

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
    return render_template('success.html')

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login/logincheck', methods=['POST'])
def check_login():
    email = request.form['email_login']
    password = request.form['password_check']
    login_query = "SELECT * FROM registration WHERE email = :email LIMIT 1"
    login_data = { 'email': email }
    user = mysql.query_db(login_query, login_data)
    if not user:
        flash("No combination of that user name and password exists", "red")
        return redirect('/login')
    else:
        if bcrypt.check_password_hash(user[0]['password'], password):
            session['user_id'] = user[0]['id']
            return redirect("/user/{}".format(session['user_id']))
        else:
            flash("No combination of that user name and password exists", "red")
            return redirect('/login')

@app.route('/user/<user_id>')
def user_logged(user_id):
    # Write query to select specific user by id. At every point where
    # we want to insert data, we write ":" and variable name.
    query = "SELECT * FROM registration WHERE id = {}".format(user_id)
    # Then define a dictionary with key that matches :variable_name in query.
    data = {'id': user_id}
    # Run query with inserted data.
    user = mysql.query_db(query, data)
    #update_record(friend_id)
    # Friends should be a list with a single object,
    # so we pass the value at [0] to our template under alias one_friend.
    return render_template('user.html', user = mysql.query_db(query, data))

app.run(debug=True)
