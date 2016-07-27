from flask import Flask, request, redirect, render_template, session, flash
from mysqlconnection import MySQLConnector
import re

#check for email completeness
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')

app = Flask(__name__)
app.secret_key = "SecretKeyDont"
mysql = MySQLConnector(app, 'mydb')

@app.route('/')
def index():
    query = "SELECT * FROM full_friends"
    friends = mysql.query_db(query)
    return render_template('index.html', friends=friends)

@app.route('/friends', methods=['POST'])
def create():
    email = request.form['email']
    first_name = request.form['first_name']
    last_name = request.form['last_name']
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
    else:
        query = "INSERT INTO full_friends (email, first_name, last_name, created_at, updated_at) VALUES (:email, :first_name, :last_name, NOW(), NOW())"
        data = {
                'email': email,
                'first_name': first_name,
                'last_name': last_name
            }
        mysql.query_db(query, data)
        return redirect('/')

@app.route('/user/<friend_id>/edit', methods=['GET'])
def edit(friend_id):
    # Write query to select specific user by id. At every point where
    # we want to insert data, we write ":" and variable name.
    query = "SELECT * FROM full_friends WHERE id = {}".format(friend_id)
    # Then define a dictionary with key that matches :variable_name in query.
    data = {'id': friend_id}
    # Run query with inserted data.
    friends = mysql.query_db(query, data)
    #update_record(friend_id)
    # Friends should be a list with a single object,
    # so we pass the value at [0] to our template under alias one_friend.
    return render_template('/edit.html', friends = mysql.query_db(query, data))

@app.route('/edit/<friend_id>', methods=['POST'])
def update_record(friend_id):
    query = "UPDATE full_friends SET email=:email, first_name=:first_name, last_name=:last_name, updated_at=NOW() WHERE id = {}".format(friend_id)
    data = {
            'email': request.form['email'],
            'first_name': request.form['first_name'],
            'last_name': request.form['last_name']
        }
    mysql.query_db(query, data)
    return redirect('/')

@app.route('/user/<friend_id>/delete', methods=['POST'])
def destroy(friend_id):
    query = "DELETE FROM full_friends WHERE id = {}".format(friend_id)
    data = {'id': friend_id}
    mysql.query_db(query, data)
    return redirect('/')

app.run(debug=True)
