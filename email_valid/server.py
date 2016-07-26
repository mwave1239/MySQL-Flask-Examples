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
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check():
    email = request.form['email']
    if len(email) < 1:
        flash("Email cannot be blank")
        return redirect('/')
    elif not EMAIL_REGEX.match(request.form['email']):
        flash("Invalid Email Address!")
        return redirect('/')
    else:
        query = "INSERT INTO emails (email_address, created_at, updated_at) VALUES (:email_address, NOW(), NOW())"
        data = {
                'email_address': request.form['email']
            }
        mysql.query_db(query, data)
        return redirect('/success')

@app.route('/success', methods=['GET'])
def success():
    query = "SELECT * FROM emails"
    email = mysql.query_db(query)
    return render_template('success.html', email=email)

@app.route('/remove', methods=['POST'])
def delete():
    email_remove = request.form['email_remove']
    query = "DELETE FROM emails WHERE email_address = :email_address"
    data = {'email_address': email_remove}
    mysql.query_db(query, data)
    return redirect('/success')

app.run(debug=True)
