from flask import Flask, session, request, redirect, render_template, flash
from flask_bcrypt import Bcrypt
from mysqlconnection import connectToMySQL

import re
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-copy9._-]+\.[a-zA-Z]+$')

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = 'secretkey'


def debugHelp(message=""):
    print("/n/n----------", message, "--------------")
    print("request.form: ", request.form)
    print("session: ", session)


@app.route('/')
def index():
    return render_template("login_reg.html")


@app.route('/register', methods=['POST'])
def register():
    error = False
    mysql = connectToMySQL('wall')
    query = "SELECT * FROM users WHERE email = %(email)s;"
    data = {
        'email': request.form['email'],
    }
    check = mysql.query_db(query, data)

    if len(request.form['name']) < 1:
        flash("Name cannot be blank!", "register")
        error = True

    if len(request.form['email']) < 1:
        flash("Email cannot be blank!", "register")
        error = True
    elif not EMAIL_REGEX.match(request.form['email']):
        flash("Email format is invalid!", "register")
        error = True

    if len(request.form['password']) < 1:
        flash("Password cannot be blank!", "register")
        error = True
    elif request.form['password'] != request.form['password_cf']:
        flash("Passwords must match!", "register")
        error = True
    
    if check:
      flash("User is already registered!",'register')
      return redirect('/')

    if error == True:
        return redirect('/')

    if error == False:
        pw_hash = bcrypt.generate_password_hash(request.form['password'])

        mysql = connectToMySQL('wall')
        query = 'INSERT INTO users (name, email, password, created_at, updated_at) VALUES (%(name)s, %(email)s, %(pw_hash)s, NOW(), NOW());'
        data = {
            'name': request.form['name'],
            'email': request.form['email'],
            'pw_hash': pw_hash,
        }
        user_id = mysql.query_db(query, data)
        session['logged_status'] = True
        session['id'] = user_id
        session['name'] = request.form['name']

        return redirect('/home')


@app.route('/home', methods=['GET', 'POST'])
def home():
    if session['logged_status'] == True:
        mysql = connectToMySQL('wall')
        query = "SELECT users.name, users.id, messages.message, messages.user_id FROM users JOIN messages ON users.id = messages.user_id WHERE users.id = %(user_id)s"
        data ={
            'user_id': session['id']
        }
        messages = mysql.query_db(query,data)
        print(messages)
        return render_template('home.html', messages=messages)
    else:
        flash("You are not logged in!", 'login')
        return redirect('/')


@app.route('/login', methods=['POST'])
def login():
    mysql = connectToMySQL('wall')
    query = "SELECT * FROM users WHERE email = %(email)s;"
    data = {
        'email': request.form['email'],
    }
    result = mysql.query_db(query, data)
   
    print (session)

    if result:
        if bcrypt.check_password_hash(result[0]['password'], request.form['password']):
            session['logged_status'] = True
            session['id'] = result[0]['id']
            session['name'] = result[0]['name']
            

            
            return redirect('/home')
        else:
            flash('Invalid password!', 'login')
            return redirect('/')
    else:
        flash('User does not exist', 'login')
        return redirect('/')


@app.route('/logout')
def logout():
    session.clear()
    flash("you have logged out!", 'login')
    return redirect("/")

@app.route('/create_message', methods=['POST'])
def create_message():
    message_text = request.form['message']
    query = "INSERT INTO messages (message, created_at, updated_at, user_id) VALUES (%(message_text)s, NOW(), NOW(), %(user_id)s)"
    data = {
        'message_text': message_text,
        'user_id': request.form['recipient_id']
    }
    mysql = connectToMySQL('wall')
    mysql.query_db(query,data)
    return redirect('/home')


if __name__ == "__main__":
    app.run(debug=True)
