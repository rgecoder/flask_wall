from flask import Flask, session, request, redirect, render_template, flash
from flask_bcrypt import Bcrypt

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


if __name__ == "__main__":
    app.run(debug=True)
