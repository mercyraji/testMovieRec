from flask import Flask, render_template, url_for, flash, redirect, request
#from forms import RegistrationForm
#from flask_sqlalchemy import SQLAlchemy
#from datetime import datetime
#from werkzeug.security import generate_password_hash, check_password_hash
#from flask_login import LoginManager, UserMixin, login_user, current_user, login_required, logout_user
import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = 'YOUR_SECRET_KEY'
"""
"""

"""login_manager = LoginManager()
login_manager.init_app(app)

class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(40), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(128), unique=True, nullable=False)
    signup_date = db.Column(db.String, default=datetime.now().strftime("%Y-%m-%d %H:%M:%S"), nullable=False)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"


@login_manager.user_loader
def loader_user(user_id):
    return Users.query.get(user_id)"""


@app.route('/')
def home():
    return "home"
    #render_template('home.html', title='Home')

# using the registration form, if registration successful, store user data into user db
@app.route('/sign-up', methods=['GET','POST'])
def sign_up():
    """form = RegistrationForm()
    if form.validate_on_submit():
        signup_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        username = form.username.data
        email = form.email.data
        password = form.password.data
        hashed_password = generate_password_hash(password)

        user = Users(username=username, password=hashed_password, email=email, signup_date=signup_date)
        db.session.add(user)
        db.session.commit()

        flash(f'Account created for {username}!', 'success')
        return redirect(url_for('log-in'))"""

    return "sign up"
    #render_template('signup.html', title='Sign Up', form=form)

@app.route("/log-in", methods=['GET','POST'])
def log_in():
    """if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # fetch user from database
        user = Users.query.filter_by(username=request.form.get("username")).first()

        if user and check_password_hash(user.password, password):
            # correct credentials, log in successfuly
            login_user(user)
            flash(f"Welcome back, {username}!", 'success')
            return redirect(url_for('home'))
        
        flash('Login failed. Check your username and/or password.', 'danger')"""
    return "log in"
    #render_template('login.html', title='Login')


"""@app.route("/log-out")
@login_required 
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for("home"))"""


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")