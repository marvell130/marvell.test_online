from flask import Flask, render_template, redirect, url_for, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.secret_key = 'Secret Key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:''@localhost/logindb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class tb_user(UserMixin, db.Model):
    user_id = db.Column(db.Integer, primary_key= True)
    user_name = db.Column(db.String(40), unique = True)
    first_name = db.Column(db.String(40), unique = True)
    last_name = db.Column(db.String(40), unique = True)
    email_account = db.Column(db.String(40), unique = True)
    user_password = db.Column(db.String(50), unique = True)
    def get_id(self):
        return (self.user_id)

@login_manager.user_loader
def load_user(email_account):
    return tb_user.query.get(email_account)

class LoginForm(FlaskForm):
    email_account = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=40)])
    user_password = PasswordField('Password', validators=[InputRequired(), Length(max=50)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
   email_account = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=40)])
   user_name = StringField('Username', validators=[InputRequired(), Length(min=4, max=40)])
   first_name = StringField('Firstname', validators=[InputRequired(), Length(min=4, max=40)])
   last_name = StringField('Lastname', validators=[InputRequired(), Length(min=4, max=40)])
   user_password = PasswordField('Password', validators=[InputRequired(), Length(max=50)])

@app.route('/')
def main():
    return render_template("index.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = tb_user.query.filter_by(email_account=form.email_account.data).first()
        if user:
            if user.user_password == form.user_password.data:
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))
        return redirect(url_for('main'))
    return render_template("login.html", form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = tb_user(email_account=form.email_account.data, user_name=form.user_name.data,
                         first_name=form.first_name.data, last_name=form.last_name.data, user_password=form.user_password.data)
        db.session.add(user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template("register.html", form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    all_data = tb_user.query.all()
    return render_template("dashboard.html", user=all_data, name=current_user.user_name)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main'))

if __name__ == "__main__":
    app.run(debug=True)