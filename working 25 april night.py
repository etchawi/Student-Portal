import os
from flask import Flask, jsonify, request, render_template, redirect, url_for, flash, session, make_response, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_login import current_user, login_required, UserMixin, LoginManager
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, set_access_cookies
from flask_mail import Mail, Message
from dotenv import load_dotenv
from flask_wtf import CSRFProtect, FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, Email, EqualTo
from itsdangerous.url_safe import URLSafeTimedSerializer as Serializer
from datetime import timedelta
from flask_migrate import Migrate 
import smtplib
from email.mime.text import MIMEText
import logging
logging.basicConfig(level=logging.DEBUG)


# Initialize Flask application
app = Flask(__name__)
load_dotenv()

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///website_data.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'super_secret_key')
app.config['MAIL_SERVER']='live.smtp.mailtrap.io'
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 2525))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'api'
app.config['MAIL_PASSWORD'] = '50bf68a46d0e635f38b2471d4dde5801'
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'another_super_secret_key')
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_ACCESS_COOKIE_NAME'] = 'access_token_cookie'
app.config['JWT_ACCESS_COOKIE_PATH'] = '/'
app.config['JWT_REFRESH_COOKIE_NAME'] = 'refresh_token_cookie'
app.config['JWT_REFRESH_COOKIE_PATH'] = '/'
app.config['JWT_COOKIE_CSRF_PROTECT'] = True
app.config['JWT_COOKIE_SECURE'] = False
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_SECRET_KEY'] = 'a_csrf_secret_key'
if os.getenv('FORCE_HTTP'):
    app.config['PREFERRED_URL_SCHEME'] = 'http'

# Extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
csrf = CSRFProtect(app)
mail = Mail(app)


# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(255), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(100), nullable=False)
    zip_code = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    def get_reset_token(self, expires_sec=1800):
        """
        Generates a reset token with an expiration time.
        """
        s = Serializer(app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token, max_age=1800):
        """
        Verifies the reset token and returns the user associated with it if valid and not expired.
        """
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token, max_age=max_age)
            return User.query.get(data['user_id'])
        except:
            return None

class Textbook(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    author = db.Column(db.String(255), nullable=False)
    isbn = db.Column(db.String(20), nullable=True)
# Add book details
with app.app_context():
    db.create_all()
    # Create instances of Textbook model with book details
    book1 = Textbook(title='Book Title 1', author='Author 1', isbn='ISBN1')
    book2 = Textbook(title='Book Title 2', author='Author 2', isbn='ISBN2')
    book3 = Textbook(title='Book Title 3', author='Author 3', isbn='ISBN3')

    # Add instances to the database session
    db.session.add(book1)
    db.session.add(book2)
    db.session.add(book3)

    # Commit changes to the database
    db.session.commit()


class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    textbook_id = db.Column(db.Integer, db.ForeignKey('textbook.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    
class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    address = StringField('Address', validators=[DataRequired()])
    city = StringField('City', validators=[DataRequired()])
    state = StringField('State', validators=[DataRequired()])
    zip_code = StringField('Zip Code', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class UpdateUserForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    address = StringField('Address', validators=[DataRequired()])
    city = StringField('City', validators=[DataRequired()])
    state = StringField('State', validators=[DataRequired()])
    zip_code = StringField('Zip Code', validators=[DataRequired()])
    email = StringField('Email address', validators=[DataRequired(), Email()])
    username = StringField('Login name', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Update')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


    
class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

def generate_token():
    secret_key = 'your-secret-key'  # This should be your actual secret key
    s = Serializer(secret_key, salt='any-string-salt')
    token = s.dumps({'user_id': 123}).decode('utf-8')  # Use a test user ID
    return token

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request', sender='mailtrap@demomailtrap.com', recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_request', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)
    
@app.route('/send-mail')
def send_mail():
    msg = Message("Hello from Flask Mail",
                  sender="mailtrap@demomailtrap.com",  # This should be a generic sender address
                  recipients=["hesham.txst@gmail.com"])  # Update this to your test recipient address
    msg.body = "This is a test email sent from a Flask application using Mailtrap."
    try:
        mail.send(msg)
        return "Email sent successfully!"
    except Exception as e:
        return str(e)

# Routes

@app.route('/')
def home():
    return redirect(url_for('login'))



@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():  # Checks if the form submission is a POST and if it is valid
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('User with this email already exists.', 'error')
            return render_template('register.html', form=form)

        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(
            first_name=form.first_name.data, 
            last_name=form.last_name.data,
            address=form.address.data, 
            city=form.city.data, 
            state=form.state.data, 
            zip_code=form.zip_code.data,
            email=form.email.data, 
            password_hash=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        flash('User registered successfully.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request', sender='mailtrap@demomailtrap.com', recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}
If you did not make this request then simply ignore this email and no changes will be made.'''
    mail.send(msg)


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_reset_email(user)
            flash('An email has been sent with instructions to reset your password.', 'info')
        else:
            flash('No account with that email. You must register first.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)

@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)



@app.route('/some_form', methods=['GET', 'POST'])
def some_form():
    form = SomeForm()
    if form.validate_on_submit():
        # process the form
        return redirect(url_for('success'))
    return render_template('your_form_template.html', form=form)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            access_token = create_access_token(identity=user.email)
            session['user_name'] = user.first_name  # Make sure this is refreshed on login
            response = make_response(redirect(url_for('dashboard')))
            set_access_cookies(response, access_token)
            return response
        else:
            flash('Invalid credentials, please register', 'error')
    return render_template('login.html', form=form)



@app.route('/dashboard')
@jwt_required()
def dashboard():
    current_user_email = get_jwt_identity()
    user = User.query.filter_by(email=current_user_email).first()
    print("Current user fetched:", user.first_name)  # Check if this prints the updated name
    return render_template('dashboard.html', current_user=user)


@app.route('/textbooks/search', methods=['GET'])
def search_textbooks():
    search_query = request.args.get('search_query')
    print(f"Search Query: {search_query}")  # Debug print
    
    search_results = []
    if search_query:
        search_results = Textbook.query.filter(
            (Textbook.title.ilike(f'%{search_query}%')) | 
            (Textbook.author.ilike(f'%{search_query}%')) |
            (Textbook.isbn.ilike(f'%{search_query}%'))
        ).all()
        
        print(f"Search Results: {search_results}")  # Debug print

    return render_template('search_textbooks.html', search_results=search_results)

# Refreshing access token using a refresh token
@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    new_token = create_access_token(identity=current_user, fresh=False)
    return jsonify({'access_token': new_token}), 200



@app.route('/update_user/<int:user_id>', methods=['GET', 'POST'])
@jwt_required()
def update_user(user_id):
    user = User.query.get_or_404(user_id)  # Retrieves user or returns 404 if not found
    form = UpdateUserForm(obj=user)  # Initialize form with user's data

    if request.method == 'POST':
        print("CSRF Token from form:", form.csrf_token.data)  # Log CSRF token received

    if form.validate_on_submit():  # Check if the form submission is valid
        user.first_name = form.first_name.data
        user.last_name = form.last_name.data
        user.address = form.address.data
        user.city = form.city.data
        user.state = form.state.data
        user.zip_code = form.zip_code.data
        user.email = form.email.data

        # Check if a password change is intended and process it
        if form.password.data:
            user.password_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        try:
            db.session.commit()  # Commit changes to the database
            flash('User updated successfully!', 'success')
            return redirect(url_for('dashboard'))  # Redirect to the dashboard after a successful update
        except Exception as e:
            db.session.rollback()  # Roll back the transaction in case of an error
            flash('Error updating user: ' + str(e), 'danger')  # Display an error message
            print("Error updating user:", e)  # Log the error for debugging

    # Log and display form errors
    if form.errors:
        print("Form errors:", form.errors)
        for error_field, error_messages in form.errors.items():
            for error in error_messages:
                flash(f"Error in {error_field}: {error}", 'danger')

    return render_template('update_user.html', form=form, current_user=user)


@app.route('/purchase_textbooks')
def purchase_textbooks():
    # Add logic here if needed to fetch or process textbook purchasing data
    return render_template('purchase_textbooks.html')

@app.route('/find_roommate')
def find_roommate():
    # Add logic here to handle roommate finding functionality
    return render_template('find_roommate.html')

@app.route('/purchase_meal_plan')
def purchase_meal_plan():
    # Add logic here to handle meal plan purchase functionality
    return render_template('purchase_meal_plan.html')

@app.route('/purchase_bus_ticket')
def purchase_bus_ticket():
    # Add logic here to handle bus ticket purchase functionality
    return render_template('purchase_bus_ticket.html')

@app.route('/view_sports_activities')
def view_sports_activities():
    # Add logic here for handling the viewing of sports activities
    return render_template('view_sports_activities.html')

@app.route('/run_election_poll')
def run_election_poll():
    # Add logic here to handle the functionality of running an election poll
    return render_template('run_election_poll.html')

@app.route('/people/search', methods=['GET'])
@jwt_required()
def search_people():
    # Extract search parameters from request query string
    department = request.args.get('department')
    first_name = request.args.get('first_name')
    last_name = request.args.get('last_name')

    # Build search query considering all or any of the provided criteria
    query = User.query
    if department:
        query = query.filter_by(department=department)
    if first_name and last_name:
        query = query.filter_by(first_name=first_name, last_name=last_name)
    elif first_name:
        query = query.filter_by(first_name=first_name)
    elif last_name:
        query = query.filter_by(last_name=last_name)

    # Execute search, handle empty results
    results = query.all()
    if not results:
        return render_template('search_results_not_found.html'), 404

    # Render search results template with user information
    return render_template('search_people_results.html', users=results)


if __name__ == '__main__':
    app.run(debug=True)