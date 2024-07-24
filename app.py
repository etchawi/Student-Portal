from flask import Flask, jsonify, request, render_template, redirect, url_for, flash, session, make_response, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, set_access_cookies
from flask_mail import Mail, Message
from flask_wtf import CSRFProtect, FlaskForm
from wtforms import StringField, SubmitField, PasswordField, HiddenField, SelectField, IntegerField
from wtforms.validators import DataRequired, Email, EqualTo, NumberRange
from wtforms.fields import DateField, DecimalField  # Import DateField and DecimalField
from itsdangerous.url_safe import URLSafeTimedSerializer as Serializer
from datetime import timedelta, datetime
from dotenv import load_dotenv
from sqlalchemy import or_
import os
import smtplib
from email.mime.text import MIMEText
import logging



logging.basicConfig(level=logging.DEBUG)


# Initialize Flask application
app = Flask(__name__)
# Load environment variables
load_dotenv()



# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///website_data.db'
app.config['SQLALCHEMY_BINDS'] = {'events': 'sqlite:///events_database.db'}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'super_secret_key')
app.config['MAIL_SERVER'] = 'live.smtp.mailtrap.io'
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
class Roommate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    move_in_date = db.Column(db.Date, nullable=False)
    gender_preference = db.Column(db.String(50), nullable=False)
    max_price = db.Column(db.Float, nullable=False)

    user = db.relationship('User', back_populates='roommate_preferences')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(100), nullable=True)
    phone_number = db.Column(db.String(20), nullable=True)
    address = db.Column(db.String(255), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    state = db.Column(db.String(100), nullable=False)
    zip_code = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

    # Ensure the backref is uniquely named and explicitly defined
    roommate_preferences = db.relationship('Roommate', back_populates='user')

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

class RoommateSearchForm(FlaskForm):
    move_in_date = DateField('Move-in Date', format='%Y-%m-%d', validators=[DataRequired()])
    gender_preference = SelectField('Gender Preference', choices=[('male', 'Male'), ('female', 'Female'), ('any', 'Any')], validators=[DataRequired()])
    max_price = IntegerField('Maximum Price', validators=[DataRequired()])


class Textbook2(db.Model):
    __tablename__ = 'textbook2'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    author = db.Column(db.String(255))
    isbn = db.Column(db.String(20))
    price = db.Column(db.Float)
    library_location = db.Column(db.String(100))  

    def __repr__(self):
        return f"<Textbook {self.title}>"

def create_and_populate_db():
    # Your code to create and populate the database
    
    alice = User(
        first_name="Alice",
        last_name="Smith",
        department="Marketing",
        phone_number="1234567890",
        address="123 Main St",
        city="New York",
        state="NY",
        zip_code="10001",
        email="alice@example.com",
        password_hash="hashed_password_for_alice"
    )
    
    bob = User(
        first_name="Bob",
        last_name="Brown",
        department="Engineering",
        phone_number="9876543210",
        address="456 Elm St",
        city="Los Angeles",
        state="CA",
        zip_code="90001",
        email="bob@example.com",
        password_hash="hashed_password_for_bob"
    )
    
    # Commit the user objects to the database
    db.session.add(alice)
    db.session.add(bob)
    db.session.commit()


# Add book details
with app.app_context():
    db.create_all()
    # Check if the table is empty before adding new entries
    if Textbook2.query.count() == 0:
        # Create instances of Textbook model with book details and prices
        books = [
            Textbook2(title="1984", author="George Orwell", isbn="9780451524935", price=19.99, library_location="Shelf A-3"),
            Textbook2(title="To Kill a Mockingbird", author="Harper Lee", isbn="9780060935467", price=24.99, library_location="City Lights Books"),
            Textbook2(title="Brave New World", author="Aldous Huxley", isbn="9780060850524", price=18.99, library_location="Shelf B-1"),
            Textbook2(title="Catch-22", author="Joseph Heller", isbn="9781451626650", price=16.99, library_location="Shelf C-4"),
            Textbook2(title="The Great Gatsby", author="F. Scott Fitzgerald", isbn="9780743273565", price=14.99, library_location="Barnes & Noble"),
            Textbook2(title="Moby-Dick", author="Herman Melville", isbn="9781503280786", price=12.99, library_location="Shelf D-2"),
            Textbook2(title="Crime and Punishment", author="Fyodor Dostoevsky", isbn="9780486415871", price=21.99, library_location="Book Depository"),
            Textbook2(title="Pride and Prejudice", author="Jane Austen", isbn="9781503290563", price=9.99, library_location="Shelf E-3"),
            Textbook2(title="Wuthering Heights", author="Emily Brontë", isbn="9781853260018", price=7.99, library_location="Powell's Books"),
            Textbook2(title="Frankenstein", author="Mary Shelley", isbn="9780486282114", price=6.99, library_location="Shelf F-5")
        ]
        # Add instances to the database session
        db.session.add_all(books)

        # Commit changes to the database
        db.session.commit()
    else:
        print("Database already initialized with entries.")


class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    textbook_id = db.Column(db.Integer, db.ForeignKey('textbook2.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    
class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    department = StringField('Department')  # Optional field for department
    phone_number = StringField('Phone Number')  # Optional field for phone number
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
    department = StringField('Department')  # Optional field for department
    phone_number = StringField('Phone Number')  # Optional field for phone number
    address = StringField('Address', validators=[DataRequired()])
    city = StringField('City', validators=[DataRequired()])
    state = StringField('State', validators=[DataRequired()])
    zip_code = StringField('Zip Code', validators=[DataRequired()])
    email = StringField('Email address', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Update')

    # Add CSRF token field
    csrf_token = HiddenField('CSRF Token')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class SearchForm(FlaskForm):
    department = StringField('Department')
    first_name = StringField('First Name')
    last_name = StringField('Last Name')
    submit = SubmitField('Search')

class PromoCodeForm(FlaskForm):
    promo_code = StringField('Promo Code', validators=[DataRequired()])
    submit = SubmitField('Apply Promo Code')



# Check if student is eligible for promo code
def check_promo_eligibility(user_id):
    total_purchase_amount = db.session.query(func.sum(Purchase.total_amount)).filter_by(user_id=user_id).scalar()
    if total_purchase_amount and total_purchase_amount > 200:
        return True
    return False
    
    
class SearchTextbooksForm(FlaskForm):
    title = StringField('Title')
    author = StringField('Author')
    isbn = StringField('ISBN')
    submit = SubmitField('Search')

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


# Model for Purchases
class Purchase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    textbook_id = db.Column(db.Integer, db.ForeignKey('textbook2.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    purchase_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    total_amount = db.Column(db.Float, nullable=False)

class PurchaseForm(FlaskForm):
    textbook_choices = [('1', 'Textbook 1'), ('2', 'Textbook 2'), ('3', 'Textbook 3')]
    textbook = SelectField('Textbook', choices=textbook_choices, validators=[DataRequired()])
    quantity = IntegerField('Quantity', validators=[DataRequired(), NumberRange(min=1)])  # Add a quantity field
    submit = SubmitField('Purchase')

class MealPlanPurchase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    type = db.Column(db.String(20))  # 'monthly' or 'semester'
    purchase_date = db.Column(db.DateTime, default=datetime.utcnow)

    def get_price(self):
        base_price = 600
        if self.type == 'semester':
            return base_price * 5 * 0.95  # 5 months at a 5% discount
        return base_price

class MealPlanForm(FlaskForm):
    type = SelectField('Plan Type', choices=[('monthly', 'Monthly - $600'), ('semester', 'Semester - 5% off')], validators=[DataRequired()])
    submit = SubmitField('Purchase Meal Plan')




class Event(db.Model):
    __tablename__ = 'event'
    __bind_key__ = 'events'  # This tells SQLAlchemy to use the secondary database

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    event_type = db.Column(db.String(50), nullable=False)
    
with app.app_context():
    db.create_all(bind='events')  # This creates tables only for the secondary database


class DateRangeForm(FlaskForm):
    start_date = DateField('Start Date', format='%Y-%m-%d', validators=[DataRequired()])
    end_date = DateField('End Date', format='%Y-%m-%d', validators=[DataRequired()])
    submit = SubmitField('Search')

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

@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    logout_user()
    response = make_response(redirect(url_for('login')))
    response.set_cookie('access_token_cookie', '', expires=0)
    response.set_cookie('refresh_token_cookie', '', expires=0)
    return response


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
    query = request.args.get('query', '').strip()
    search_attempted = False  # Flag to indicate if a search was attempted
    search_results = []
    if query:
        search_attempted = True
        search_results = Textbook2.query.filter(
            or_(
                Textbook2.title.ilike(f'%{query}%'),
                Textbook2.author.ilike(f'%{query}%'),
                Textbook2.isbn.ilike(f'%{query}%')
            )
        ).all()
    
    return render_template('search_textbooks.html', search_results=search_results, search_attempted=search_attempted)






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
    user = User.query.get_or_404(user_id)
    form = UpdateUserForm(obj=user)

    if request.method == 'POST':
        print("CSRF Token from form:", form.csrf_token.data)

    if form.validate_on_submit():
        # Update user's information
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
            db.session.commit()
            flash('User updated successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash('Error updating user: ' + str(e), 'danger')
            print("Error updating user:", e)

    # Log and display form errors
    if form.errors:
        print("Form errors:", form.errors)
        for error_field, error_messages in form.errors.items():
            for error in error_messages:
                flash(f"Error in {error_field}: {error}", 'danger')

    return render_template('update_user.html', form=form, current_user=user)




# Flask route for bus ticket purchase
@app.route('/purchase_bus_ticket', methods=['GET', 'POST'])
def purchase_bus_ticket():
    if request.method == 'POST':
        # Get form data
        selected_zones = request.form.getlist('zones')
        quantity = int(request.form.get('quantity', 1))

        # Calculate total cost
        total_cost = calculate_total_cost(selected_zones, quantity)

        # Render confirmation page with total cost
        return render_template('confirmation.html', total=total_cost)

    # Render the bus ticket purchase form
    return render_template('bus_ticket_purchase.html')

# Function to calculate total cost
def calculate_total_cost(selected_zones, quantity):
    zone_prices = {
        'zone1': 2,
        'zone2': 4,
        'zone3': 6,
        'bus-card': 40
    }

    total_cost = 0
    for zone in selected_zones:
        if zone in zone_prices:
            total_cost += zone_prices[zone]

    # Multiply total cost by quantity
    total_cost *= quantity

    return total_cost




from flask import render_template

@app.route('/search_people', methods=['GET'])
def search_people():
    form = SearchForm(request.args)
    users = None  # Initialize users as None or empty list

    # Check if any search field is filled
    if 'department' in request.args or 'first_name' in request.args or 'last_name' in request.args:
        department = request.args.get('department', '')
        first_name = request.args.get('first_name', '')
        last_name = request.args.get('last_name', '')

        query = User.query
        if department:
            query = query.filter(User.department.ilike(f'%{department}%'))
        if first_name:
            query = query.filter(User.first_name.ilike(f'%{first_name}%'))
        if last_name:
            query = query.filter(User.last_name.ilike(f'%{last_name}%'))

        users = query.all()

    return render_template('search_people.html', form=form, users=users)

# Update the route for purchasing textbooks to handle the search form
from flask import render_template

@app.route('/purchase_textbooks', methods=['GET', 'POST'])
def purchase_textbooks():
    purchase_form = PurchaseForm()  # Assuming you have a form for purchasing textbooks
    promo_code_form = PromoCodeForm()  # Assuming you have a form for promo codes

    textbooks = Textbook2.query.all()

    if request.method == 'POST':
        if purchase_form.validate_on_submit():
            textbook_id = request.form.get('textbook')
            quantity = request.form.get('quantity')

            # Here you can handle the purchase logic, e.g., updating the database, calculating total amount, etc.
            # For simplicity, let's just redirect to a success page for now.
            flash('Purchase successful!', 'success')
            return redirect(url_for('purchase_success'))

        elif promo_code_form.validate_on_submit():
            promo_code = request.form.get('promo_code')

            # Check if promo code exists in the database
            promo = PromoCode.query.filter_by(code=promo_code).first()
            if promo:
                # Apply promo code logic here
                flash('Promo code applied successfully!', 'success')
            else:
                flash('Invalid promo code!', 'error')

    return render_template('purchase_textbooks.html', 
                           purchase_form=purchase_form,
                           textbooks=textbooks,
                           promo_code_form=promo_code_form)

@app.route('/get_textbook_price/<int:textbook_id>/<int:quantity>')
def get_textbook_price(textbook_id, quantity):
    # Assuming each textbook has a price attribute in the database
    textbook = Textbook2.query.get(textbook_id)
    if textbook:
        total_price = textbook.price * quantity
        return jsonify({'total_price': total_price})
    else:
        return jsonify({'error': 'Textbook not found'}), 404
    
    
# Purchase History Route
@app.route('/purchase_history')
def purchase_history():
    purchases = Purchase.query.filter_by(user_id=current_user.id).all()
    return render_template('purchase_history.html', purchases=purchases)
@app.route('/apply_promo_code', methods=['POST'])


def apply_promo_code():
    promo_code = request.form.get('promo_code')
    # Check if promo code is valid
    promo = PromoCode.query.filter_by(code=promo_code).first()
    if promo:
        # Apply discount to the purchase
        # (Code to apply discount)
        flash('Promo code applied successfully!', 'success')
    else:
        flash('Invalid promo code. Please try again.', 'danger')
    return redirect(url_for('purchase_textbooks'))


def insert_sample_roommates():
    db.session.add(Roommate(user_id=1, move_in_date=datetime(2024, 1, 1), gender_preference='any', max_price=2000))
    db.session.add(Roommate(user_id=2, move_in_date=datetime(2024, 1, 1), gender_preference='any', max_price=1500))
    db.session.add(Roommate(user_id=3, move_in_date=datetime(2024, 1, 10), gender_preference='any', max_price=1600))
    db.session.commit()
    print("Sample roommates added to the database.")

# Call this function within your Flask application context to populate the database
with app.app_context():
    insert_sample_roommates()

    
@app.route('/find_roommate', methods=['GET', 'POST'])
def find_roommate():
    form = RoommateSearchForm()
    roommates = []  # Initialize roommates as an empty list for safe handling in templates

    if form.validate_on_submit():
        move_in_date = form.move_in_date.data
        gender_preference = form.gender_preference.data
        max_price = form.max_price.data

        # Logging criteria for debugging
        app.logger.debug(f"Search Criteria - Date: {move_in_date}, Gender: {gender_preference}, Price: {max_price}")

        # Query based on form input, applying distinct on user_id and limiting results
        roommates = Roommate.query.filter(
            Roommate.move_in_date == move_in_date,
            Roommate.gender_preference == gender_preference,
            Roommate.max_price <= max_price
        ).distinct(Roommate.user_id).limit(2).all()  # Limit to only 2 results

        app.logger.debug(f"Found {len(roommates)} roommates")  # Log how many roommates were found

    return render_template('find_roommate.html', form=form, roommates=roommates)




@app.route('/purchase_meal_plan', methods=['GET', 'POST'])
def purchase_meal_plan():
    form = MealPlanForm()
    if form.validate_on_submit():
        meal_plan_purchase = MealPlanPurchase(
            user_id=current_user.id,
            type=form.type.data
        )
        db.session.add(meal_plan_purchase)
        db.session.commit()
        flash(f"Meal plan purchased successfully at ${meal_plan_purchase.get_price()}.", "success")
        return redirect(url_for('dashboard'))
    
    return render_template('purchase_meal_plan.html', form=form)

def insert_sample_events():
    events = [
        Event(name="Intercollegiate Basketball", description="Basketball game between colleges.", start_date=datetime(2024, 1, 16, 18, 0), end_date=datetime(2024, 1, 16, 20, 0), event_type="Sports"),
        Event(name="Local Soccer League", description="Soccer matches among local teams.", start_date=datetime(2024, 2, 12, 16, 0), end_date=datetime(2024, 2, 12, 18, 0), event_type="Sports"),
        Event(name="Annual Science Fair", description="Exhibition of science projects.", start_date=datetime(2024, 3, 5, 10, 0), end_date=datetime(2024, 3, 5, 17, 0), event_type="Academic"),
        Event(name="Spring Fest", description="Enjoy the spring with music, food, and games.", start_date=datetime(2024, 4, 22, 14, 0), end_date=datetime(2024, 4, 22, 23, 59), event_type="Party")
    ]
    db.session.add_all(events)
    db.session.commit()
    print("Sample events added to the database.")



@app.route('/view_sports_activities')
def view_sports_activities():
    events = Event.query.order_by(Event.start_date.asc()).all()
    return render_template('view_sports_activities.html', events=events)


if __name__ == '__main__':
    with app.app_context():
        # This creates tables for the secondary database specified by 'events' bind key
        db.create_all(binds=['events'])
        insert_sample_events()
    app.run(debug=True)
