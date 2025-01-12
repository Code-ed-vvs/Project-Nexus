from flask_login import login_required, current_user, LoginManager, UserMixin, login_user, logout_user
from flask import Flask, render_template, url_for, request, redirect, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import pytz
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SelectField, TextAreaField, DateField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, Length
import logging
from logging.handlers import RotatingFileHandler
import os
from ai_integration import analyze_solution, summarize_solutions, get_solution_rank

# Flask app configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('qwertyuiopasdfghjklzxcvbnm', 'dev-key-please-change')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///project_nexus.db' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  # Session lasts for 7 days
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=14)  # Remember me cookie lasts for 14 days
app.config['SESSION_PROTECTION'] = 'strong'
app.config['WTF_CSRF_ENABLED'] = True

# Initialize extensions
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Setup logging
if not os.path.exists('logs'):
    os.mkdir('logs')
file_handler = RotatingFileHandler('logs/nexus.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Project Nexus startup')

# Rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

def get_ist_time():
    ist = pytz.timezone('Asia/Kolkata')
    utc_time = datetime.now(pytz.utc)
    ist_time = utc_time.astimezone(ist)
    ist_time = ist_time.replace(microsecond=0)
    return ist_time.strftime('%Y-%m-%d %H:%M:%S')

def format_content(content):
    content = content.strip()
    return content.replace('\n', '<br>')


# Define models
class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # 'student' or 'company'
    posts = db.relationship('Post', backref='author', lazy=True)
    solutions = db.relationship('Solution', backref='student', lazy=True)

    def __repr__(self):
        return f"<User {self.username}, Role: {self.role}>"

    def check_password(self, password):
        return check_password_hash(self.password, password)


# Define the Post model
class Post(db.Model):
    __tablename__ = 'post'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    company_name = db.Column(db.String(100), nullable=False)
    deadline = db.Column(db.DateTime, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    solutions = db.relationship('Solution', backref='post', lazy=True)

    def __repr__(self):
        return f"<Post {self.title}>"


# Define the Solution model
class Solution(db.Model):
    __tablename__ = 'solution'
    id = db.Column(db.Integer, primary_key=True)
    solution_text = db.Column(db.Text, nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    # AI evaluation fields
    relevance_score = db.Column(db.Float, nullable=True)
    technical_score = db.Column(db.Float, nullable=True)
    innovation_score = db.Column(db.Float, nullable=True)
    completeness_score = db.Column(db.Float, nullable=True)
    clarity_score = db.Column(db.Float, nullable=True)
    overall_score = db.Column(db.Float, nullable=True)
    rank = db.Column(db.Integer, nullable=True)
    
    # Feedback fields
    strengths = db.Column(db.JSON, nullable=True)
    weaknesses = db.Column(db.JSON, nullable=True)
    suggestions = db.Column(db.JSON, nullable=True)

    def __repr__(self):
        return f"<Solution {self.id} for Post {self.post_id}>"


# Initialize database
def init_db():
    try:
        with app.app_context():
            # Drop all tables first to ensure clean state
            db.drop_all()
            # Create all tables
            db.create_all()
            app.logger.info('Created new database tables')
    except Exception as e:
        app.logger.error(f'Error creating tables: {str(e)}')
        raise


# Define the user_loader function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def password_meets_requirements(password):
    """Check if password meets minimum security requirements."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        return False, "Password must contain at least one special character"
    return True, ""


class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('student', 'Student'), ('company', 'Company')], validators=[DataRequired()])

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')

class PostForm(FlaskForm):
    title = StringField('Problem Title', validators=[DataRequired(), Length(min=4, max=100)])
    company_name = StringField('Company Name', validators=[DataRequired(), Length(min=2, max=100)])
    description = TextAreaField('Problem Description', validators=[DataRequired(), Length(min=10)])
    deadline = DateField('Valid Until', validators=[DataRequired()])
    submit = SubmitField('Post Problem')

class SolutionForm(FlaskForm):
    solution_text = TextAreaField('Solution', validators=[DataRequired(), Length(min=10)])
    submit = SubmitField('Submit Solution')


@app.route('/')
def index():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.role == 'student':
            return redirect(url_for('student_dashboard'))
        else:
            return redirect(url_for('company_dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            session.permanent = True  # Make the session permanent
            if user.role == 'student':
                return redirect(url_for('student_dashboard'))
            else:
                return redirect(url_for('company_dashboard'))
        flash('Invalid username or password')
        return redirect(url_for('login'))
    return render_template('login.html', title='Login', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = SignupForm()
    if form.validate_on_submit():
        try:
            # Check if username already exists
            if User.query.filter_by(username=form.username.data).first():
                flash('Username already exists. Please choose a different one.', 'danger')
                return render_template('signup.html', title='Sign Up', form=form)
            
            # Check if email already exists
            if User.query.filter_by(email=form.email.data).first():
                flash('Email already registered. Please use a different email.', 'danger')
                return render_template('signup.html', title='Sign Up', form=form)
            
            # Create new user
            hashed_password = generate_password_hash(form.password.data)
            user = User(
                username=form.username.data,
                email=form.email.data,
                password=hashed_password,
                role=form.role.data
            )
            
            db.session.add(user)
            db.session.commit()
            app.logger.info(f'New user registered: {user.username} ({user.role})')
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Error in signup: {str(e)}')
            flash(f'An error occurred during registration: {str(e)}', 'danger')
            return render_template('signup.html', title='Sign Up', form=form)
    
    return render_template('signup.html', title='Sign Up', form=form)

@app.route('/company_dashboard', methods=['GET', 'POST'])
@login_required
def company_dashboard():
    if not current_user.is_authenticated or current_user.role != 'company':
        flash('Access denied. Please login as a company.')
        return redirect(url_for('login'))
    posts = Post.query.filter_by(user_id=current_user.id).all()
    return render_template('company_dashboard.html', posts=posts)


@app.route('/student_dashboard')
@login_required
def student_dashboard():
    if not current_user.is_authenticated or current_user.role != 'student':
        flash('Access denied. Please login as a student.')
        return redirect(url_for('login'))
    
    # Get all posts from all companies, ordered by newest first
    posts = Post.query.join(User).filter(User.role == 'company').order_by(Post.deadline.desc()).all()
    return render_template('student_dashboard.html', title='Student Dashboard', posts=posts)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


# Add Post
@app.route('/add_post', methods=['GET', 'POST'])
@login_required
def add_post():
    if not current_user.is_authenticated or current_user.role != 'company':
        flash('Access denied. Please login as a company.')
        return redirect(url_for('login'))
    
    form = PostForm()
    if form.validate_on_submit():
        post = Post(
            title=form.title.data,
            description=form.description.data,
            company_name=form.company_name.data,
            deadline=form.deadline.data,
            user_id=current_user.id
        )
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created!', 'success')
        return redirect(url_for('company_dashboard'))
    return render_template('add_post.html', title='New Post', form=form)


@app.route('/post/<int:post_id>')
@login_required
def view_post(post_id):
    post = Post.query.get_or_404(post_id)
    # Get all solutions for this post, ordered by rank
    solutions = Solution.query.filter_by(post_id=post_id).order_by(
        Solution.rank.nullslast(), 
        Solution.overall_score.desc().nullslast(), 
        Solution.created_at.desc()
    ).all()
    
    # If company is viewing, get solutions summary
    solutions_summary = None
    if current_user.role == 'company' and solutions:
        solutions_data = [{'text': s.solution_text} for s in solutions]
        solutions_summary = summarize_solutions(post.title, post.description, solutions_data)
    
    form = SolutionForm()
    return render_template('view_post.html', 
                         title=post.title, 
                         post=post, 
                         solutions=solutions, 
                         solutions_summary=solutions_summary,
                         form=form)


@app.route('/post/<int:post_id>/submit_solution', methods=['POST'])
@login_required
def submit_solution(post_id):
    if current_user.role != 'student':
        flash('Only students can submit solutions.')
        return redirect(url_for('view_post', post_id=post_id))
    
    try:
        solution_text = request.form.get('solution_text')
        if not solution_text:
            flash('Solution text is required.', 'danger')
            return redirect(url_for('view_post', post_id=post_id))

        post = Post.query.get_or_404(post_id)
        solution = Solution(
            solution_text=solution_text,
            student_id=current_user.id,
            post_id=post_id,
            created_at=datetime.utcnow()
        )
        
        try:
            # Analyze solution using AI
            evaluation = analyze_solution(post.title, post.description, solution_text)
            
            # Store evaluation results
            solution.relevance_score = evaluation['scores'].get('relevance', 0)
            solution.technical_score = evaluation['scores'].get('technical_merit', 0)
            solution.innovation_score = evaluation['scores'].get('innovation', 0)
            solution.completeness_score = evaluation['scores'].get('completeness', 0)
            solution.clarity_score = evaluation['scores'].get('implementation_clarity', 0)
            solution.overall_score = evaluation['scores'].get('overall_score', 0)
            solution.strengths = evaluation['feedback'].get('strengths', [])
            solution.weaknesses = evaluation['feedback'].get('weaknesses', [])
            solution.suggestions = evaluation['feedback'].get('suggestions', [])
        except Exception as e:
            app.logger.error(f'Error in AI analysis: {str(e)}')
            # Set default scores if AI analysis fails
            solution.overall_score = 5.0
            solution.strengths = ["AI analysis unavailable"]
            solution.weaknesses = ["Could not analyze solution"]
            solution.suggestions = ["Please try again later"]
        
        # Add and commit the solution
        db.session.add(solution)
        db.session.commit()
        
        # Update ranks for all solutions
        try:
            solutions = Solution.query.filter_by(post_id=post_id).all()
            solution_scores = {s.id: {'overall_score': s.overall_score or 0} for s in solutions}
            ranks = get_solution_rank(solution_scores)
            
            for solution_id, rank in ranks.items():
                sol = Solution.query.get(solution_id)
                if sol:
                    sol.rank = rank
            db.session.commit()
        except Exception as e:
            app.logger.error(f'Error updating ranks: {str(e)}')
        
        flash('Your solution has been submitted and evaluated successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error submitting solution: {str(e)}')
        flash('An error occurred while submitting your solution. Please try again.', 'danger')
    
    return redirect(url_for('view_post', post_id=post_id))

@app.errorhandler(404)
def not_found_error(error):
    app.logger.error(f'Page not found: {request.url}')
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    app.logger.error(f'Server Error: {error}')
    return render_template('500.html'), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    app.logger.warning(f'Rate limit exceeded for IP: {get_remote_address()}')
    return render_template('429.html'), 429


if __name__ == '__main__':
    init_db()  # Initialize the database
    app.run(host='127.0.0.1', port=8080, debug=True)
