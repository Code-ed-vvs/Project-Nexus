from flask import Flask, render_template ,url_for ,request,redirect
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import pytz

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'  # Use SQLite database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

def get_ist_time():
    ist  = pytz.timezone('Asia/Kolkata')
    utc_time = datetime.now(pytz.utc)
    ist_time = utc_time.astimezone(ist)
    ist_time = ist_time.replace(microsecond=0)
    return ist_time.strftime('%Y-%m-%d %H:%M:%S')

def format_content(content):
    content = content.strip()
    return content.replace('\n', '<br>')


with app.app_context():
    db.create_all()

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    title = db.Column(db.String(500), nullable=False)
    email = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime)

@app.route('/')
def index():
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template('company_dashboard.html', posts = posts)

@app.route('/new_posts',methods = ["GET","POST"])
def add_post():
    if request.method == 'POST':
        content = request.form['content']
        new_post = Post(content=format_content(content), created_at=datetime.now(pytz.timezone('Asia/Kolkata')).replace(microsecond = 0))
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('new_posts.html')

if __name__ == "__main__":
    app.run(debug=True)
