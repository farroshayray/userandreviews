from flask import Flask, render_template, redirect, url_for
from config.config import Config
from models.models import db, Users
from flask_login import LoginManager, login_required, current_user
from auth import auth as auth_blueprint
from pages.reviews import reviews as reviews_blueprint
from models.models import db, Review
from functools import wraps

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

with app.app_context():
    db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'  # Redirect ke login jika belum login

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'Admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

app.register_blueprint(auth_blueprint, url_prefix='/auth')
app.register_blueprint(reviews_blueprint, url_prefix='/reviews')

@app.route('/', methods=['GET'])
def home():
    username = current_user.username if current_user.is_authenticated else None
    return render_template('home.html', username=username, reviews=Review.query.all())

@app.route('/about')
def about():
    return render_template('about.html')
@app.route('/users')
def users():
    logusername = current_user.username if current_user.is_authenticated else None
    return render_template('users.html', logusername=logusername, users=Users.query.all())

from flask import abort, redirect, url_for

@app.route('/users/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = Users.query.get_or_404(user_id)
    
    if user.username == current_user.username:  # Prevent deletion of the logged-in user
        flash("You cannot delete yourself.")
        return redirect(url_for('users'))
    
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!')
    return redirect(url_for('users'))


if __name__ == "__main__":
    app.run(debug=True)
