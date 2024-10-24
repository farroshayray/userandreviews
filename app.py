from flask import Flask, render_template, redirect, url_for, flash, abort, request, jsonify
from connectors.config import Config
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

@login_manager.unauthorized_handler
def unauthorized():
    if request.is_json:
        return jsonify({'message': 'Unauthorized'}), 403
    return render_template('unauthorized.html')

@app.errorhandler(403)
def forbidden(e):
    if request.is_json:
        return jsonify({'message': 'Forbidden: You do not have permission to access this resource.'}), 403
    return render_template('forbidden.html'), 403

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
    logrole = current_user.role if current_user.is_authenticated else None
    return render_template('home.html', username=username, logrole=logrole, reviews=Review.query.all())

@app.route('/about')
def about():
    return render_template('about.html')
@app.route('/users', methods=['GET'])
@login_required
def users():
    logusername = current_user.username
    logrole = current_user.role

    if request.is_json:
        users = Users.query.all()

        json_response = jsonify({
            'data': [
                {
                    'email': user.email,
                    'username': user.username,
                    'role': user.role,
                    'id': user.id
                } 
                for user in users
            ]
        })
        return json_response, 200

    return render_template('users.html', logusername=logusername, logrole=logrole, users=Users.query.all())


@app.route('/users/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = Users.query.get(user_id)
    
    if not user:
        if request.is_json:
            return jsonify({'message': "Data doesn't exist"}), 404
        flash("Data doesn't exist", 'danger')
        return redirect(request.referrer or url_for('users'))
    
    if user.username == current_user.username:  # Prevent deletion of the logged-in user
        if request.is_json:
            return jsonify({'message': "You cannot delete yourself."})
        flash("You cannot delete yourself.")
        return redirect(url_for('users'))
    
    db.session.delete(user)
    db.session.commit()
    if request.is_json:
        return jsonify({'message': 'User deleted successfully!'})
    flash('User deleted successfully!')
    return redirect(url_for('users'))

if __name__ == "__main__":
    app.run(debug=True)
