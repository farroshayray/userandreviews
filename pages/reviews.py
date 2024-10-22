from flask import abort, request, render_template, flash, redirect
from flask_login import login_required, current_user
from functools import wraps
from . import reviews
from models.models import db, Review

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'Admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@reviews.route('/', methods=['GET', 'POST'])
@login_required
# @admin_required
def review():
    username = current_user.username if current_user.is_authenticated else None
    role = current_user.role
    if request.method == 'POST':
        description = request.form['description']
        rating = request.form['rating']

        new_review = Review(description=description, email=current_user.email, rating=rating)
        db.session.add(new_review)
        db.session.commit()

        flash('Review added successfully!')
    
    return render_template('reviews.html', username=username, role=role, reviews=Review.query.all())

@reviews.route('/delete/<int:review_id>', methods=['POST'])
@login_required
@admin_required
def delete_review(review_id):
    review = Review.query.get_or_404(review_id)
    db.session.delete(review)
    db.session.commit()
    flash('Review deleted successfully!')
    return redirect(request.referrer)  # Redirect back to the page the user came from

@reviews.route('/dashboard', methods=['GET'])
@login_required
def dashboard():

    username = current_user.username
    email = current_user.email
    role = current_user.role
    
    return render_template('dashboard.html', username=username, email=email, role=role)
