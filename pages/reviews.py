from flask import abort, request, render_template, flash, redirect, url_for, jsonify
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
@admin_required
def review():
    username = current_user.username if current_user.is_authenticated else None #Get login data
    role = current_user.role

    if request.method == 'POST':
        try:
            if request.is_json:
                data = request.get_json()
                email = data.get('email', current_user.email).strip()
                description = data.get('description', '').strip()
                rating = int(data.get('rating', '0'))
            else:
                email = current_user.email
                description = request.form['description'].strip()
                rating = int(request.form['rating'])

            if not description:
                raise ValueError("Description cannot be empty")
            if not (1 <= rating <= 5):
                raise ValueError("Rating must between 1 and 5.")

            new_review = Review(description=description, email=email, rating=rating)
            db.session.add(new_review)
            db.session.commit()

            if request.is_json:
                return jsonify({
                    'data': {
                        'email': email,
                        'description': description,
                        'rating': rating
                    },
                    'message': 'Review added successfully!'
                }), 201

            flash('Review added successfully!', 'success')
            return redirect(url_for('reviews.review'))

        except ValueError as ve:  # for error input validation
            db.session.rollback()  # Rollback if error
            if request.is_json:
                return jsonify({'error': str(ve)}), 400
            flash(str(ve), 'danger')

        except Exception as e:  # error for all
            db.session.rollback()
            if request.is_json:
                return jsonify({'error': 'An error occurred. Please try again.'}), 500
            flash('An error occurred. Please try again.', 'danger')
            return redirect(url_for('reviews.review'))

    if request.method == 'GET':
        reviews = Review.query.all()
        if request.is_json:
            return jsonify({
                'data': [{
                    'review_id': review.review_id,
                    'email': review.email,
                    'description': review.description,
                    'rating': review.rating
                } for review in reviews]
            })
        return render_template('reviews.html', username=username, role=role, reviews=reviews)

    
@reviews.route('/delete/<int:review_id>', methods=['POST'])
@login_required
@admin_required
def delete_review(review_id):
    # get review by id
    review = Review.query.get(review_id)

    # if review not found
    if not review:
        if request.is_json:
            return jsonify({'message': "Data doesn't exist"}), 404
        flash("Data doesn't exist", 'danger')
        return redirect(request.referrer or url_for('reviews.review'))

    db.session.delete(review)
    db.session.commit()

    if request.is_json:
        return jsonify({'message': 'Review deleted successfully!'}), 200

    flash('Review deleted successfully!', 'success')
    return redirect(request.referrer or url_for('reviews.review'))


@reviews.route('/dashboard', methods=['GET'])
@login_required
def dashboard():

    username = current_user.username
    email = current_user.email
    role = current_user.role
    
    return render_template('dashboard.html', username=username, email=email, role=role)
