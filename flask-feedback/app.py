from flask import Flask, render_template, redirect, session, flash, url_for, request
from models import db, User, Feedback 
from form import RegistrationForm, LoginForm, FeedbackForm
from sqlalchemy.exc import IntegrityError
from flask_bcrypt import Bcrypt
from config import Config

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    bcrypt = Bcrypt(app)
    with app.app_context():
        db.create_all()
    return app, bcrypt 

app, bcrypt = create_app()
# toolbar= DebugToolbarExtension(app)

def register_user(username, password, email, first_name , last_name):
    """ Checking for existing user, creating a new one """
    
    existing_user = User.query.filter_by(username=username).first()
    
    if existing_user is not None:
        # Handle username already exists error
        return "User already exists"
    
    
    #Creating new user and add it to database
    
    new_user = User(
        username=username,
        password=password,
        email=email,
        first_name=first_name,
        last_name=last_name
    )
    print('created a new user')
    db.session.add(new_user)
    db.session.commit()
    
    return new_user
##### ROUTES #############

@app.route('/')
def home_page():
    """ Redirect to registration form page """

    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """ Display/Handle registration form """

    form = RegistrationForm()
    if form.validate_on_submit():
        username= form.username.data
        password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data
        
        success = register_user(username,
                               password,
                               email,
                               first_name,
                               last_name)
        if success:
            session['username'] = username
            return redirect(url_for('user_profile', username=success.username))
        else:
            #Display the error message to the user
            flash(success, 'error')
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """ Display/Handle the login form """

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['username'] = username
            return redirect(url_for('user_profile', username=session['username']))
        else:
            flash('Login failed. Please check your username and password')
    return render_template('login.html', form=form)

@app.route('/secret')
def secret():
    """ Update the /secret route to display user info """

    #Check if user is logged in
    if 'username' in session:

        #Get the username from the session
        username = session['username']
        user = User.query.filter_by(username=username).first()

        if user is None: 
            flash('User not found', 'info')
            return redirect(url_for('home_page'))
        
        # Display user info on secret page
        return render_template('secret.html', user=user)
    else:
        flash('You must be logged in to access this page.')
        return redirect(url_for('login'))

@app.route('/logout')
def logout_user():
    if 'username' in session:
        username = session['username']
        session.pop('username')
        flash(f"Cya Later, {username}!", "info")
    else: 
        flash('You are not logged in.', 'info')
    return redirect(url_for('home_page'))

###### USER ROUTES #####

@app.route('/users/<username>')
def user_profile(username):
    """ Show information about the given user and their feedback """

    #Ensure that only the logged-in user can access this
    if 'username' not in session or session['username'] != username:
        flash('You must be logged in to perform this action')
        return redirect(url_for('login'))
    
    user = User.query.filter_by(username=username).first()
    feedback = user.feedback
    
    return render_template('user_profile.html', user=user, feedback=feedback, username=username)

@app.route('/users/<username>/delete', methods=['POST'])
def delete_user(username):
    """Remove the user and their feedback from the database."""

    if request.method == 'POST':
        # Ensure that only the logged-in user can delete their account
        if 'username' not in session or session['username'] != username:
            flash('You must be logged in to perform this action.', 'info')
            return redirect(url_for('login'))

        feedback = Feedback.query.filter_by(username=username).all()
        
        # Delete the feedback first
        for fb in feedback:
            db.session.delete(fb)

        # Now delete the user
        user = User.query.filter_by(username=username).first()
        if user:
            db.session.delete(user)
            db.session.commit()
            session.pop('username')
            flash('Account deleted successfully.', 'info')
        else:
            flash('User not found.', 'info')

        return redirect(url_for('home_page'))

@app.route('/users/<username>/feedback/add', methods=['GET', 'POST'])
def add_feedback(username):
    """ Display a form to add feedback for the user """

    #Ensure that the only logged in user can add feedback
    if 'username' not in session or session['username'] != username:
        flash('You must be logged in to tadd feedback')
        return redirect(url_for('login'))
    
    form = FeedbackForm()
    username = session['username']

    if form.validate_on_submit():
        feedback = Feedback(
            title = form.title.data,
            content = form.content.data,
            username = username
        )

        db.session.add(feedback)
        db.session.commit()

        flash('Feedback added successfully', 'success')
    return render_template('add_feedback.html', form=form, username=username)
    
@app.route('/feedback/<int:feedback_id>/update', methods=['GET', 'POST'])
def update_feedback(feedback_id):
    """ Display a form to edit feedback """

    #Get the feedback ID
    feedback = Feedback.query.get(feedback_id)

    if 'username' not in session or feedback.username != session['username']:
        flash('You must be logged in to tadd feedback')
        return redirect(url_for('login'))
    
    form = FeedbackForm(obj=feedback)

    if form.validate_on_submit():
        feedback.title = form.title.data
        feedback.content = form.content.data
        db.session.commit()

        flash('Feedback updated successfully', 'success')
        return redirect(url_for('user_profile', username=feedback.username))
    
    return render_template('edit_feedback.html', 
                           form=form,
                           feedback_id=feedback_id)

@app.route('/feedback/<int:feedback_id>/delete', methods=['GET', 'POST'])
def delete_feedback(feedback_id):
    """ Delete a feedback """

    feedback = Feedback.query.get(feedback_id)

    if 'username' not in session or feedback.username != session['username']:
        flash('You must be logged in to delete feedback')
        return redirect(url_for('login'))
    else:
        db.session.delete(feedback)
        db.session.commit()
        flash('Feedback deleted successfully', 'success')
    return redirect(url_for('user_profile', username=feedback.username))


if __name__ == '__main__':
    app.run()