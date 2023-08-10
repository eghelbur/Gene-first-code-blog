from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)

# Initialize the Gravatar extension
gravatar = Gravatar(app, size=100, rating='g', default='identicon', force_default=False)


# Initialize and configure the LoginManager
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Specify the login view for Flask-Login to redirect unauthorized users

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

    # Define the relationship between User and BlogPost (posts made by the user)
    posts = relationship("BlogPost", back_populates="author")

    # Define the relationship between User and Comment (comments made by the user)
    comments = relationship("Comment", back_populates="author")

    # Add a gravatar field to the model (it won't be stored in the database)
    gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    author = relationship("User", back_populates="posts") # Define the back-reference to User

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    # Define the relationship between BlogPost and Comment (comments on the blog post)
    comments = relationship("Comment", back_populates="post")

# In models.py or main.py

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text, nullable=False)

    # Define the relationship between Comment and User
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    author = relationship("User", back_populates="comments")

    # Define the relationship between Comment and BlogPost
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"), nullable=False)
    post = relationship("BlogPost", back_populates="comments")


db.create_all()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if the user is authenticated and their id is 1(admin user)
        if not current_user.is_authenticated or current_user.id != 1:
            # If not authenticated or not an admin, return 403 error
            abort(403)
        return f(*args, **kwargs)

    return decorated_function



@app.route('/protected')
@login_required
def protected():
    return "This is a protected route. You can only access this if you're logged in!"

# Define the user loader function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()

    # Check if the current user is an admin (id=1)
    is_admin = current_user.is_authenticated and current_user.id == 1

    return render_template("index.html", all_posts=posts, is_admin=is_admin)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        # Check if the username or email already exists in the database
        existing_user = User.query.filter_by(username=form.username.data).first()
        existing_email = User.query.filter_by(email=form.email.data).first()

        if existing_user:
            flash('Username already taken. Please choose a different username.', 'danger')
        elif existing_email:
            # If the email exists in the database, redirect to the /login route
            flash('An account with this email already exists. Please log in instead.', 'warning')
            return redirect(url_for('login'))

        else:
            # If the username and email are unique, create a new user
            new_user = User(
                username=form.username.data,
                email=form.email.data,
                password=generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
            )
            db.session.add(new_user)
            db.session.commit()

            # Log in the user after successful registration
            login_user(new_user)

            flash('Registration successful! You are now logged in.', 'success')
            return redirect(url_for('get_all_posts'))

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()  # Use the LoginForm class for the login form

    if form.validate_on_submit():
        email = form.email.data  # Access the email value from the form using 'form.email.data'
        password = form.password.data  # Access the password value from the form using 'form.password.data'

        # Find the user with the given email
        user = User.query.filter_by(email=email).first()

        if not user:
            flash('Email not found. Please check your email or register for a new account.', 'danger')
            return redirect(url_for('login'))

        # If the user exists but the password is incorrect
        if not check_password_hash(user.password, password):
            flash('Invalid password. Please try again.', 'danger')
            return redirect(url_for('login'))

        login_user(user)
        # If the user exists and the password is correct, log in the user
        # You may use Flask-Login's login_user() function here, but for simplicity, I'll just assume the user is logged in.
        flash('Logged in successfully!', 'success')
        return redirect(url_for('get_all_posts'))

    # Render the login form for GET requests and form validation failures
    return render_template("login.html", form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>")
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)

    # Get the comments associated with the blog post
    comments = requested_post.comments

    # Create an instance of the CommentForm and pass it to the template
    form = CommentForm()

    return render_template("post.html", post=requested_post, comments=comments, form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)

    if not post:
        # If the post doesn't exist, return a 404 error
        abort(404)

    if post.author != current_user:
        # Check if the current user is the author of the post
        # If not, return a 403 error (forbidden)
        abort(403)

    # Create the edit form and exclude the 'author' field from it
    edit_form = CreatePostForm(obj=post)
    delattr(edit_form, "author")

    if edit_form.validate_on_submit():
        # Update the post data with the new values from the form
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()

        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, is_edit=True, post=post)

@app.route("/add-comment/<int:post_id>", methods=["POST"])
@login_required
def add_comments(post_id):
    post = BlogPost.query.get(post_id)
    form = CommentForm()

    if form.validate_on_submit():
        new_comment = Comment(
            body=form.comment.data,
            author=current_user,
            post=post
        )
        db.session.add(new_comment)
        db.session.commit()
        flash("Comment added successfully", "success")

    return redirect(url_for("show_post", post_id=post.id))


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=False)
