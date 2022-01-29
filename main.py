from wtforms import StringField, PasswordField, validators, SubmitField
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor, CKEditorField
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
# from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, FlaskForm
# from flask_gravatar import Gravatar
from functools import wraps
import os
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

# #CONNECT TO DB
uri = os.environ.get("DATABASE_URL")
if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Configure LoginManager
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


# #CONFIGURE TABLES
Base = declarative_base()


class BlogPost(db.Model, Base):
    __tablename__ = "blog_post"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("Users", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")


class Users(db.Model, UserMixin, Base):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    password = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False, unique=True)
    name = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="comment_author")

    posts = relationship("BlogPost", back_populates="author")


class Comment(db.Model, Base):
    __tablename__ = "comment"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("Users", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_post.id"))
    parent_post = relationship("BlogPost", back_populates="comments")


# db.create_all()


# Create Forms
class RegisterForm(FlaskForm):
    email = StringField("Email", [validators.DataRequired()])
    password = PasswordField("Password", [validators.DataRequired()])
    name = StringField("Name", [validators.DataRequired()])
    submit = SubmitField("SIGN ME UP")


class LoginForm(FlaskForm):
    email = StringField("Email", [validators.DataRequired()])
    password = PasswordField("Password", [validators.DataRequired()])
    submit = SubmitField("LET ME IN", [validators.DataRequired()])


class CommentForm(FlaskForm):
    comment = CKEditorField("Comment", [validators.DataRequired()])
    submit = SubmitField("SUBMIT COMMENT")


def admin(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if int(current_user.get_id()) != 1:
            print(current_user.get_id())
            return redirect(url_for("get_all_posts")), 403
        return function(*args, **kwargs)

    return wrapper


@app.route('/')
def get_all_posts():
    user = None
    posts = BlogPost.query.all()
    user_id = current_user.get_id()
    if user_id:
        user = load_user(user_id)
    # print(user)
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated, user=user)


@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user_name = form.name.data
        user_email = form.email.data
        print("passed 1")
        if Users.query.filter_by(email=user_email).first():
            flash("You've already created an account with this email,Login instead!", category="error")
            return redirect(url_for('login'))
        else:
            user_password = generate_password_hash(form.password.data, method="pbkdf2:sha256", salt_length=8)
            new_user_acct = Users(email=user_email, name=user_name, password=user_password)
            db.session.add(new_user_acct)
            db.session.commit()
            login_user(new_user_acct)
            return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form)


@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginForm()
    # error = None
    if form.validate_on_submit():
        user_email = form.email.data
        user_account = Users.query.filter_by(email=user_email).first()
        if user_account:
            if check_password_hash(user_account.password, form.password.data):
                print("passed")
                login_user(user_account)
                print("passed 2")
                return redirect(url_for("get_all_posts"))
            else:
                flash("invalid password", category="error")
        else:
            flash("Email does not exist", category="error")
    return render_template("login.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    user = None
    logged_in = None
    requested_post = BlogPost.query.get(post_id)
    user_id = current_user.get_id()
    form = CommentForm()
    if user_id:
        user = load_user(user_id)
    if request.method == "POST":
        form.validate_on_submit()
        print(form.comment.data)
        if not user_id:
            flash("You need to login to comment!", category="error")
            return redirect(url_for("login"))
        else:
            new_comment = Comment(post_id=post_id,
                                  author_id=user_id,
                                  text=form.comment.data,
                                  )
            db.session.add(new_comment)
            db.session.commit()
    all_comments = Comment.query.all()
    return render_template("post.html",
                           post=requested_post,
                           logged_in=current_user.is_authenticated,
                           user=user,
                           form=form,
                           comments=all_comments
                           )


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=["POST", "GET"])
@admin
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
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=["POST", "GET"])
@admin
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=current_user,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
