from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user, \
    AnonymousUserMixin
from forms import *
from flask_gravatar import Gravatar
from functools import wraps
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = str(os.environ.get("SECRET_KEY", "noyouwillnotgetthissecretkeyEVERY1864917301u0π"))
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = str(os.environ.get("DATABASE_URL", "sqlite:///blog.db"))
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship("Users", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comments", back_populates="parent_post")


class Users(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(10000))
    name = db.Column(db.String(25))
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comments", back_populates="author")


class Comments(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("Users", back_populates="comments")
    text = db.Column(db.Text, nullable=False)
    parent_post = relationship("BlogPost", back_populates="comments")
    parent_post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))


db.create_all()


@login_manager.user_loader
def loader(user_id):
    return Users.query.get(user_id)


def admin_only(func):
    @wraps(func)
    def admin_check(*args, **kwargs):
        if not isinstance(current_user, AnonymousUserMixin):
            if current_user.id == 1:
                return func(*args, **kwargs)
            else:
                abort(403)
        else:
            abort(403)

    return admin_check


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    id_ = current_user.get_id()
    if id_:
        return render_template("index.html", all_posts=posts, is_auth=current_user.is_authenticated, id=int(id_))
    else:
        return render_template("index.html", all_posts=posts, is_auth=current_user.is_authenticated, id=0)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = CreateUserForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        if not Users.query.filter_by(email=form.email.data).first():
            new = Users(name=name, email=email,
                        password=generate_password_hash(password, method='pbkdf2:sha256', salt_length=8))
            db.session.add(new)
            db.session.commit()
            login_user(new)
            return redirect(url_for("get_all_posts"))
        else:
            flash("You already signed up with that email! Please sign in instead.")
            return redirect(url_for("login"))
    return render_template("register.html", form=form, is_auth=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = SignInForm()
    if form.validate_on_submit():
        if Users.query.filter_by(email=form.email.data).first():
            email = form.email.data
            password = form.password.data
            user = Users.query.filter_by(email=email).first()
            hash_pass = user.password
            if check_password_hash(hash_pass, password):
                login_user(user)
                return redirect(url_for("get_all_posts"))
            else:
                flash("Wrong username or password!")
                return redirect(url_for("login"))
        else:
            flash("Wrong username or password!")
            return redirect(url_for("login"))
    return render_template("login.html", form=form, is_auth=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    form = CommentForm()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            text = form.comment.data
            new = Comments(
                author=current_user,
                text=text,
                parent_post_id=post_id
            )
            db.session.add(new)
            db.session.commit()
            return redirect(url_for(f"show_post", post_id=post_id))
        else:
            flash("You need to be logged in to comment!")
            return redirect(url_for("login"))
    requested_post = BlogPost.query.get(post_id)
    id_ = current_user.get_id()
    if not id_:
        id_ = 1000000
    comments = Comments.query.filter_by(parent_post=BlogPost.query.get(post_id))
    return render_template("post.html", post=requested_post, is_auth=current_user.is_authenticated, id_=int(id_),
                           form=form, comments=comments, gravatar=gravatar)


@app.route("/about")
def about():
    return render_template("about.html", is_auth=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", is_auth=current_user.is_authenticated)


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
    return render_template("make-post.html", form=form, is_auth=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, is_auth=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
