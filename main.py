from flask import Flask, request, render_template, redirect, url_for, send_from_directory, flash, Markup
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_ckeditor import CKEditor, CKEditorField
from datetime import date
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask import abort
from flask_gravatar import Gravatar
from forms import CommentForm, CreatePostForm
from sqlalchemy import func
from werkzeug.utils import secure_filename
import os
import secrets
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_mail import Mail,Message

## Delete this code:
# import requests
# posts = requests.get("https://api.npoint.io/43644ec4f0013682fc0d").json()

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
# to silence the warning error in flask
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
UPLOAD_FOLDER = "/static/profile_pics"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
gravatar = Gravatar(app, size=100, rating='g', default='retro',
                    force_default=False, force_lower=False, use_ssl=False, base_url=None)

# set up the email for sending the Token
app.config['MAIL_SERVER'] = 'smtp.mail.yahoo.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "alsultan_adel1992@yahoo.com"
app.config['MAIL_PASSWORD'] = "cuzzgjblrbsficld"
mail = Mail(app)


# load user

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Create admin-only decorator
# Protect Routes by making Decorators
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If user current user isnt authenticated or id is not 1 then return abort with 403 error
        if current_user.id != 1 or not current_user.is_authenticated:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


# Create the User Table
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    image_file = db.Column(db.String(20), nullable=False, default="default.jpg")

    # This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="author")

    # *******Add parent relationship*******#
    # "comment_author" refers to the comment_author property in the Comment class.
    comments = relationship("Comment", back_populates="comment_author")

    # password rest
    # 1800 = 30 min
    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)


# video explain how to make realations in Flask SQL ALCHMY

# https://youtu.be/juPQ04_twtA?list=PLXmMXHVSvS-BlLA5beNJojJLlpE0PJgCW
# Check the new_post function to understand how the db is saved and how relations work
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    # Create Foreign Key, "users.id" the users refers to the tablename of User.
    # after the foreignkey always put lower case
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    # Create reference to the User object, the "posts" refers to the posts protperty in the User class.
    author = relationship("User", back_populates="posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    # ***************Parent Relationship*************#
    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)

    # *******Add child relationship*******#
    # "users.id" The users refers to the tablename of the Users class.
    # "comments" refers to the comments property in the User class.
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    # ***************Child Relationship*************#
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable=False)
    date = db.Column(db.String(250), nullable=False)


# this code run only once
db.create_all()

import bleach


## strips invalid tags/attributes
def strip_invalid_html(content):
    allowed_tags = ['a', 'abbr', 'acronym', 'address', 'b', 'br', 'div', 'dl', 'dt',
                    'em', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr', 'i', 'img',
                    'li', 'ol', 'p', 'pre', 'q', 's', 'small', 'strike',
                    'span', 'sub', 'sup', 'table', 'tbody', 'td', 'tfoot', 'th',
                    'thead', 'tr', 'tt', 'u', 'ul']

    allowed_attrs = {
        'a': ['href', 'target', 'title'],
        'img': ['src', 'alt', 'width', 'height'],
    }

    cleaned = bleach.clean(content,
                           tags=allowed_tags,
                           attributes=allowed_attrs,
                           strip=True)

    return cleaned


# BLOB AND POST CODE ____________________________________________________________________________
@app.route('/')
def get_all_posts():
    # get all the data from the db
    all_post = db.session.query(BlogPost).all()
    return render_template("index.html", all_posts=all_post)


@app.route("/post/<int:index>", methods=["GET", "POST"])
def show_post(index):
    # to add the comment Form
    form = CommentForm()
    # querying a records by passing the primary key get(id)
    post = BlogPost.query.get(index)

    # comment_count = Comment.query.filter_by(post_id=id).count()
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))

        new_comment = Comment(
            text=form.comment_text.data,
            comment_author=current_user,
            parent_post=post,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_comment)
        db.session.commit()
        # الكود اللي تحت عشان بعد الشخص مايحط بوست نرجع لنفس البوست عشان مايكون الردد متكرر مع كل تحديث
        return redirect(url_for("show_post", index=post.id))

    return render_template("post.html", post=post, form=form, current_user=current_user, )


@app.route("/new-post", methods=["GET", "POST"])
# Mark with decorator
@admin_only
def new_post():
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

    return render_template("make-post.html", form=form, current_user=current_user)


@app.route("/edit-post/<int:index>", methods=["POST", "GET"])
# Mark with decorator
@login_required
@admin_only
def edit_post(index):
    # querying a records by passing the primary key get(id)
    post = BlogPost.query.get(index)
    # code below to auto-populate the fields so the user change the desirable fields only
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=current_user.name,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()

        return redirect(url_for("show_post", index=post.id))

    return render_template("make-post.html", form=edit_form, is_edit=True)


@app.route("/delete/<int:index>", methods=["POST", "GET"])
# Mark with decorator
@login_required
@admin_only
def delete_post(index):
    # querying a records by passing the primary key get(id)
    post_to_delete = BlogPost.query.get(index)
    # Delete the post from the db
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


# USER REGISTRATION AND LOG IN CODE ____________________________________________________________________________


@app.route("/register", methods=["POST", "GET"])
def register():
    if request.method == "POST":
        pas = request.form.get("password")
        user_name = request.form.get("name").lower()
        user_name_db = User.query.filter_by(name=user_name).first()

        # way to check if the email is exists

        email = request.form.get('email').capitalize()
        user = User.query.filter_by(email=email).first()
        if user:
            flash(Markup("You've already signed up with that email, log in instead <a href='/login'>click here</a>"))
            return redirect(url_for('register'))
        elif user_name_db:
            flash(Markup("You've already signed up with that Name, log in instead <a href='/login'>click here</a>"))
            return redirect(url_for('register'))

        # way to check if the email is exists

        # if User.query.filter_by(email=request.form.get('email')).first:
        #     # User already exists
        #     # Markup is tool allow us to insert link in flash message
        #     flash(Markup("You've already signed up with that email, log in instead <a href='/login'>click here</a>"))
        #     return redirect(url_for('register'))

        hashed_password = generate_password_hash(pas, method='pbkdf2:sha256', salt_length=8)

        new_user = User(
            name=request.form.get("name").capitalize(),
            password=hashed_password,
            email=request.form.get("email").capitalize()
        )
        db.session.add(new_user)
        db.session.commit()

        # Log in and authenticate user after adding details to database.
        # This line will authenticate the user with Flask-Login
        login_user(new_user)

        return redirect(url_for("secrets"))
        # بعد ما اضفنا خاصيه flask login ماعاد احتجنا للكود اللي تحت لان صرنا نتحكم ونعرف العضو اللي مسجل دخول
        # return redirect(url_for("secrets", name=new_user.name))

    return render_template("register.html")


@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        password = request.form.get("password")
        email = request.form.get("email").capitalize()
        # find user by email entered
        user = User.query.filter_by(email=email).first()
        # EMAIL DOSEN'T EXIST IN THE DB
        if not user:
            flash(Markup("The email is not Exist Register instead <a href='/register'>click here</a>"))
            return redirect(url_for('login'))
        # Password not correct
        elif not check_password_hash(user.password, password):
            flash("Password incorrect, please try again")
            return redirect(url_for("login"))
        # email exists and password is correct
        else:
            login_user(user)
            return redirect(url_for("secrets"))

    return render_template("login.html")


@app.route("/delete-comment/<int:index>/<int:comment_id>", methods=["GET", "POST"])
@login_required
def delete_comment(index, comment_id):
    comment_to_delete = Comment.query.get(comment_id)
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for('show_post', index=index))


from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, Length, Email, ValidationError, EqualTo
from flask_wtf.file import FileField, FileAllowed


class UpdateAccountForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField("Email", validators=[DataRequired(), Email()])
    picture = FileField("update profile Picture", validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField("Update")

    def validate_username(self, username):
        # Custom validators
        # https://wtforms.readthedocs.io/en/2.3.x/validators/#custom-validators
        # هنا اضفنا خانه زياده اف عشان تشيك لو العضو ضغط على تعديل ولا عدل شي لو حطينا مثل
        # registrationForm معناها بيكون فيه مشكله لو ماعدل شي
        if username.data != current_user.name:
            user_case_sensitive = User.query.filter(func.lower(User.name) == func.lower(username.data)).first()
            user = User.query.filter_by(name=username.data).first()
            if user:
                raise ValidationError('That user name is Taken, please choose another one')

            elif user_case_sensitive:

                raise ValidationError("User is already exist try another one ")

    def validate_email(self, email):

        # الكود اللي تحت معناها لو اليوزر دخل الفورم ولا عدل شي يبقى الفورم مثل ماهو عشان لو
        # ماحطيناه بيشيك وبيعطي غلط
        if email.data != current_user.email:
            # to check the case sensitive letter for emails in database
            check_email = User.query.filter(func.lower(User.email) == func.lower(email.data)).first()
            email = User.query.filter_by(email=email.data).first()
            if check_email:
                raise ValidationError("that email is Taken try another user")
            elif email:
                raise ValidationError("email is already exist try another one ")



class RequestResetForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

    # def validate_email(self, email):
    #     check_email = User.query.filter(func.lower(User.email) == func.lower(email.data)).first()
    #     user = User.query.filter_by(email=email.data).first()
    #     if user is None:
    #         raise ValidationError('There is no account with that email. You must register first.')
    #     if check_email is None:
    #         raise ValidationError('There is no account with that email. You must register first.')



class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')


import random
import string


# from PIL import Image
def save_picture(form_picture):
    # to generate random name to the picture

    random_name = ''.join(random.choice(string.ascii_lowercase) for i in range(16))
    f_name, f_ext = os.path.splitext(form_picture.filename)
    picture_name = random_name + f_ext
    picture_name.save.os.path.join(app.root_path, 'static/profile_pics', picture_name)

    # get the extenstion
    # file name is the attribute for the form_picture
    # استخدمنا الكود اللي تحت عشان نقسم الملف الى قسمين الامتداد واسم الملف او الباث حقه
    # f_name, f_ext = os.path.splitext(form_picture.filename)
    # بعد ماخذنا الامتداد اضفناه للهكس عشان نولد له اسم
    # picture_fn = random_hex + f_ext
    # path to save the picture
    # اللي تحت طلعنا الباث كامل وسوينا جون ل اسم الملف اللي فيه الصور
    # هنا اضفنا باث حفظ الصوره كامل
    # picture_path = os.path.join(app.root_path, "static/profile_pics", picture_fn)
    # picture_fn.save(os.path.join(app.root_path, 'static/profile_pics', picture_file))
    # form.picture.data.save(os.path.join(app.root_path, 'static/profile_pics', picture_file))
    # resize the picture
    # output_size = (125, 125)
    # i = Image.open(form_picture)
    # i.thumbnail(output_size)
    # i.save(picture_path)
    # i.save(picture_path)
    return picture_name


@app.route("/account", methods=["GET", "POST"])
@login_required
# this page won't be available if the user is not log in
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            # استخدمنا الكود اللي تحت عشان نقسم الملف الى قسمين الامتداد واسم الملف او الباث حقه
            f_name, f_ext = os.path.splitext(form.picture.data.filename)
            # generate random name to the picture file name
            picture_file = ''.join(random.choice(string.ascii_lowercase) for i in range(16)) + f_ext

            picture_secure = secure_filename(form.picture.data.filename)
            form.picture.data.save(os.path.join(app.root_path, 'static/profile_pics', picture_file))
            current_user.image_file = picture_file
        # تحديث الاسم والايميل
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash("your account has been updasted", 'success')
        return redirect(url_for('account'))
    # عشان تطلع اسم اليوزر والايميل دايركت
    elif request.method == "GET":
        form.username.data = current_user.name
        form.email.data = current_user.email
    # image_file is in the models created when the user created
    image_file = url_for("static", filename='profile_pics/' + current_user.image_file)
    return render_template("account.html", title="Account"
                           , image_file=image_file, form=form)


@app.route("/secrets")
@login_required
def secrets():
    # this name is the name iside the return redirect(url_for("secrets",name=new_user.name)) in the register route
    # name = request.args.get('name')

    # بعد ما اضفنا خاصيه flask login ماعاد احتجنا للكود اللي فوق لان صرنا نتحكم ونعرف العضو اللي مسجل دخول
    return render_template("secrets.html", name=current_user.name)


@app.route("/download")
@login_required
def download():
    return send_from_directory("static", filename='files/cheat_sheet.pdf')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='alsultan_adel1992@yahoo.com',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}
If you did not make this request then simply ignore this email and no changes will be made.
'''
    mail.send(msg)


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        email = form.email.data
        email_cap = email.capitalize()
        user = User.query.filter_by(email=email_cap).first()
        send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if user is None:
        flash('That is an invalid or expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=True)
