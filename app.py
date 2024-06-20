from email.policy import default
import datetime
from math import prod
from unicodedata import name
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import requests
from random import randint


app = Flask(__name__)

app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['QLALCHEMY_TRACK_MODIFICATIONS']=False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

class Product(db.Model):
    pid = db.Column(db.Integer, primary_key=True)
    pname = db.Column(db.String(50),unique=False)
    pquantity = db.Column(db.Integer,unique=False)
    pcategory = db.Column(db.String(50),unique=False)
    psub = db.Column(db.String(50),unique=False)
    pprice = db.Column(db.Integer,unique=False)
    pphoto=db.Column(db.String(180),default='profile.jpg')

class Cart(db.Model):
    oid=db.Column(db.String(50),primary_key=True)
    cid=db.Column(db.String(50),unique=False)
    cmail=db.Column(db.String(50),unique=False)
    cname = db.Column(db.String(50),unique=False)
    prod_index=db.Column(db.Integer,unique=False)
    prod_name = db.Column(db.String(50),unique=False)
    prod_price = db.Column(db.Integer,unique=False)
    prod_quan=db.Column(db.Integer,unique=False)
    total=db.Column(db.Integer)
    over_all=db.Column(db.Integer)



class Order(db.Model):
    sno = db.Column(db.Integer, primary_key=True)
    oid=db.Column(db.String(50),unique=False)
    cid=db.Column(db.String(50),unique=False)
    cmail=db.Column(db.String(50),unique=False)
    cname = db.Column(db.String(50),unique=False)
    prod_index=db.Column(db.Integer,unique=False)
    prod_name = db.Column(db.String(50),unique=False)
    prod_price = db.Column(db.Integer,unique=False)
    prod_quan=db.Column(db.Integer,unique=False)
    total=db.Column(db.Integer)
    over_all=db.Column(db.Integer)
    con_flag=db.Column(db.Integer,unique=False)
    date=db.Column(db.Integer,unique=False)
    
class Order_Status(db.Model):
    sno = db.Column(db.Integer, primary_key=True)
    oid=db.Column(db.String(50),unique=False)
    cid=db.Column(db.String(50),unique=False)
    status=db.Column(db.String(50),unique=False)

class Category(db.Model):
    sno = db.Column(db.Integer, primary_key=True)
    psub=db.Column(db.String(50),unique=False)

class Contact(db.Model):
    name=db.Column(db.String(50),unique=False)
    phone=db.Column(db.String(50),primary_key=True)
    email=db.Column(db.String(50),unique=False)
    message= db.Column(db.String(50),unique=False)
    

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=5, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])



@app.route('/home')
def home():
    total=0
    allProd = Product.query.all() 
    allCart=Cart.query.all()
    
    return render_template("home.html",allTodo=allProd,allCart=allCart)

@app.route('/addproduct')
def product():
    return render_template('addproduct.html')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/products')
def view_product():
    product=Product.query.all()
    return render_template('products.html',product=product)

@app.route('/about')
def about():
    return render_template('about.html')





@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    allTodo = User.query.all() 
    print(allTodo)
    
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        print(user)
        
        if user:
            login_user(user)
            return redirect(url_for('shop'))
        else:
            flash('Invalid username or password')
            return render_template('login.html', form=form)
    
    return render_template('login.html', form=form)

@app.route('/shop')
def shop():
    # Assuming you have a view function for the shop page
    return render_template('shop.html')
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    allTodo = User.query.all() 
    form = RegisterForm()
    if form.validate_on_submit():
        # hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=form.password.data)
        db.session.add(new_user)
        db.session.commit()

        flash('You are registered')
        return redirect(url_for('home'))

    return render_template('signup.html', form=form)

@app.route('/add', methods=['GET', 'POST'])
def addproduct():
    if request.method=='POST':
        pname = request.form['pname']
        pquantity = request.form['pquantity']
        pcategory=request.form['pcategory']
        psub=request.form['psub']
        pprice = request.form['pprice']
        pphoto = request.form['pphoto']
    
    category=Category.query.filter_by(psub=psub).first()
    if category:
        category.psub=psub
    else:
        psub=psub

    new_category=Category(psub=psub)
    new_product = Product(pname = pname,pquantity = pquantity,pcategory=pcategory,psub=psub,pprice = pprice,pphoto=pphoto)
    db.session.add(new_product)
    db.session.add(new_category)
    db.session.commit()

    product= Product.query.all() 
    return redirect(url_for('view_product',product=product))

@app.route('/del_prod/<int:pid>', methods=['GET', 'POST'])
@login_required
def del_prod(pid):
    product=Product.query.all()
    delete = Product.query.filter_by(pid=pid).first()
    db.session.delete(delete)
    db.session.commit()
    return redirect(url_for('view_product',product=product))

@app.route('/search',methods=['GET'])

def search():
    brand = request.args['search']
    brand=brand.title()
    if brand=='':
         show = Product.query.all()
         return render_template('shop.html',show=show)
    else:
        show = Product.query.filter_by(pname=brand) 
        return render_template('search.html',show=show,brand=brand)

@app.route('/view_cart')
@login_required
def view_cart():
    flag=0
    cart_flag=Cart.query.filter_by(cmail=current_user.email).first()
    cart=Cart.query.filter_by(cmail=current_user.email)
    if cart_flag:
        flag=1
    else:
        flag=0
    product=Product.query.all()
    return render_template('view_cart.html',cart=cart,product=product,flag=flag)



@app.route('/add_to_cart/<int:pid>', methods=['GET', 'POST'])
@login_required
def add_to_cart(pid):
    todo = Product.query.filter_by(pid=pid).first()
    user = current_user
    
    if not todo:
        flash('Product not found')
        return redirect(url_for('shop'))
    
    flag = Cart.query.filter_by(cmail=user.email, prod_index=pid).first()
    total = todo.pprice
    if flag:
        flag.prod_quan += 1
        flag.total += total
        db.session.commit()
    else:
        sum_total = Cart.query.with_entities(func.sum(Cart.total)).filter_by(cmail=user.email).scalar() or 0
        new_cart = Cart(
            oid=randint(1, 100000),
            cid=user.id,
            cmail=user.email,
            cname=user.username,
            prod_index=todo.pid,
            prod_name=todo.pname,
            prod_price=todo.pprice,
            prod_quan=1,
            total=total,
            over_all=sum_total + total
        )
        db.session.add(new_cart)
        db.session.commit()

    # Update over_all for all cart items
    update_overall(user.email)

    flash('Product was added')
    return redirect("/show_brand?brand=all")

def update_overall(email):
    sum_total = Cart.query.with_entities(func.sum(Cart.total)).filter_by(cmail=email).scalar() or 0
    carts = Cart.query.filter_by(cmail=email).all()
    for cart in carts:
        cart.over_all = sum_total
    db.session.commit()


@app.route('/del_cart/<int:pid>', methods=['GET', 'POST'])
@login_required
def del_cart(pid):
    cart=Cart.query.filter_by(cmail=current_user.email)
    
    product=Product.query.all()
    delete = Cart.query.filter_by(prod_index=pid,cmail=current_user.email).first()
    delete_order = Order.query.filter_by(oid=delete.oid).first()
    db.session.delete(delete)
    db.session.delete(delete_order)
    db.session.commit()
    
    return redirect(url_for('view_cart',cart=cart,product=product))


@app.route('/update_cart/<int:pid>', methods=['GET', 'POST'])
@login_required
def update_cart(pid):
    quant=request.args.get('prod_quan')
    cart=Cart.query.filter_by(cmail=current_user.email)
    if cart:
        update=Cart.query.filter_by(prod_index=pid,cmail=current_user.email).first()
        prod_quantity=quant
        db.session.delete(update)
    new_cart=Cart(oid=update.oid,cid=update.cid,cmail=update.cmail,cname =update.cname,prod_index=update.prod_index,prod_name =update.prod_name,prod_price =update.prod_price,prod_quan=prod_quantity,total=update.total,over_all=update.over_all)
    db.session.add(new_cart)
    db.session.commit()
    flash('product was added')
    return render_template('view_cart.html')


@app.route('/show_brand',methods=['GET'])

def show_brand():
    brand = request.args['brand']
    if brand=='all':
         show = Product.query.all()
         return render_template('shop.html',show=show)
    else:
        show = Product.query.filter_by(pcategory=brand)
        return render_template('show_brand.html',show=show,brand=brand)

@app.route('/show_sub',methods=['GET'])

def show_sub():
    brand = request.args['brand']
    show = Product.query.filter_by(psub=brand)
    return render_template('show_sub.html',show=show,brand=brand)

@app.route('/checkout', methods=['GET'])
@login_required
def checkout():
    cart = Cart.query.filter_by(cmail=current_user.email).all()
    prod = Product.query.all()
    sum_total = Cart.query.with_entities(func.sum(Cart.total)).filter_by(cmail=current_user.email).scalar() or 0
    return render_template('checkout.html', cart=cart, prod=prod, sum=sum_total)


@app.route('/confirm', methods=['GET'])
@login_required
def confirm():
    # Order by oid (Order ID) if it exists
    con = Order.query.filter_by(cmail=current_user.email).order_by(Order.oid.desc()).first()
    
    if con:
        product = Product.query.filter_by(pid=con.prod_index).first()
        if product:
            product.pquantity = product.pquantity - con.prod_quan
            status = Order_Status(oid=con.oid, cid=con.cid, status="Received")
            db.session.add(status)

            cart_items = Cart.query.filter_by(cname=current_user.username).all()
            con.con_flag = 1 
            
            # Deleting all items in the cart for the current user
            for item in cart_items:
                db.session.delete(item)
                
            db.session.add(product)
            db.session.commit()
        else:
            flash("Product not found.")
    else:
        flash("Order not found.")
        
    return redirect(url_for('order'))


@app.route('/contact', methods=['POST'])
def contact():
    if request.method=='POST':
        cname = request.form['name']
        cemail = request.form['email']
        cphone=request.form['phone']
        cmessage = request.form['message']
        

    new_contact = Contact(name = cname,email = cemail,phone=cphone,message = cmessage)
    db.session.add(new_contact)
    db.session.commit()
    allTodo=Product.query.all()
    flash('Message submitted')
    return render_template('home.html',allTodo=allTodo)  
@app.route('/dashboard')
@login_required
def dashboard():
    user=User.query.filter_by(username=current_user.username)
    order=Order.query.filter_by(cname=current_user.username,con_flag=1)
    return render_template('dashboard.html',user=user,order=order)

@app.route('/admin')
@login_required
def admin():
    if current_user.username=='faizan':
        return render_template('admin.html')
    else:
        flash('You are not admin')
        return render_template('home.html')

@app.route('/user_details')
@login_required
def user_details():
    user=User.query.all()
    return render_template('user_details.html',user=user)

@app.route('/order_details')
@login_required
def order_details():
    cart=Cart.query.all()
    order=Order.query.all()
    product=Product.query.all()
    status=Order_Status.query.all()
    return render_template('order_details.html',order=order,product=product,cart=cart,status=status)

@app.route('/show_status')
@login_required
def show_status():
    status = request.args['status']
    show = Order_Status.query.filter_by(status=status)
    order=Order.query.all()
    product=Product.query.all()
  
    return render_template('show_status.html',order=order,product=product,show=show,status=status)

@app.route('/sales')
@login_required
def sales():
    show = Order_Status.query.filter_by(status="Received")
    order=Order.query.all()
    product=Product.query.all()

    return render_template('show_status.html',order=order,product=product,show=show,status=status)


@app.route('/update_statusp/<int:oid>', methods=['GET', 'POST'])
@login_required
def update_statusp(oid):
   
    ostatus=Order_Status.query.filter_by(oid=oid).first()
    ostatus.oid = ostatus.oid
    ostatus.cid = ostatus.cid
    ostatus.status = "Packed"
    db.session.add(ostatus)
    db.session.commit()
    return redirect(url_for('order_details'))

@app.route('/update_statusd/<int:oid>', methods=['GET', 'POST'])
@login_required
def update_statusd(oid):
   
    ostatus=Order_Status.query.filter_by(oid=oid).first()
    ostatus.oid = ostatus.oid
    ostatus.cid = ostatus.cid
    ostatus.status = "Dispatched"
    db.session.add(ostatus)
    db.session.commit()
    return redirect(url_for('order_details'))

@app.route('/update_statusr/<int:oid>', methods=['GET', 'POST'])
@login_required
def update_statusr(oid):
  
    ostatus=Order_Status.query.filter_by(oid=oid).first()
    ostatus.oid = ostatus.oid
    ostatus.cid = ostatus.cid
    ostatus.status = "Delivered"
    db.session.add(ostatus)
    db.session.commit()
    return redirect(url_for('order_details'))

@app.route('/del_order/<int:oid>', methods=['GET', 'POST'])
@login_required
def del_order(oid):
    if current_user.username=='deepika':
        order=Order.query.all()
        delete = Order.query.filter_by(oid=oid,).first()
        db.session.delete(delete)
        db.session.commit()
        return redirect(url_for('order_details'))     
@app.route('/status')
@login_required
def status():
    cart=Cart.query.all()
    order=Order.query.all()
    product=Product.query.all()
    status=Order_Status.query.all()
    # select = request.form.get('ostatus')
    # return(str(select))
    return render_template('order_details.html',order=order,product=product,cart=cart,status=status)

@app.route('/del_user/<int:id>', methods=['GET', 'POST'])
@login_required
def del_user(id):
    if current_user.username=='deepika':
        user=User.query.all()
        delete = User.query.filter_by(id=id,).first()
        db.session.delete(delete)
        db.session.commit()
        return redirect(url_for('user_details',user=user))
@app.route('/profile')
@login_required
def profile():
    user=User.query.filter_by(username=current_user.username)
    return render_template('profile.html',user=user)

@app.route('/order')
@login_required
def order():
    flag_cart=Cart.query.filter_by(cname=current_user.username).first()
    cart=Cart.query.filter_by(cname=current_user.username)
    order=Order.query.filter_by(cname=current_user.username)
    if flag_cart is None:
        flag=0
    else:
        flag=1
    product=Product.query.all()
   
    return render_template('order.html',order=order,cart=cart,product=product,flag=flag)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)