# After (remove unused imports)
from flask import request, jsonify
from flask_restful import Resource, reqparse
import jwt
import datetime
from flask_sqlalchemy import SQLAlchemy
from flask import Flask, request, jsonify
from flask_restful import Api, Resource, reqparse

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres.wkuspdgxgphmyfjirsdm:dhanush@aws-0-ap-south-1.pooler.supabase.com:5432/postgres"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = "sdkfjghodsfhk"  # Replace with a strong secret key
db = SQLAlchemy(app)
# db.init_app(app)
api = Api(app)
from flask_cors import CORS
CORS(app)
CORS(app, resources={r"/*": {"origins": "*"}})

# Import the initialization function for the database
# from app.utils.db import init_db

# # Import Resources
# from resources.user import UserRegisterAPI, UserLoginAPI
# from resources.cart import CartAPI, ScanCartAPI
# from resources.checkout import CheckoutAPI

# Initialize Database with Application Context
# creating the datbase tables

# models py file
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default="active")  # active, checked_out
    total_amount = db.Column(db.Float, default=0.0)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cart_id = db.Column(db.Integer, db.ForeignKey('cart.id'), nullable=False)
    product_name = db.Column(db.String(100), nullable=False)
    cost = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, default=1)


# user py file
from flask_restful import Resource, reqparse
from werkzeug.security import generate_password_hash, check_password_hash
# from app.models import User
# from app.run import database

class UserRegisterAPI(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str, required=True, help='Name is required')
        parser.add_argument('email', type=str, required=True, help='Email is required')
        parser.add_argument('password', type=str, required=True, help='Password is required')
        data = parser.parse_args()

        # Check if user already exists
        if User.query.filter_by(email=data['email']).first():
            return {'status': 'fail', 'message': 'Email already registered'}, 400

        # Hash the password
        hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
        # Create a new user
        new_user = User(name=data['name'], email=data['email'], password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return {'status': 'success', 'message': 'User registered successfully'}, 201


class UserLoginAPI(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('email', type=str, required=True, help='Email is required')
        parser.add_argument('password', type=str, required=True, help='Password is required')
        data = parser.parse_args()

        # Check if user exists
        user = User.query.filter_by(email=data['email']).first()
        if not user:
            return {'status': 'fail', 'message': 'User not found'}, 404

        # Verify password
        if not check_password_hash(user.password, data['password']):
            return {'status': 'fail', 'message': 'Invalid credentials'}, 401

            # Return user info (Here you can implement session/token-based authentication later)
        return {
            'status': 'success',
            'message': 'Login successful',
            'user_id': user.id,
            'user_name': user.name
        }, 200


# cart update py file
from flask_restful import Resource, reqparse
# from app.models import Cart, Product
# from app import db

class AddProductAPI(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('cart_id', type=int, required=True, help='Cart ID is required')
        parser.add_argument('product_id', type=int, required=True, help='Product ID is required')
        parser.add_argument('product_name', type=str, required=True, help='Product name is required')
        parser.add_argument('cost', type=float, required=True, help='Product cost is required')
        parser.add_argument('quantity', type=int, required=True, help='Quantity is required')
        data = parser.parse_args()

        # Check if the cart exists and is active
        cart = Cart.query.filter_by(id=data['cart_id'], status='active').first()
        if not cart:
            return {'status': 'fail', 'message': 'Active cart not found'}, 404

        # Add or update product in the cart
        product = Product.query.filter_by(cart_id=cart.id, id=data['product_id']).first()
        if product:
            product.quantity += data['quantity']  # Update quantity if product already exists
        else:
            product = Product(
                id=data['product_id'],
                product_name=data['product_name'],
                cost=data['cost'],
                quantity=data['quantity'],
                cart_id=cart.id
            )
            db.session.add(product)

        db.session.commit()
        return {'status': 'success', 'message': 'Product added/updated successfully'}, 200


class RemoveProductAPI(Resource):
    def delete(self):
        parser = reqparse.RequestParser()
        parser.add_argument('cart_id', type=int, required=True, help='Cart ID is required')
        parser.add_argument('product_id', type=int, required=True, help='Product ID is required')
        data = parser.parse_args()

        # Check if the cart exists and is active
        cart = Cart.query.filter_by(id=data['cart_id'], status='active').first()
        if not cart:
            return {'status': 'fail', 'message': 'Active cart not found'}, 404

        # Remove product from the cart
        product = Product.query.filter_by(cart_id=cart.id, id=data['product_id']).first()
        if not product:
            return {'status': 'fail', 'message': 'Product not found in cart'}, 404

        db.session.delete(product)
        db.session.commit()

        return {'status': 'success', 'message': 'Product removed successfully'}, 200


# checkout py file
from flask_restful import Resource, reqparse
# from app.models import Cart, Product
# from app import db
import uuid

class CheckoutAPI(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('customer_id', type=int, required=True, help='Customer ID is required')
        parser.add_argument('customer_email', type=str, required=True, help='Customer email is required')
        parser.add_argument('customer_phone', type=str, required=True, help='Customer phone number is required')
        parser.add_argument('cart_id', type=int, required=True, help='Cart ID is required')
        data = parser.parse_args()

        # Check if the cart exists and is active
        cart = Cart.query.filter_by(id=data['cart_id'], user_id=data['customer_id'], status='active').first()
        if not cart:
            return {'status': 'fail', 'message': 'Active cart not found'}, 404

        # Calculate total amount
        products = Product.query.filter_by(cart_id=cart.id).all()
        if not products:
            return {'status': 'fail', 'message': 'Cart is empty'}, 400

        total_amount = sum(product.cost * product.quantity for product in products)

        # Generate a unique order ID
        order_id = str(uuid.uuid4())

        # Simulate payment process (can integrate with a payment gateway here)
        payment_details = {
            'customer_id': data['customer_id'],
            'customer_email': data['customer_email'],
            'customer_phone': data['customer_phone'],
            'order_id': order_id,
            'order_amount': total_amount,
            'order_currency': 'INR',
            'return_url': 'https://example.com/return_url'  # Replace with actual return URL
        }

        # Mark the cart as checked out
        cart.status = 'checked_out'
        cart.total_amount = total_amount
        db.session.commit()

        # Return confirmation response
        return {
            'status': 'success',
            'message': 'Checkout completed successfully',
            'order_id': order_id,
            'order_amount': total_amount,
            'payment_details': payment_details
        }, 200



# auth py file
from flask import request, jsonify
from flask_restful import Api, Resource, reqparse
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime

# User model definition is already present in app.py

# Request parsers
register_parser = reqparse.RequestParser()
register_parser.add_argument("username", type=str, required=True, help="Username is required")
register_parser.add_argument("email", type=str, required=True, help="Email is required")
register_parser.add_argument("password", type=str, required=True, help="Password is required")

login_parser = reqparse.RequestParser()
login_parser.add_argument("email", type=str, required=True, help="Email is required")
login_parser.add_argument("password", type=str, required=True, help="Password is required")

# User Registration
class Register(Resource):
    def post(self):
        args = register_parser.parse_args()
        username = args["username"]
        email = args["email"]
        password = args["password"]

        # Check if email already exists
        if User.query.filter_by(email=email).first():
            return {"message": "Email already registered"}, 400

        # Create a new user
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return {"message": "User registered successfully"}, 201


# User Login
class Login(Resource):
    def post(self):
        args = login_parser.parse_args()
        email = args["email"]
        password = args["password"]

        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password_hash, password):
            return {"message": "Invalid email or password"}, 401

        # Generate JWT token
        token = jwt.encode({
            "user_id": user.id,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        return {"token": token, "message": "Login successful"}, 200


# Secure Route Example
class Profile(Resource):
    def get(self):
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return {"message": "Token is missing"}, 401

        try:
            token = auth_header.split(" ")[1]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            user_id = data["user_id"]
            user = User.query.get(user_id)
            if not user:
                return {"message": "User not found"}, 404
        except jwt.ExpiredSignatureError:
            return {"message": "Token has expired"}, 401
        except jwt.InvalidTokenError:
            return {"message": "Invalid token"}, 401

        return {
            "user_id": user.id,
            "username": user.username,
            "email": user.email
        }, 200


# cart py file
from flask_restful import Resource, reqparse
# from app.models import Cart, Product, User
# from app import db

class ScanCartAPI(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('cart_id', type=int, required=True, help='Cart ID is required')
        parser.add_argument('user_id', type=int, required=True, help='User ID is required')
        data = parser.parse_args()

        # Check if user exists
        user = User.query.get(data['user_id'])
        if not user:
            return {'status': 'fail', 'message': 'User not found'}, 404

        # Check if cart exists or create a new one
        cart = Cart.query.filter_by(id=data['cart_id'], user_id=data['user_id'], status='active').first()
        if not cart:
            cart = Cart(id=data['cart_id'], user_id=data['user_id'])
            db.session.add(cart)
            db.session.commit()

        return {'status': 'success', 'message': 'Cart linked successfully', 'cart_id': cart.id}, 200


class CartAPI(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('cart_id', type=int, required=True, help='Cart ID is required')
        parser.add_argument('user_id', type=int, required=True, help='User ID is required')
        data = parser.parse_args()

        # Fetch cart and its products
        cart = Cart.query.filter_by(id=data['cart_id'], user_id=data['user_id'], status='active').first()
        if not cart:
            return {'status': 'fail', 'message': 'Active cart not found'}, 404

        products = Product.query.filter_by(cart_id=cart.id).all()
        products_data = [
            {
                'product_id': product.id,
                'product_name': product.product_name,
                'cost': product.cost,
                'quantity': product.quantity
            }
            for product in products
        ]

        return {'status': 'success', 'cart_id': cart.id, 'products': products_data}, 200


class cart_status(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('cart_id', type=int, required=True, help='Cart ID is required')
        parser.add_argument('user_id', type=int, required=True, help='User ID is required')
        data = parser.parse_args()

        # Fetch cart and its products
        cart = Cart.query.filter_by(id=data['cart_id'], user_id=data['user_id'], status='active').first()
        if not cart:
            return {'status': 'fail', 'message': 'Active cart not found'}, 404

        return { 'cart_id': cart.id, 'status': cart.status}, 200



# Add resources to API
api.add_resource(Register, "/register")
api.add_resource(Login, "/login")
api.add_resource(Profile, "/profile")
# Register resources with unique endpoint names to avoid conflicts
api.add_resource(UserRegisterAPI, '/user/register', endpoint='user_register')
api.add_resource(UserLoginAPI, '/user/login', endpoint='user_login')
api.add_resource(ScanCartAPI, '/cart/identify', endpoint='scan_cart')
api.add_resource(CartAPI, '/cart/products', endpoint='cart_products')
api.add_resource(CheckoutAPI, '/cart/checkout', endpoint='checkout')
api.add_resource(AddProductAPI, '/cart/add_product', endpoint='add_product')
api.add_resource(RemoveProductAPI, '/cart/remove_product', endpoint='remove_product')
api.add_resource(cart_status, '/cart/status', endpoint='cart_status')
# Add resources to API

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        db.session.commit()
    app.run(debug=True)