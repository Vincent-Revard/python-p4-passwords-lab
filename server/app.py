from flask import request, session
from flask_restful import Resource, Api
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.future import select


from config import app, db, api
from models import User

class Signup(Resource):

    def post(self):
        data = request.get_json(force=True)
        if not data:
            return {"message": "No input data provided"}, 400
        username = data.get("username")
        password = data.get("password")
        if not username or not password:
            return {"message": "Missing 'username' or 'password' in request data"}, 400
        user = User(username=username)
        user.password_hash = password
        db.session.add(user)
        try:
            db.session.commit()
            return {"id": user.id, "username": user.username}, 201
        except SQLAlchemyError:
            return {"message": "Database error occurred"}, 500

class Login(Resource):

    def post(self):
        data = request.get_json(force=True)
        if not data:
            return {"message": "No input data provided"}, 400
        username = data.get("username")
        password = data.get("password")
        if not username or not password:
            return {"message": "Missing 'username' or 'password' in request data"}, 400
        result = db.session.execute(select(User).where(User.username == username))
        user = result.scalars().first()
        if user and user.authenticate(password):
            session["user_id"] = user.id
            session["username"] = user.username
            return {"id": user.id, "username": user.username}, 200
        return {"id": None, "username": None, "message": "Invalid credentials"}, 401

class CheckSession(Resource):

    def get(self):
        if (user_id := session.get("user_id")) is not None:
            user = db.session.get(User, user_id)
            if user is not None:
                return {"id": user.id, "username": user.username}, 200
        return {"message": "No user in session"}, 204
class Logout(Resource):
    def delete(self):
        session["user_id"] = None
        session["username"] = None
        return {}, 204


api.add_resource(Signup, "/signup", endpoint="signup")
api.add_resource(CheckSession, "/check_session", endpoint="check_session")
api.add_resource(Login, "/login", endpoint="login")
api.add_resource(Logout, "/logout", endpoint="logout")


if __name__ == '__main__':
    app.run(port=5555, debug=True)
