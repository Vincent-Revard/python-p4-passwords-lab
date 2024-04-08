#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.future import select


from config import app, db, api
from models import User


class Signup(Resource):
    def post(self):
        data = request.get_json(force=True)
        username = data.get("username")
        password = data.get("password")
        if not username or not password:
            return {"message": "Missing 'username' or 'password' in request data"}, 400
        user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(user)
        try:
            db.session.commit()
            return {"id": user.id, "username": user.username}, 201
        except SQLAlchemyError:
            return {"message": "Database error occurred"}, 500


class Login(Resource):
    def post(self):
        data = request.get_json(force=True)
        username = data.get("username")
        password = data.get("password")
        if not username or not password:
            return {"message": "Missing 'username' or 'password' in request data"}, 400
        with db.engine.begin() as connection:
            result = connection.execute(select(User).where(User.username == username))
            user = result.fetchone()
            if user and check_password_hash(user.password_hash, password):
                session["user_id"] = user.id
                session["username"] = user.username
                return {"id": user.id, "username": user.username}, 200
        return {"message": "Invalid credentials"}, 401


class ClearSession(Resource):
    def delete(self):
        session.pop("user_id", None)
        session.pop("username", None)
        return {}, 204


class CheckSession(Resource):
    def get(self):
        if (user_id := session.get("user_id")) is not None:
            with db.engine.begin() as connection:
                result = connection.execute(select(User).where(User.id == user_id))
                user = result.fetchone()
                if user is not None:
                    return {"id": user.id, "username": user.username}, 200
        return {"message": "No user in session"}, 204

class Logout(Resource):
    def delete(self):
        session["user_id"] = None
        session["username"] = None
        return {}, 204

api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, "/check_session", endpoint="check_session")
api.add_resource(Login, "/login", endpoint="login")
api.add_resource(Logout, "/logout", endpoint="logout")

if __name__ == '__main__':
    app.run(port=5555, debug=True)
