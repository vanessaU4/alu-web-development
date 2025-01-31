#!/usr/bin/env python3
""" Hashing """
import bcrypt
from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4
from db import DB
from user import User
from typing import Optional


def _hash_password(password: str) -> str:
    """Hashes a password and returns it as a UTF-8 encoded string."""
    return bcrypt.hashpw(
        password.encode('utf-8'),
        bcrypt.gensalt()
    ).decode('utf-8')


def _generate_uuid() -> str:
    """Returns a new UUID as a string."""
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database."""

    def __init__(self):
        """Constructor"""
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Registers a new user or raises a ValueError if the user exists."""
        try:
            user = self._db.find_user_by(email=email)
            raise ValueError(f'User {email} already exists')
        except NoResultFound:
            pwd = _hash_password(password)
            user = self._db.add_user(email, pwd)
            return user

    def valid_login(self, email: str, password: str) -> bool:
        """Validates user credentials and returns a boolean."""
        try:
            user = self._db.find_user_by(email=email)
            return bcrypt.checkpw(
                password.encode('utf-8'),
                user.hashed_password.encode('utf-8')
            )
        except NoResultFound:
            return False

    def create_session(self, email: str) -> Optional[str]:
        """Creates a session for a user and returns the session ID."""
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> Optional[User]:
        """Returns a User object if session ID exists, otherwise None."""
        try:
            return self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Destroys a user's session by setting session_id to None."""
        try:
            self._db.update_user(user_id, session_id=None)
        except NoResultFound:
            pass

    def get_reset_password_token(self, email: str) -> str:
        """Generates and returns a reset password token for a user."""
        try:
            user = self._db.find_user_by(email=email)
            token = _generate_uuid()
            self._db.update_user(user.id, reset_token=token)
            return token
        except NoResultFound:
            raise ValueError(f"No user found with email: {email}")

    def update_password(self, reset_token: str, password: str) -> None:
        """Updates the user's password if the reset token is valid."""
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            hashed_pwd = _hash_password(password)
            self._db.update_user(
                user.id, hashed_password=hashed_pwd, reset_token=None
            )
        except NoResultFound:
            raise ValueError("Invalid reset token.")
