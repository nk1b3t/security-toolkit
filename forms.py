# forms.py
# WTForms validation for Security Toolkit

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, IntegerField, FloatField, SelectField
from wtforms.validators import (
    DataRequired, Length, Email, EqualTo, NumberRange, 
    ValidationError, Regexp
)
import re


# Custom Validators
class HostnameOrIP:
    """Validate hostname or IP address"""
    def __init__(self, message=None):
        if not message:
            message = 'Invalid hostname or IP address'
        self.message = message

    def __call__(self, form, field):
        value = field.data.strip()
        
        # Check for valid hostname pattern
        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        
        # Check for valid IPv4 pattern
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        
        if re.match(hostname_pattern, value):
            return
        
        if re.match(ipv4_pattern, value):
            # Validate each octet is 0-255
            octets = value.split('.')
            if all(0 <= int(octet) <= 255 for octet in octets):
                return
        
        raise ValidationError(self.message)


class SafePath:
    """Validate directory path is safe (no path traversal)"""
    def __init__(self, message=None):
        if not message:
            message = 'Invalid or unsafe path'
        self.message = message

    def __call__(self, form, field):
        value = field.data.strip()
        
        # Check for path traversal attempts
        dangerous_patterns = ['../', '..\\', '%2e%2e', '%252e%252e']
        
        for pattern in dangerous_patterns:
            if pattern in value.lower():
                raise ValidationError('Path traversal detected')
        
        # Allow only alphanumeric, spaces, dots, slashes, underscores, hyphens
        if not re.match(r'^[a-zA-Z0-9\s\.\/_\-:]+$', value):
            raise ValidationError(self.message)


# Authentication Forms
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message='Username is required'),
        Length(min=3, max=50, message='Username must be 3-50 characters'),
        Regexp(r'^[a-zA-Z0-9_]+$', message='Username can only contain letters, numbers, and underscores')
    ])
    
    password = PasswordField('Password', validators=[
        DataRequired(message='Password is required'),
        Length(min=6, max=128, message='Password must be at least 6 characters')
    ])
    
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message='Please confirm your password'),
        EqualTo('password', message='Passwords must match')
    ])


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message='Username is required'),
        Length(min=1, max=50)
    ])
    
    password = PasswordField('Password', validators=[
        DataRequired(message='Password is required')
    ])


class ForgotPasswordForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message='Username is required'),
        Length(min=3, max=50)
    ])
    
    new_password = PasswordField('New Password', validators=[
        DataRequired(message='New password is required'),
        Length(min=6, max=128, message='Password must be at least 6 characters')
    ])
    
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message='Please confirm your password'),
        EqualTo('new_password', message='Passwords must match')
    ])


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[
        DataRequired(message='Current password is required')
    ])
    
    new_password = PasswordField('New Password', validators=[
        DataRequired(message='New password is required'),
        Length(min=6, max=128, message='Password must be at least 6 characters')
    ])


# Port Scanner Form
class PortScanForm(FlaskForm):
    host = StringField('Host', validators=[
        DataRequired(message='Host is required'),
        Length(min=1, max=255, message='Host must be 1-255 characters'),
        HostnameOrIP()
    ])
    
    start_port = IntegerField('Start Port', validators=[
        DataRequired(message='Start port is required'),
        NumberRange(min=1, max=65535, message='Port must be between 1 and 65535')
    ])
    
    end_port = IntegerField('End Port', validators=[
        DataRequired(message='End port is required'),
        NumberRange(min=1, max=65535, message='Port must be between 1 and 65535')
    ])
    
    timeout = FloatField('Timeout', validators=[
        DataRequired(message='Timeout is required'),
        NumberRange(min=0.1, max=10.0, message='Timeout must be between 0.1 and 10 seconds')
    ])
    
    def validate_end_port(self, field):
        if field.data < self.start_port.data:
            raise ValidationError('End port must be greater than or equal to start port')


# File Integrity Form
class FileIntegrityForm(FlaskForm):
    directory = StringField('Directory', validators=[
        DataRequired(message='Directory is required'),
        Length(min=1, max=500, message='Directory path too long'),
        SafePath()
    ])
    
    algorithm = SelectField('Algorithm', 
        choices=[('sha256', 'SHA256'), ('md5', 'MD5'), ('sha1', 'SHA1')],
        validators=[DataRequired(message='Algorithm is required')]
    )