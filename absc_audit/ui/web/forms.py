# absc_audit/ui/web/forms.py

"""
Web Forms - Web interface form modules.

This module defines the forms used in the Flask web interface.
"""

from flask_wtf import FlaskForm
from wtforms import (
    StringField, PasswordField, TextAreaField, SelectField,
    SelectMultipleField, BooleanField, IntegerField, HiddenField,
    widgets, SubmitField
)
from wtforms.validators import DataRequired, Email, EqualTo, Optional, Length, NumberRange, Regexp


class MultiCheckboxField(SelectMultipleField):
    """Field for multiple selection with checkboxes."""
    widget = widgets.ListWidget(prefix_label=False)
    option_widget = widgets.CheckboxInput()


class LoginForm(FlaskForm):
    """Login form."""
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember me')


class RegisterForm(FlaskForm):
    """Form for registering a new user."""
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=30)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters long')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])


class UserForm(FlaskForm):
    """User management form."""
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=30)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    role = SelectField('Role', choices=[
        ('user', 'User'),
        ('admin', 'Administrator')
    ])
    password = PasswordField('Password', validators=[Optional(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[
        Optional(),
        EqualTo('password', message='Passwords must match')
    ])
    enabled = BooleanField('Enabled', default=True)


class ProfileForm(FlaskForm):
    """User profile modification form."""
    email = StringField('Email', validators=[DataRequired(), Email()])
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[Optional(), Length(min=8)])
    confirm_password = PasswordField('Confirm New Password', validators=[
        Optional(),
        EqualTo('new_password', message='Passwords must match')
    ])


class TargetForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(message="Name is required")])
    hostname = StringField('Hostname')
    ip_address = StringField('IP Address', validators=[
        Optional(),
        # Add IP address validator if needed
    ])
    os_type = SelectField('Operating System', choices=[
        ('', 'Select'),
        ('windows', 'Windows'),
        ('linux', 'Linux'),
        ('macos', 'macOS'),
        ('other', 'Other')
    ])
    os_version = StringField('OS Version')
    description = TextAreaField('Description')
    group = StringField('Group')
    tags = StringField('Tags')

    submit = SubmitField('Save')


class NetworkScanForm(FlaskForm):
    scan_name = StringField('Scan Name',
                            validators=[DataRequired(message="Scan name is required")],
                            default="Network Scan"
                            )
    description = StringField('Description (optional)')

    network_ranges = StringField('Network Ranges (e.g. 192.168.1.0/24)',
                                 validators=[Optional()],
                                 description="Enter network ranges separated by comma"
                                 )

    scan_method = SelectField('Scan Method',
                              choices=[
                                  ('nmap', 'Nmap'),
                                  ('scapy', 'Scapy')
                              ],
                              default='nmap'
                              )

    ports = StringField('Ports to Scan',
                        default='22,80,443,3389',
                        description="Enter ports separated by comma"
                        )

    detailed = SelectField('Scan Type',
                              choices=[
                                  ('basic', 'Basic'),
                                  ('detailed', 'Detailed'),
                                  ('vulnerability', 'Vulnerability')
                              ],
                              default='vulnerability'
                              )
    save_targets = BooleanField('Save Devices as Targets')

    submit = SubmitField('Start Scan')


class ScheduledAuditForm(FlaskForm):
    """Scheduled audit management form."""
    name = StringField('Name', validators=[DataRequired()])
    description = TextAreaField('Description')

    target_ids = SelectMultipleField('Targets', validators=[DataRequired()], coerce=str)
    check_ids = SelectMultipleField('Checks', validators=[DataRequired()], coerce=str)

    frequency = SelectField('Frequency', choices=[
        ('daily', 'Daily'),
        ('weekly', 'Weekly'),
        ('monthly', 'Monthly')
    ])

    day_of_week = SelectField('Day of Week', choices=[
        (0, 'Monday'),
        (1, 'Tuesday'),
        (2, 'Wednesday'),
        (3, 'Thursday'),
        (4, 'Friday'),
        (5, 'Saturday'),
        (6, 'Sunday')
    ], coerce=int)

    day_of_month = IntegerField('Day of Month', validators=[Optional(), NumberRange(min=1, max=31)])
    hour = IntegerField('Hour (0-23)', validators=[DataRequired(), NumberRange(min=0, max=23)])
    minute = IntegerField('Minute (0-59)', validators=[DataRequired(), NumberRange(min=0, max=59)])

    enabled = BooleanField('Enabled', default=True)
    notify_on_completion = BooleanField('Notify on Completion')
    notify_email = StringField('Notification Email', validators=[Optional(), Email()])


class ReportForm(FlaskForm):
    """Report generation form."""
    name = StringField('Report Name', validators=[DataRequired()])
    description = TextAreaField('Description')

    target_ids = SelectMultipleField('Targets', coerce=str)
    categories = MultiCheckboxField('Categories', coerce=str)

    format = SelectField('Format', choices=[
        ('html', 'HTML'),
        ('json', 'JSON'),
        ('csv', 'CSV'),
        ('pdf', 'PDF')
    ])