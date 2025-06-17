# absc_audit/ui/web/forms.py

"""
Web Forms - Moduli form per l'interfaccia web.

Questo modulo definisce i form utilizzati nell'interfaccia web Flask.
"""

from flask_wtf import FlaskForm
from wtforms import (
    StringField, PasswordField, TextAreaField, SelectField,
    SelectMultipleField, BooleanField, IntegerField, HiddenField,
    widgets
)
from wtforms.validators import DataRequired, Email, EqualTo, Optional, Length, NumberRange


class MultiCheckboxField(SelectMultipleField):
    """Campo per selezione multipla con checkbox."""
    widget = widgets.ListWidget(prefix_label=False)
    option_widget = widgets.CheckboxInput()


class LoginForm(FlaskForm):
    """Form per il login."""
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Ricordami')


class RegisterForm(FlaskForm):
    """Form per la registrazione di un nuovo utente."""
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=30)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    first_name = StringField('Nome', validators=[DataRequired()])
    last_name = StringField('Cognome', validators=[DataRequired()])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='La password deve essere di almeno 8 caratteri')
    ])
    confirm_password = PasswordField('Conferma Password', validators=[
        DataRequired(),
        EqualTo('password', message='Le password devono coincidere')
    ])


class UserForm(FlaskForm):
    """Form per la gestione degli utenti."""
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=30)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    first_name = StringField('Nome', validators=[DataRequired()])
    last_name = StringField('Cognome', validators=[DataRequired()])
    role = SelectField('Ruolo', choices=[
        ('user', 'Utente'),
        ('admin', 'Amministratore')
    ])
    password = PasswordField('Password', validators=[Optional(), Length(min=8)])
    confirm_password = PasswordField('Conferma Password', validators=[
        Optional(),
        EqualTo('password', message='Le password devono coincidere')
    ])
    enabled = BooleanField('Abilitato', default=True)


class ProfileForm(FlaskForm):
    """Form per la modifica del profilo utente."""
    email = StringField('Email', validators=[DataRequired(), Email()])
    first_name = StringField('Nome', validators=[DataRequired()])
    last_name = StringField('Cognome', validators=[DataRequired()])
    current_password = PasswordField('Password Attuale', validators=[DataRequired()])
    new_password = PasswordField('Nuova Password', validators=[Optional(), Length(min=8)])
    confirm_password = PasswordField('Conferma Nuova Password', validators=[
        Optional(),
        EqualTo('new_password', message='Le password devono coincidere')
    ])


class TargetForm(FlaskForm):
    """Form per la gestione dei target."""
    name = StringField('Nome', validators=[DataRequired()])
    hostname = StringField('Hostname/IP', validators=[DataRequired()])
    ip_address = StringField('Indirizzo IP')
    os_type = SelectField('Sistema Operativo', choices=[
        ('windows', 'Windows'),
        ('linux', 'Linux/Unix'),
        ('macos', 'macOS'),
        ('network', 'Dispositivo di Rete'),
        ('other', 'Altro')
    ])
    os_version = StringField('Versione SO')
    description = TextAreaField('Descrizione')
    group = StringField('Gruppo')
    tags = StringField('Tag (separati da virgola)')


class ScheduledAuditForm(FlaskForm):
    """Form per la gestione degli audit pianificati."""
    name = StringField('Nome', validators=[DataRequired()])
    description = TextAreaField('Descrizione')

    target_ids = SelectMultipleField('Target', validators=[DataRequired()], coerce=str)
    check_ids = SelectMultipleField('Controlli', validators=[DataRequired()], coerce=str)

    frequency = SelectField('Frequenza', choices=[
        ('daily', 'Giornaliera'),
        ('weekly', 'Settimanale'),
        ('monthly', 'Mensile')
    ])

    day_of_week = SelectField('Giorno della Settimana', choices=[
        (0, 'Lunedì'),
        (1, 'Martedì'),
        (2, 'Mercoledì'),
        (3, 'Giovedì'),
        (4, 'Venerdì'),
        (5, 'Sabato'),
        (6, 'Domenica')
    ], coerce=int)

    day_of_month = IntegerField('Giorno del Mese', validators=[Optional(), NumberRange(min=1, max=31)])
    hour = IntegerField('Ora (0-23)', validators=[DataRequired(), NumberRange(min=0, max=23)])
    minute = IntegerField('Minuto (0-59)', validators=[DataRequired(), NumberRange(min=0, max=59)])

    enabled = BooleanField('Abilitato', default=True)
    notify_on_completion = BooleanField('Notifica al completamento')
    notify_email = StringField('Email per notifiche', validators=[Optional(), Email()])


class ReportForm(FlaskForm):
    """Form per la generazione dei report."""
    name = StringField('Nome del Report', validators=[DataRequired()])
    description = TextAreaField('Descrizione')

    target_ids = SelectMultipleField('Target', coerce=str)
    categories = MultiCheckboxField('Categorie', coerce=str)

    format = SelectField('Formato', choices=[
        ('html', 'HTML'),
        ('json', 'JSON'),
        ('csv', 'CSV'),
        ('pdf', 'PDF')
    ])