from flask import redirect, request, url_for, flash, render_template, jsonify, Response
from flask_login import login_user, logout_user, login_required
from . import main
from ..models import User, Role, Permission
from ..decorators import admin_required, permission_required

@main.route('/')

def index():


    return render_template('index.html')

@main.route('/raisejob')
def raise_job():


    return render_template('index.html')

@main.route('.make_picklist')
def make_picklist():


    return render_template('index.html')