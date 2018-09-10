from flask import redirect, request, url_for, flash, render_template, jsonify, Response
from . import main
from ..models import  User, Role, Permission

@main.route('/')
def index():


    return render_template('index.html')