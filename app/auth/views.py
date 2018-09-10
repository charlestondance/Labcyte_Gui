from flask import render_template, redirect, request, url_for, flash
from .forms import LoginForm, RegistrationForm, DeleteUser, EditProfileAdminForm
from flask_login import login_user, logout_user, login_required
from . import auth
from .. import db
from ..models import User, Role
from ..decorators import admin_required, permission_required


@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('main.index'))
        flash('Invalid username or password.')
    return render_template('auth/login.html', form=form)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('main.index'))

@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data, username=form.username.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('You can now login')
        return redirect(url_for('auth.login'))
    return render_template('auth/register.html', form=form)

@auth.route('/testing', methods=['GET'])
@login_required
def testing():
    print('hi')
    return render_template('auth/testing.html')

@auth.route('/user_management', methods=['GET'])
@login_required
@admin_required
def user_management():
    user_list = User.query.all()

    return render_template('auth/user_management.html', user_list=user_list)

@auth.route('/delete_user', methods=['GET', 'POST'])
@login_required
@admin_required
def delete_user():
    form = DeleteUser()

    if form.validate_on_submit():
        flash('Delete User')
        user_del = User.query.filter_by(username=form.username.data).first()
        db.session.delete(user_del)
        db.session.commit()
        return redirect(url_for('main.index'))

    return render_template('auth/delete_user.html', form=form)

@auth.route('/user/<username>')
@login_required
def user(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        abort(404)
    return render_template('auth/user.html', user=user)

@auth.route('/edit-profile/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_profile_admin(id):
    user = User.query.get_or_404(id)
    form = EditProfileAdminForm(user=user)
    if form.validate_on_submit():
        user.email = form.email.data
        user.username = form.username.data
        user.role = Role.query.get(form.role.data)
        db.session.add(user)
        db.session.commit()
        flash('The profile has been updated.')
        return redirect(url_for('.user', username=user.username))
    form.email.data = user.email
    form.username.data = user.username
    form.role.data = user.role_id
    return render_template('auth/edit_profile.html', form=form, user=user)
