import sys

from flask import Flask, render_template, request, redirect, Response
import random, json


app = Flask(__name__)


@app.route("/well_plate96")
def well_plate96():
    return render_template('Selectable_plate.html')


if __name__ == "__main__":
    app.run()