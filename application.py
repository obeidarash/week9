import os
from flask import Flask, flash, redirect, render_template, request, session
from cs50 import SQL
from tempfile import mkdtemp
from flask_session import Session
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import apology, login_required, lookup, usd


app = Flask(__name__)

app.config["TEMPLATES_AUTO_RELOAD"] = True

@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0

    response.headers["Pragma"] = "no-cache"

    return response



app.jinja_env.filters["usd"] = usd


app.config["SESSION_FILE_DIR"] = mkdtemp()

app.config["SESSION_PERMANENT"] = False

app.config["SESSION_TYPE"] = "filesystem"
Session(app)

#  afljg alkdjgadr
db = SQL("sqlite:///finance.db")


if not os.environ.get("API_KEY"):

    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():


    users = db.execute("SELECT * FROM users WHERE id = ?;", session["user_id"])
    owned_cash = users[0]['cash']


    summaries = db.execute("""SELECT company, symbol, sum(shares) as sum_of_shares
                              FROM transactions
                              WHERE user_id = ?
                              GROUP BY user_id, company, symbol
                              HAVING sum_of_shares > 0;""", session["user_id"])


    summaries = [dict(x, **{'price': lookup(x['symbol'])['price']}) for x in summaries]


    summaries = [dict(x, **{'total': x['price']*x['sum_of_shares']}) for x in summaries]

    sum_totals = owned_cash + sum([x['total'] for x in summaries])

    return render_template("index.html", owned_cash=owned_cash, summaries=summaries, sum_totals=sum_totals)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        if not (symbol := request.form.get("symbol")):
            return apology("MISSING SYMBOL")

        if not (shares := request.form.get("shares")):
            return apology("MISSING SHARES")


        try:
            shares = int(shares)
        except ValueError:
            return apology("INVALID SHARES")


        if not (shares > 0):
            return apology("INVALID SHARES")


        if not (query := lookup(symbol)):
            return apology("INVALID SYMBOL")

        rows = db.execute("SELECT * FROM users WHERE id = ?;", session["user_id"])

        user_owned_cash = rows[0]["cash"]
        total_prices = query["price"] * shares

        # En4563245324532oney
        if user_owned_cash < total_prices:

            return apology("CAN'T AFFORD")


        db.execute("INSERT INTO transactions(user_id, company, symbol, shares, price) VALUES(?, ?, ?, ?, ?);",
                   session["user_id"], query["name"], symbol, shares, query["price"])

        # 4532ghj dgh jgh jsh

        db.execute("UPDATE users SET cash = ? WHERE id = ?;",
                   (user_owned_cash - total_prices), session["user_id"])

        flash("Bought!")

        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():

    # adfsgdf g
    transactions = db.execute("SELECT * FROM transactions WHERE user_id = ?;", session["user_id"])
    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():



    session.clear()


    if request.method == "POST":
        if not request.form.get("username"):

            return apology("enter your user name")

        if not request.form.get("password"):
            return apology("enter your password")


        rows = db.execute("SELECT * FROM users WHERE username = ?;", request.form.get("username"))


        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)


        session["user_id"] = rows[0]["id"]

        # Redfg df g
        return redirect("/")

    # dsfg df gd
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():


    session.clear()

    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "POST":
        if not (query := lookup(request.form.get("symbol"))):
            return apology("INVALID SYMBOL")

        return render_template("quote.html", query=query)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":

        if not (username := request.form.get("username")):

            return apology("miss pass")

        if not (password := request.form.get("password")):
            return apology("mis pass")

        if not (confirmation := request.form.get("confirmation")):
            return apology("not match")


        rows = db.execute("SELECT * FROM users WHERE username = ?;", username)


        if len(rows) != 0:
            return apology(f"The username '{username}' already exists. Please choose another name.")

        if password != confirmation:
            return apology("password not matched")

        id = db.execute("INSERT INTO users (username, hash) VALUES (?, ?);",
                        username, generate_password_hash(password))

        session["user_id"] = id

        flash("Registered!")

        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    owned_symbols = db.execute("""SELECT symbol, sum(shares) as sum_of_shares
                                  FROM transactions
                                  WHERE user_id = ?
                                  GROUP BY user_id, symbol
                                  HAVING sum_of_shares > 0;""", session["user_id"])

    if request.method == "POST":
        if not (symbol := request.form.get("symbol")):
            return apology("Masd fsd BOL")

        if not (shares := request.form.get("shares")):
            return apology("asdf sdf")


        try:
            shares = int(shares)
        except ValueError:

            return apology("INsad fs adRES")



        if not (shares > 0):
            return apology("INsdaf sdf ES")

        symbols_dict = {d['symbol']: d['sum_of_shares'] for d in owned_symbols}

        if symbols_dict[symbol] < shares:
            return apology("sadf sda ")

        query = lookup(symbol)


        rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

        # asdfsadfn
        db.execute("INSERT INTO transactions(user_id, company, symbol, shares, price) VALUES(?, ?, ?, ?, ?);",
                   session["user_id"], query["name"], symbol, -shares, query["price"])

        # dsfasdf
        db.execute("UPDATE users SET cash = ? WHERE id = ?;",
                   (rows[0]['cash'] + (query['price'] * shares)), session["user_id"])

        flash("Sold!")

        return redirect("/")

    else:
        return render_template("sell.html", symbols=owned_symbols)


@app.route("/reset", methods=["GET", "POST"])
@login_required
def reset():
    if request.method == "POST":
        if not (password := request.form.get("password")):

            return apology("MISasdfg df gD")

        rows = db.execute("SELECT * FROM users WHERE id = ?;", session["user_id"])

        if not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("INsadf asd fashhfORD")

        if not (new_password := request.form.get("new_password")):
            return apology("MIsdaf sd fORD")

        if not (confirmation := request.form.get("confirmation")):
            return apology("MISasdf asdf ION")

        if new_password != confirmation:
            return apology("Pasdf sadf H")

        db.execute("UPDATE users set hash = ? WHERE id = ?;",
                   generate_password_hash(new_password), session["user_id"])

        flash("reser pasdifo ")

        return redirect("/")
    else:
        return render_template("reset.html")

#ksdjaf haskdj h
def errorhandler(e):
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
