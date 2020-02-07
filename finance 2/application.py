# This is a similated stock trading web app

import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Import of decimal module to limit roi to two decimal places
from decimal import *

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")

# This is the main index, which shows current stock holdings and cash.
@app.route("/")
@login_required
def index():

    print(session["user_id"])
    """Show portfolio of stocks"""

    # Gets the stocks that have positive quantity.
    result = db.execute("SELECT SUM(total), symbol, SUM(quantity) FROM hist WHERE quantity > 0 AND user_id =:user_id GROUP BY symbol", user_id=session["user_id"])

    print(result)

    # this goes through all of the returned stocks and gets their quantities

    # c_total is used to hold the total present value of ALL of the stocks
    c_total = 0

    # p_total is used to hold the total purchased value of ALL of the stocks
    ap_total = 0

    list_results = []
    for symbol in result:
        print(symbol["symbol"])
        print(symbol["SUM(quantity)"])
        q = symbol["SUM(quantity)"]
        print(f"q: {q}")
        ticker = (symbol["symbol"])
        print("new res above")
        p_total = float(symbol["SUM(total)"])
        p_ave = p_total/q
        print(p_total)

        # Get current price and full name of stock
        res = lookup(ticker)
        print(res)
        print("res above")
        price = res['price']
        total = price * q
        print(f"total: {total}")

        # returns = current price - purchase_p
        returns = total + p_total
        print(f"returns: {returns}")
        roi = Decimal((returns/total)*100).quantize(Decimal('.01'))
        print(f"roi: {roi}")

        print(price)
        new_results = {}

        print(type(c_total))
        print(type(total))
        c_total = float(c_total) + total
        ap_total = float(ap_total) + p_total


        # Appends the lookup call results to new_results dictionary
        new_results = res
        new_results['p_ave'] = usd(p_ave)
        new_results['p_total'] = usd(p_total)
        new_results['price'] = usd(price)
        new_results['q'] = q
        new_results['total'] = usd(total)
        new_results['roi'] = roi
        new_results['returns'] = usd(returns)

        # Made for conditional type-matching in flask
        new_results['f_returns'] = returns

        print(new_results)

        # Appends new_results dictionary to list of dicts in list_results
        list_results.append(new_results.copy())
        print(list_results)
        print(f"current total: {c_total}")
        print("end of one cycle of loop")

    print("end of entire loop")
    # When done with loop, add usd formatting to total owned assests.


    # Gets cash of current user
    currentCash = db.execute("SELECT cash FROM users WHERE id = :userId", userId= session["user_id"])

    py_cash = 0
    for rrow in currentCash:
        print(rrow["cash"])
        py_cash = rrow["cash"]

    acct_total = py_cash + c_total
    total_r = c_total + ap_total
    total_roi = Decimal((total_r/(-ap_total))*100).quantize(Decimal('.01'))

    py_cash = usd(py_cash)
    c_total = usd(c_total)
    ap_total = usd(ap_total)
    acct_total = usd(acct_total)
    total_r = usd(total_r)

    return render_template("index.html", result=list_results, py_cash=py_cash, ap_total=ap_total, c_total=c_total, acct_total=acct_total, total_r=total_r, total_roi=total_roi)



@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    # If form is submitted
    if request.method == "POST":

        if not request.form.get("symbol"):
            return apology("please input a stock ticker", 403)

        elif not lookup(request.form.get("symbol")):
            return apology("please input a proper stock ticker", 403)

        elif not request.form.get("shares"):
            return apology("please input a whole number from 1 on up", 403)

        shares = float(request.form.get("shares"))

        print(shares)

        if (shares).is_integer() != True:
            return apology("please input a whole number from 1 on up", 403)

        symbol = lookup(request.form.get("symbol"))
        print(symbol["price"])
        print(session["user_id"])
        print(symbol["symbol"])

        currentCash = db.execute("SELECT cash FROM users WHERE id = :userId", userId = session["user_id"])

        py_cash = 0

        for rrow in currentCash:
            print(rrow["cash"])
            py_cash = rrow["cash"]

        price = symbol["price"]

        cost = -(price) * shares
        print(cost)

        # cash of current user must be higher than cost of intended purchase
        if py_cash < cost:
            return apology("we're sorry you don't have enough money", 403)

        remaining = py_cash + cost

        result = db.execute("INSERT INTO hist (user_id, action, symbol, price, quantity, total) VALUES(:user_id, :action, :symbol, :price, :quantity, :total)", user_id=session["user_id"], action="buy", symbol=symbol["symbol"], price=price, quantity=shares, total=cost)

        db.execute("UPDATE users SET cash=:cash WHERE id=:id", cash=remaining, id=session["user_id"])

        flash('Purchased!')
        return redirect("/")

    else:
        return render_template("buyform.html")


@app.route("/history")
@login_required
def history():
    result = db.execute("SELECT action, symbol, price, quantity, total, time FROM hist WHERE user_id =:user_id", user_id=session["user_id"])

    return render_template("history.html", result=result)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():

    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("please input a stock ticker", 403)

        elif not lookup(request.form.get("symbol")):
            return apology("please input a proper stock ticker", 403)

        symbol = lookup(request.form.get("symbol"))
        print(symbol)
        return render_template("quoted.html", symbol=symbol)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # should reactivate once get program running
    # session.clear()

    if request.method == "POST":

        # Forget any user_id
        if not request.form.get("username"):
            return apology("must provide username", 403)

        elif not request.form.get("password"):
            return apology("must provide password", 403)

        elif not request.form.get("confirmation"):
            return apology("must confirm password", 403)

        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords don't match, 403")

        hash = generate_password_hash(request.form.get("password"))

        print(hash)

        result = db.execute("INSERT INTO users (username, hash) VALUES(:username, :hash)", username=request.form.get("username"), hash=hash)

        # apology isn't working properly
        print ({result})
        if not result:
            return apology("unable to add poss bc id not unique", 403)

      # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username doesn't already exist and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "POST":

        if not request.form.get("symbol"):
             return apology("please choose a stock to sell", 403)

        if not request.form.get("shares"):
            return apology("please input a whole number from 1 on up", 403)

        shares = float(request.form.get("shares"))

        if (shares).is_integer() != True:
            return apology("please input a whole number from 1 on up", 403)

        symbol = lookup(request.form.get("symbol"))
        print(symbol["price"])
        print(session["user_id"])
        print(symbol["symbol"])
        print(symbol)
        print(shares)

        total = symbol["price"] * shares

        db.execute("INSERT INTO hist (user_id, action, symbol, price, quantity, total) VALUES(:user_id, :action, :symbol, :price, :quantity, :total)", user_id=session["user_id"], action="sell", symbol=symbol["symbol"], price=symbol["price"], quantity = -(shares), total=total)
        flash("Sold!")
        return redirect("/")

    else:
        result = db.execute("SELECT symbol, SUM(quantity) FROM hist WHERE quantity > 0 AND user_id =:user_id GROUP BY symbol", user_id=session["user_id"])

        for symbol in result:
            print(symbol["symbol"])
            print(symbol["SUM(quantity)"])

        return render_template("sellform.html", result=result)



def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)




