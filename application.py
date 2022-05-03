import os
import re

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

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


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Check if session["user_id"] is dictionary or list and turn it to dictionary
    if not isinstance(session["user_id"], int):
        session["user_id"] = session["user_id"][0]["id"]

    # Get users stock portfolio
    stocks = db.execute(
        "SELECT stocksymbol, stockname, shares FROM portfolio WHERE user_id = ? GROUP BY stocksymbol", session["user_id"])

    # Get users remaining cash
    value = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    value[0]["total"] = value[0]["cash"]

    # Sum shares' total price
    for i in range(0, len(stocks)):
        quotedStock = lookup(stocks[i]["stocksymbol"])
        stocks[i]["price"] = quotedStock["price"]
        stocks[i]["total"] = quotedStock["price"] * stocks[i]["shares"]
        value[0]["total"] += stocks[i]["total"]

    # Send user to index page
    return render_template("index.html", stocks=stocks, value=value[0])


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Get stock's symbol if it was submitted, else return apology
        stockSymbol = request.form.get("symbol")
        if not stockSymbol:
            return apology("must provide symbol", 400)

        else:
            # Get shares' number if it was submitted, else return apology
            try:
                sharesNumber = int(request.form.get("shares"))
            except:
                return apology("invalid number of shares", 400)

        # Check if shares' number is positive integer
        if sharesNumber < 1:
            return apology("invalid number of shares", 400)

        else:
            quotedStock = lookup(stockSymbol)

            # Check if stock symbol is valid
            if not quotedStock:
                return apology("incorrect stock symbol", 400)

            else:
                # Get current user cash
                cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
                balance = cash - quotedStock["price"] * sharesNumber

                # Check if user has enough cash
                if balance < 0:
                    return apology("your balance is insufficient", 400)

                # If user has enough cash complete the transaction
                else:
                    # Remove shares cost from his balance
                    db.execute("UPDATE users SET cash = ? WHERE id = ?", balance, session["user_id"])

                    # Add the transaction to history table
                    db.execute("INSERT INTO history (user_id, stocksymbol, stockname, shares, price, action) VALUES(?, ?, ?, ?, ?, ?)", int(
                        session["user_id"]), quotedStock["symbol"], quotedStock["name"], sharesNumber, quotedStock["price"], "BOUGHT")

                    # Get user's shares
                    sharesOwned = db.execute("SELECT shares FROM portfolio WHERE user_id = ? AND stocksymbol = ?",
                                             session["user_id"], stockSymbol.upper())

                    # Check if user owns any shares of that stock
                    if not sharesOwned:
                        # If user doesn't own any share of that stock, insert it in portfolio table
                        db.execute("INSERT INTO portfolio (user_id, stocksymbol, stockname, shares) VALUES(?, ?, ?, ?)",
                                   int(session["user_id"]), quotedStock["symbol"], quotedStock["name"], sharesNumber)

                        # Redirect user to home page
                        return redirect("/")

                    else:
                        sharesOwned = sharesOwned[0]["shares"]
                        sharesOwned += sharesNumber
                        # If user already owns shares of that stock, add increase the share's number in his portfolio
                        db.execute("UPDATE portfolio SET shares = ? WHERE user_id = ? AND stocksymbol = ?",
                                   sharesOwned, session["user_id"], stockSymbol.upper())

                        # Redirect user to home page
                        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Get users transactions history
    stocks = db.execute(
        "SELECT stocksymbol, stockname, shares, price, date, action FROM history WHERE user_id = ?", session["user_id"])

    # Send user to history page
    return render_template("history.html", stocks=stocks)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username").lower())

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 400)

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
    """Get stock quote."""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Get stock's symbol from quote.html form
        stockSymbol = request.form.get("symbol")

        # Check if stock symbol was submitted
        if not stockSymbol:
            return apology("must provide symbol", 400)
        else:
            quotedStock = lookup(stockSymbol)

        # Check if stock symbol is valid
        if not quotedStock:
            return apology("incorrect stock symbol", 400)
        else:
            # Send user to quoted page
            return render_template("quoted.html", quotedStock=quotedStock)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Query database for username
        try:
            usernameCheck = db.execute("SELECT username FROM users WHERE username = ?", request.form.get("username").lower())
        except:
            pass

        # Get username, password and confirmation password from register.html
        username = request.form.get("username").lower()
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure username was submitted
        if not username:
            return apology("must provide username", 400)

        # Ensure username has no spaces
        if " " in username:
            return apology("username can't have spaces", 400)

        # Ensure password was submitted
        elif not password:
            return apology("must provide password", 400)

        # Ensure password is at least 8 characters long
        elif not re.search(r".{8,}", password):
            return apology("password must be at least 8 characters long", 400)

        # Ensure password contains at least two letters
        elif not re.search(r"(?=.*?[a-zA-Z].*?[a-zA-Z])", password):
            return apology("password must contains at least two letters", 400)

        # Ensure password contains at least two digits
        elif not re.search(r"(?=.*?[0-9].*?[0-9])", password):
            return apology("password must contains at least two digits", 400)

        # Ensure password contains at least two of the following symbols: !@#$%^&*
        # elif not re.search(r"(?=.*?[!@#$%^&*].*?[!@#$%^&*])", password):
        #    return apology("password must contains at least two of the following symbols: !@#$%^&*", 400)

        # Ensure confirmation password matches password
        elif (not confirmation) or (password != confirmation):
            return apology("passwords do not match", 400)

        # Ensure username doesn't already exists
        elif len(usernameCheck) == 1:
            return apology("username already exists", 400)

        else:
            # Insert username and password hash in db
            db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username,
                       generate_password_hash(password, method='pbkdf2:sha256', salt_length=8))

            # Remember which user has logged in
            session["user_id"] = db.execute("SELECT id FROM users WHERE username = ?", username)

            # Redirect user to home page
            return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Get stock's symbol if it was submitted, else return apology
        stockSymbol = request.form.get("symbol")
        if not stockSymbol:
            return apology("must provide symbol", 400)

        else:
            # Get shares' number if it was submitted, else return apology
            try:
                sharesNumber = int(request.form.get("shares"))
            except:
                return apology("invalid number of shares", 400)

        # Check if shares' number is positive integer
        if sharesNumber < 1:
            return apology("invalid number of shares", 400)

        else:
            quotedStock = lookup(stockSymbol)

            # Check if stock symbol is valid
            if not quotedStock:
                return apology("incorrect stock symbol", 400)

            else:
                # Get user's shares
                sharesOwned = db.execute("SELECT shares FROM portfolio WHERE user_id = ? AND stocksymbol = ?",
                                         session["user_id"], stockSymbol.upper())

                # Get user's cash
                cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

                # Check if user owns any shares of that stock
                if not sharesOwned:
                    return apology("you don't have enough shares", 400)

                # If user has enough shares complete the transaction
                else:
                    sharesOwned = sharesOwned[0]["shares"]

                    # Check if user has enough shares
                    if sharesOwned < sharesNumber:
                        return apology("you don't have enough shares", 400)

                    else:
                        # Add shares cost in his balance
                        cash += sharesNumber * quotedStock["price"]
                        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash, session["user_id"])

                        # Remove shares from his portfolio
                        sharesOwned -= sharesNumber
                        db.execute("UPDATE portfolio SET shares = ? WHERE user_id = ? AND stocksymbol = ?",
                                   sharesOwned, session["user_id"], stockSymbol.upper())

                        # Add the transaction to history table
                        db.execute("INSERT INTO history (user_id, stocksymbol, stockname, shares, price, action) VALUES(?, ?, ?, ?, ?, ?)", int(
                            session["user_id"]), quotedStock["symbol"], quotedStock["name"], sharesNumber, quotedStock["price"], "SOLD")

                        # if shares owned by user is equal to 0, remove the row from the portfolio table
                        if sharesOwned == 0:
                            db.execute("DELETE FROM portfolio WHERE user_id = ? AND stocksymbol = ?",
                                       session["user_id"], stockSymbol.upper())

                        # Redirect user to home page
                        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        # Get the stock symbols from user's portfolio
        symbolsOwned = db.execute("SELECT stocksymbol FROM portfolio WHERE user_id = ?", session["user_id"])
        return render_template("sell.html", symbolsOwned=symbolsOwned)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
