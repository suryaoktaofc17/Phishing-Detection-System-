from flask import Flask, render_template, request, redirect
from integration import predict_url

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

# @app.route("/check", methods=["GET", "POST"])
# def check():
#     if request.method == "POST":
#         url = request.form.get("url")
#         result = predict_url(url)
#         return render_template("result.html", url=url, result=result)
#     else:
#         return redirect("/")
@app.route("/check", methods=["GET", "POST"])
def check():
    if request.method == "POST":
        url = request.form.get("url")
        
        # Tambahkan logika otomatis agar input 'google.com' menjadi 'https://google.com'
        if url and not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url
            
        result = predict_url(url)
        return render_template("result.html", url=url, result=result)
    else:
        return redirect("/")

if __name__ == '__main__':
    app.run(debug=True, port=2002)
