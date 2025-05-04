from flask import Flask, request, render_template
import tensorflow as tf
import numpy as np

app = Flask(__name__)

# Load trained model
model = tf.keras.models.load_model("models/phishing_detector.h5")

def extract_features(url):
    return np.array([[len(url), url.count("."), url.count("/")]])

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        url = request.form["url"]
        features = extract_features(url)
        prediction = model.predict(features)[0][0]
        result = "Phishing" if prediction > 0.5 else "Safe"
        return render_template("index.html", result=result, url=url)
    return render_template("index.html", result=None)

if __name__ == "__main__":
    app.run(debug=True)
