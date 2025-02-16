import pandas as pd
import tensorflow as tf
from sklearn.model_selection import train_test_split
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense

# Load dataset
df = pd.read_csv("dataset/final_dataset.csv")

df = df.dropna(subset=["URL"])  # Remove rows with NaN in the URL column
df["length"] = df["URL"].apply(lambda x: len(x))

# Feature Engineering (Convert URLs into numbers)
df["length"] = df["URL"].apply(lambda x: len(str(x)))
df["dot_count"] = df["URL"].apply(lambda x: x.count("."))
df["slash_count"] = df["URL"].apply(lambda x: x.count("/"))

# Selecting features (X) and labels (y)
X = df[["length", "dot_count", "slash_count"]].values
y = df["Label"].values

# Split Data into Training & Testing Sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Build AI Model
model = Sequential([
    Dense(16, activation="relu", input_shape=(X_train.shape[1],)),
    Dense(8, activation="relu"),
    Dense(1, activation="sigmoid")
])

model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])

# Train Model
model.fit(X_train, y_train, epochs=10, batch_size=16, validation_data=(X_test, y_test))

# Save Trained Model
model.save("models/phishing_detector.h5")

print("✅ Model training completed and saved!")
