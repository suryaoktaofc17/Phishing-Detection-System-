import pickle
from feature import extract_features


# Load model saat file diimpor
with open("model.pkl", "rb") as file:
    model = pickle.load(file)


def predict_url(url):
    features = extract_features(url)
    # TAMBAHKAN BARIS INI UNTUK DEBUGGING:
    print("DEBUG ARRAY FITUR:", features) 
    
    if len(features) != 30:
        return "⚠️ Jumlah fitur tidak sesuai. Harus 30."

    proba = model.predict_proba([features])[0][1]  # prob kelas 1
    percent = round(proba * 100, 2)

    if percent >= 90:
        return f"✅ Website ini {percent:.2f}% aman digunakan (Sangat Aman)."
    elif percent >= 80:
        return f"🟢 Website ini {percent:.2f}% aman digunakan (Cukup Aman)."
    elif percent >= 60:
        return f"🟡 Website ini {percent:.2f}% aman, tapi patut dicurigai (Meragukan)."
    else:
        return f"🔴 Website ini hanya {percent:.2f}% aman (Berisiko Tinggi / Phishing)."


    
    

# def check_url(url):
#     features = extract_features(url)
#     prediction = model.predict([features])[0]
#     return "Phishing!" if prediction == 1 else "Aman"
