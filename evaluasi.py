import pickle
import pandas as pd
import matplotlib.pyplot as plt
from xgboost import plot_importance
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

# =====================================================================
# 1. MEMUAT DATASET KAGGLE & REKAYASA DATA 
# =====================================================================

try:
    df = pd.read_csv('phishing.csv') 
    
    # Menghapus kolom indeks dan memisahkan label kelas 
    X = df.drop(['Index', 'class'], axis=1) if 'Index' in df.columns else df.drop(['class'], axis=1)
    y = df['class']
    y = y.replace(-1, 0)
    
    # Membagi data uji 20% secara konsisten 
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
except Exception as e:
    print(f"Pengingat: Pastikan file dataset.csv ada di folder yang sama! Error: {e}")

# =====================================================================
# 2. MEMUAT MODEL BINARI XGBOOST (.PKL) KAMU
# =====================================================================

try:
    with open('model.pkl', 'rb') as file:
        model_xgb = pickle.load(file)
    
    # Melakukan prediksi terhadap 20% data uji
    y_pred = model_xgb.predict(X_test)
except Exception as e:
    print(f"Pengingat: Pastikan file model.pkl ada di folder yang sama! Error: {e}")

# =====================================================================
# 3. PRINT HASIL UNTUK BAB IV (ACCURACY, PRECISION, RECALL, F1-SCORE)
# =====================================================================
print("\n" + "="*50)
print("===      HASIL METRIK EVALUASI MODEL     ===")
print("="*50)
try:
    print(classification_report(y_test, y_pred))
except NameError:
    print("Gagal memproses metrik karena data atau model belum termuat sempurna.")

print("\n" + "="*50)
print("===            CONFUSION MATRIX           ===")
print("="*50)
try:
    print(confusion_matrix(y_test, y_pred))
    print("="*50 + "\n")
except NameError:
    print("Gagal memproses matriks karena data atau model belum termuat sempurna.")

# =====================================================================
# EXTRA: EVALUASI DATA TRAIN (80% / 0,8 DATA LATIH) - BEBAS OVERFITTING
# =====================================================================
print("\n" + "="*60)
print("===     HASIL METRIK EVALUASI DATA TRAIN (8.843 SAMPEL)    ===")
print("="*60)
try:
    # Memprediksi kembali 80% data latih
    y_pred_train = model_xgb.predict(X_train)
    
    print(classification_report(y_train, y_pred_train))
    print("\n" + "="*60)
    print("===            CONFUSION MATRIX DATA TRAIN                 ===")
    print("="*60)
    print(confusion_matrix(y_train, y_pred_train))
    print("="*60 + "\n")
except Exception as e:
    print(f"Gagal memproses evaluasi data train: {e}")


# =====================================================================
# 4. MEMUNCULKAN POP-UP GRAFIK FEATURE IMPORTANCE 
# =====================================================================
try:
    print("Menampilkan grafik Feature Importance... Silakan cek jendela pop-up baru.")
    plot_importance(model_xgb, max_num_features=10)
    plt.title("Tingkat Kepentingan Fitur - XGBoost Deteksi Phishing")
    plt.show()
except Exception as e:
    print(f"Gagal menampilkan grafik: {e}")
