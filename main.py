

from flask import Flask, render_template, request, redirect, url_for, flash
from datetime import datetime, timedelta
from flask import session
from flask_mail import Mail, Message
from werkzeug.security import check_password_hash, generate_password_hash
import psycopg2
import os
import binascii
import re
import numpy as np
from urllib.parse import urlparse
from dotenv import load_dotenv

# Charger les variables d'environnement depuis le fichier .env
load_dotenv()

# Création de l'application Flask
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')

# Configuration de la session

print("SESSION_LIFETIME =", os.getenv('SESSION_LIFETIME'))
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=int(os.getenv('SESSION_LIFETIME')))
app.config['SESSION_PERMANENT'] = True

# Configuration de l'email
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS')
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL')
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
app.config['DATABASE_URL'] = os.getenv('DATABASE_URL')

mail = Mail(app)

# Connexion à la base de données PostgreSQL
def get_db_connection():
    database_url = os.getenv('DATABASE_URL')
    url = urlparse(database_url)
    conn = psycopg2.connect(
        database=url.path[1:],
        user=url.username,
        password=url.password,
        host=url.hostname,
        port=url.port
    )
    return conn

# Fonction pour récupérer un utilisateur par email
def get_user_by_email(email):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return user

# Fonction pour ajouter un utilisateur dans la base de données
def add_user_to_db(email, password_hash, date_naissance, genre, nom):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (email, password_hash, date_naissance, genre, nom) VALUES (%s, %s,%s,%s,%s)", (email, password_hash, date_naissance, genre, nom))
    conn.commit()
    cursor.close()
    conn.close()

# ... (le reste de ton code reste inchangé)


# Dictionnaire pour stocker les tentatives de connexion
login_attempts = {}

# Limite des tentatives et durée de verrouillage
MAX_ATTEMPTS = 3
LOCK_TIME = timedelta(minutes=10)  # 10 minutes de verrouillage

# Vérifie si l'utilisateur est verrouillé
def is_locked(email):
    """Vérifie si l'utilisateur est verrouillé"""
    if email in login_attempts:
        attempts = login_attempts[email]
        if attempts['locked_until'] > datetime.now():
            return True, attempts['locked_until']
    return False, None

# Met à jour les tentatives d'un utilisateur et le verrouille si nécessaire
def update_attempts(email):
    """Met à jour les tentatives d'un utilisateur et le verrouille si nécessaire"""
    if email not in login_attempts:
        login_attempts[email] = {'attempts': 0, 'locked_until': datetime.min}
    
    attempts = login_attempts[email]
    
    # Si l'utilisateur est verrouillé, on ne permet pas de nouvelles tentatives
    if attempts['locked_until'] > datetime.now():
        return "Votre session a expiré ! Veuillez reprendre dans 10min"

    # Si l'utilisateur n'est pas verrouillé, on incrémente les tentatives
    attempts['attempts'] += 1

    # Si les tentatives sont dépassées, on verrouille l'utilisateur
    if attempts['attempts'] >= MAX_ATTEMPTS:
        attempts['locked_until'] = datetime.now() + LOCK_TIME
        return "Votre session a expiré ! Veuillez reprendre dans 10min"

    # Si l'utilisateur a encore droit à des tentatives, on renvoie un message d'erreur
    return "Mot de passe ou email incorrect !"

# Réinitialise les tentatives après une connexion réussie
def reset_attempts(email):
    """Réinitialise les tentatives d'un utilisateur après une connexion réussie"""
    if email in login_attempts:
        login_attempts[email]['attempts'] = 0
        login_attempts[email]['locked_until'] = datetime.min

        # Fonction de calcul du coefficient de diffusion
def calculer_coefficient_diffusion(D_AB_initial, D_BA_initial, fraction_A, coef_lambda_A, coef_lambda_B, q_A, q_B, theta_A, theta_B, theta_BA, theta_AB, theta_AA, theta_BB, tau_AB, tau_BA, D_exp):
    fraction_B = 1 - fraction_A
    phi_A = fraction_A * coef_lambda_A / (fraction_A * coef_lambda_A + fraction_B * coef_lambda_B)
    phi_B = fraction_B * coef_lambda_B / (fraction_A * coef_lambda_A + fraction_B * coef_lambda_B)

    terme1 = fraction_B * np.log(D_AB_initial) + fraction_A * np.log(D_BA_initial) + 2 * (fraction_A * np.log(fraction_A / phi_A) + fraction_B * np.log(fraction_B / phi_B))
    terme2 = 2 * fraction_A * fraction_B * ((phi_A / fraction_A) * (1 - (coef_lambda_A / coef_lambda_B)) + (phi_B / fraction_B) * (1 - (coef_lambda_B / coef_lambda_A)))
    terme3 = (fraction_B * q_A) * ((1 - theta_BA ** 2) * np.log(tau_BA) + (1 - theta_BB ** 2) * tau_AB * np.log(tau_AB))
    terme4 = (fraction_A * q_B) * ((1 - theta_AB ** 2) * np.log(tau_AB) + (1 - theta_AA ** 2) * tau_BA * np.log(tau_BA))

    ln_D_AB = terme1 + terme2 + terme3 + terme4
    D_AB = np.exp(ln_D_AB)
    erreur_relative = abs((D_AB - D_exp)) / D_exp * 100

    return D_AB, erreur_relative


# Route pour la connexion
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        nom = request.form['name']
        email = request.form['email']
        mot_de_passe = request.form['password']
        

        # Vérifie si l'utilisateur est verrouillé
        locked, lock_time = is_locked(email)
        if locked:
            flash(f"Votre session a expiré ! Veuillez reprendre dans 10min", 'error')
            return redirect(url_for('login'))

        # Récupère l'utilisateur depuis la base de données
        user = get_user_by_email(email)
        if user and check_password_hash(user['password_hash'], mot_de_passe):
            # Réinitialiser les tentatives après une connexion réussie
            reset_attempts(email)
            # Après connexion réussie
            session['user_email'] = email  # Stocke l’email dans la session
            session.permanent = True   #Pour gérer les sessions
            return redirect(url_for('home'))  # Redirige l'utilisateur après la connexion

        # Si l'authentification échoue, met à jour les tentatives
        message = update_attempts(email)
        flash(message, 'error')
        return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/')
def index():
    return render_template('accueil.html')  # La page avec bouton "Se connecter"


# Route pour la page d'accueil (après connexion réussie)
@app.route('/home')
def home():
    if 'user_email' not in session:
        return redirect(url_for('login'))
    return render_template('home.html')  # Accueil après login

#Route pour se déconnecter
@app.route('/logout')
def logout():
    session.pop('user_email', None)
    flash("Vous avez été déconnecté avec succès.", "success")
    return redirect(url_for('login'))

def contient_caractere_special(mot_de_passe):
    return re.search(r"[!@#$%^&*(),.?\":{}|<>]", mot_de_passe) is not None

# Route pour l'inscription des utilisateurs
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        mot_de_passe = request.form['password']
        date_naissance = request.form['date_naissance']
        genre = request.form['genre']
        nom = request.form['nom']

       # Vérification du mot de passe
        if not contient_caractere_special(mot_de_passe):
            flash("Le mot de passe doit contenir au moins un caractère spécial !", "danger")
            return render_template("signup.html")

        # Vérifie si l'utilisateur existe déjà
        existing_user = get_user_by_email(email)
        if existing_user:
            flash("Cet email est déjà utilisé.", 'error')
            return redirect(url_for('signup'))

        # Crée un utilisateur avec un mot de passe hashé
        password_hash = generate_password_hash(mot_de_passe)
        add_user_to_db(email, password_hash, date_naissance, genre, nom)
        
        flash("Votre compte a été créé avec succès !", 'success')
        return redirect(url_for('login'))  # Redirige vers la page de connexion

    return render_template('signup.html')
#Route pour à propos
@app.route('/A_propos')
def A_propos():
    return render_template('A_propos.html')

def generate_reset_token():
    # Génère un token unique de 40 caractères en hexadécimal
    return binascii.hexlify(os.urandom(20)).decode()  # 20 octets => 40 caractères hexadécimaux

def store_reset_token(email):
    reset_token = generate_reset_token()  # Génère le token
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET reset_token = %s WHERE email = %s", (reset_token, email))
    conn.commit()
    cursor.close()
    conn.close()
    return reset_token


# réinitialisation du mot de passe
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']

        user = get_user_by_email(email)
        if user:
            reset_token = store_reset_token(email)  # <-- email bien défini ici
            reset_link = url_for('reset_password_token', token=reset_token, _external=True)

            msg = Message("Récupération de mot de passe", recipients=[email])
            msg.body = f"Bonjour,\n\nPour réinitialiser votre mot de passe, cliquez ici : {reset_link}"

            try:
                mail.send(msg)
                flash("Un email de récupération vous a été envoyé.", 'success')
                return redirect(url_for('login'))
            except Exception as e:
                flash("Erreur lors de l'envoi de l'email.", 'danger')
        else:
            flash("Aucun utilisateur trouvé avec cet email.", 'danger')

    return render_template('reset_password.html')


def get_user_by_reset_token(token):
    conn = get_db_connection()  # Connexion à la base de données
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE reset_token = %s", (token,))
    user = cursor.fetchone()  # Récupère le premier utilisateur correspondant
    cursor.close()
    conn.close()
    return user  # Retourne l'utilisateur s'il existe

   
   



@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    if request.method == 'POST':
        nouveau_mot_de_passe = request.form['password']
        confirmer_le_mot_de_passe = request.form['confirm_password']

        # Vérifie si les deux mots de passe sont identiques
        if nouveau_mot_de_passe != confirmer_le_mot_de_passe:
            flash("Les mots de passe ne correspondent pas.", 'danger')
            return render_template('reset_password_token.html', token=token)

        # Vérifie si le token est valide
        user = get_user_by_reset_token(token)
        if user:
            # Hache le nouveau mot de passe
            hashed_password = generate_password_hash(nouveau_mot_de_passe)

            # Met à jour le mot de passe dans la base de données
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET password_hash = %s WHERE email = %s", (hashed_password, user['email']))
            conn.commit()
            cursor.close()
            conn.close()

            # Invalide le token après utilisation
            invalidate_reset_token(user['email'])

            flash("Votre mot de passe a été réinitialisé avec succès.", 'success')
            return redirect(url_for('login'))
        else:
            flash("Token invalide ou expiré.", 'danger')
            return redirect(url_for('reset_password'))

    return render_template('reset_password_token.html', token=token)

def invalidate_reset_token(email):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET reset_token = NULL WHERE email = %s", (email,))
    conn.commit()
    cursor.close()
    conn.close()



    # Route pour le calcul du coefficient de diffusion
@app.route('/calcul', methods=['GET', 'POST'])
def calcul():
    if request.method == 'POST':
        # Récupère les données du formulaire
        D_AB_initial = float(request.form['D_AB_initial'])
        D_BA_initial = float(request.form['D_BA_initial'])
        fraction_A = float(request.form['fraction_A'])
        coef_lambda_A = float(request.form['coef_lambda_A'])
        coef_lambda_B = float(request.form['coef_lambda_B'])
        q_A = float(request.form['q_A'])
        q_B = float(request.form['q_B'])
        theta_A = float(request.form['theta_A'])
        theta_B = float(request.form['theta_B'])
        theta_BA = float(request.form['theta_BA'])
        theta_AB = float(request.form['theta_AB'])
        theta_AA = float(request.form['theta_AA'])
        theta_BB = float(request.form['theta_BB'])
        tau_AB = float(request.form['tau_AB'])
        tau_BA = float(request.form['tau_BA'])
        D_exp = float(request.form['D_exp'])

        # Effectue le calcul du coefficient de diffusion
        D_AB, erreur_relative = calculer_coefficient_diffusion(
            D_AB_initial, D_BA_initial, fraction_A, coef_lambda_A, coef_lambda_B,
            q_A, q_B, theta_A, theta_B, theta_BA, theta_AB, theta_AA, theta_BB,
            tau_AB, tau_BA, D_exp
        )

        # Récupère l'ID de l'utilisateur connecté
        user_id = 1  # Remplace par l'ID réel de l'utilisateur connecté, par exemple via 'session'
         # Enregistrer les résultats dans la base de données
        add_resultat_to_database_db(user_id, D_AB, erreur_relative)
        #On affiche les résultats dans resultats.html
        return render_template('resultats.html', D_AB=D_AB, erreur_relative=erreur_relative)

    return render_template('calcul.html')

        # Fonction pour enregistrer les résultats dans la base de données
def add_resultat_to_database_db(user_id, D_AB, erreur_relative):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO results (user_id, D_AB, erreur_relative) VALUES (%s, %s, %s)",
        (user_id, D_AB, erreur_relative)
    )
    conn.commit()
    cursor.close()
    conn.close()

    from flask import session, redirect, url_for, flash

# Renommée en logout_user pour éviter le conflit
@app.route('/logout')
def logout_user():
    # Supprimer l'email de la session
    session.pop('user_email', None)
    flash("Vous avez été déconnecté avec succès.", 'success')
    # Rediriger l'utilisateur vers la page de connexion
    return redirect(url_for('login'))




# Exécution de l'application Flask
if __name__ == '__main__':
    app.run(debug=True)