#Import
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import ExtensionOID
from ecdsa import VerifyingKey, curves, NIST256p, NIST384p, NIST521p, ellipticcurve, numbertheory
from ecdsa.util import sigdecode_der
from datetime import datetime, timezone
import hashlib
import argparse
import requests
from colorama import Fore, Back, Style


# Fonction pour charger un certificat depuis un fichier PEM ou DER
def charger_certificat(chemin_fichier, format_fichier):
    print(Fore.BLUE + "Chargement du certificat depuis le fichier :", chemin_fichier)
    try:
        with open(chemin_fichier, "rb") as fichier:
            contenu = fichier.read()
            if format_fichier == 'PEM':
                certificat = x509.load_pem_x509_certificate(contenu, default_backend())
            elif format_fichier == 'DER':
                certificat = x509.load_der_x509_certificate(contenu, default_backend())
            else:
                raise ValueError(Fore.RED + 'Erreur : format non pris en charge. Veuillez utiliser DER ou PEM.')
        print(Fore.GREEN + "Le certificat a bien été chargé")
        return certificat
    except Exception as e:
        print(Fore.RED + "Erreur lors du chargement du certificat :", e)

# Fonction pour obtenir des informations à partir d'un certificat
def obtenir_informations_certificat(certificat):
    print(Fore.BLUE + "Obtention des informations du certificat...")
    sujet = certificat.subject
    emetteur = certificat.issuer
    cle_publique = certificat.public_key()
    cle_publique_pem = cle_publique.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print(Fore.GREEN + "Les informations du certificat ont bien été obtenues")
    return sujet, emetteur, cle_publique_pem

# Fonction pour vérifier l'utilisation de la clé d'un certificat
def verifier_utilisation_cle(certificat):
    print(Fore.BLUE + "Vérification de l'utilisation de la clé...")
    try:
        utilisation_cle = certificat.extensions.get_extension_for_class(x509.KeyUsage)
        print(Fore.GREEN + "L'utilisation de la clé a bien été vérifié")
        return utilisation_cle
    except x509.ExtensionNotFound:
        print(Fore.RED + "Erreur : l'extension d'utilisation de la clé n'a pas été trouvée")
        return None

# Fonction pour vérifier la période de validité d'un certificat
def verifier_periode_validite(certificat):
    print(Fore.BLUE + "Vérification de la période de validité...")
    non_avant_utc = certificat.not_valid_before_utc
    non_apres_utc = certificat.not_valid_after_utc
    temps_actuel_utc = datetime.utcnow().replace(tzinfo=timezone.utc)  # Rendre l'objet conscient du fuseau horaire
    if temps_actuel_utc < non_avant_utc or temps_actuel_utc > non_apres_utc:
        print(Fore.RED + "Erreur : echec de la vérification de la période de validité. Le certificat n'est pas valide")
        return False
    print(Fore.GREEN + "Période de validité vérifiée. Le certificat est valide")
    return True


# Fonction pour valider un certificat
def valider_certificat(chemin_fichier, format_fichier):
    print(Fore.BLUE + "Validation du certificat en cours...")

    certificat = charger_certificat(chemin_fichier, format_fichier)

    # Vérifier si le certificat est un certificat racine
    if certificat.issuer == certificat.subject:
        print(Fore.GREEN + "Le certificat est un certificat racine")
    else:
        print(Fore.RED + "Le certificat n'est pas un certificat racine. La vérification est arrêtée.")
        return

    sujet, emetteur, cle_publique_pem = obtenir_informations_certificat(certificat)
    print(Fore.MAGENTA + f'Sujet : {sujet}')
    print( Fore.MAGENTA + f'Emetteur : {emetteur}')
    print(Fore.MAGENTA + f'Cle Publique : {cle_publique_pem}')

    utilisation_cle = verifier_utilisation_cle(certificat)
    if utilisation_cle is not None:
        print(Fore.MAGENTA + f'Utilisation de la clé : {utilisation_cle}')

    if verifier_periode_validite(certificat):
        print(Fore.GREEN + 'Le certificat est actuellement valide')
    else:
        print(Fore.RED + 'Le certificat n\'est pas valide')

    # Vérification du statut de révocation
    verifier_statut_revocation(certificat)

    extraire_et_verifier_signature(certificat, None)

    print(Fore.GREEN + "Validation du certificat terminée et réussie !")


# Fonction pour vérifier le statut de révocation
def verifier_statut_revocation(certificat):
    print(Fore.BLUE + "Vérification du statut de révocation...")

    # Récupérer l'URI de distribution de la CRL depuis le certificat
    try:
        uri_crl = \
        certificat.extensions.get_extension_for_oid(x509.ExtensionOID.CRL_DISTRIBUTION_POINTS).value[0].full_name[
            0].value
    except x509.ExtensionNotFound:
        print(Fore.YELLOW + "Warning : l'extension de distribution de CRL n'a pas été trouvée. La vérification du statut de révocation a été interrompue")
        return

    # Télécharger la CRL
    crl_response = requests.get(uri_crl)

    if crl_response.status_code != 200:
        print(Fore.RED + f"Erreur : echec du téléchargement de la CRL depuis l'URI : {uri_crl}. La vérification du statut de révocation a été interrompue")
        return

    crl_bytes = crl_response.content

    # Charger la CRL
    crl = x509.load_der_x509_crl(crl_bytes, default_backend())

    # Vérifier si le certificat est révoqué
    if crl.get_revoked_certificate_by_serial_number(certificat.serial_number) is not None:
        print(Fore.RED + "Erreur : Le certificat est révoqué")
    else:
        print(Fore.GREEN + "Le certificat n'est pas révoqué")

# Fonction pour vérifier l'extension BasicConstraints
def verifier_basic_constraints(certificat):
    print(Fore.BLUE + "Vérification de l'extension BasicConstraints...")
    try:
        basic_constraints = certificat.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        value = basic_constraints.value

        if value.ca:
            if value.path_length is None:
                print(Fore.CYAN + "Certificat Racine (Root CA)")
            else:
                print(Fore.CYAN + f'Certificat CA avec limite de chemin : {value.path_length}')
        else:
            print(Fore.CYAN + "Certificat Feuille")
    except x509.ExtensionNotFound:
        print(Fore.YELLOW + "Warning : extension BasicConstraints non trouvée.")


# Fonction pour valider une chaîne de certificats
def valider_chaine_certificats(chemins_fichiers, format_fichier):
    print(Fore.BLUE + "Validation de la chaîne de certificats en cours...")

    # Charger le premier certificat
    premier_certificat = charger_certificat(chemins_fichiers[0], format_fichier)

    # Vérifier si le premier certificat est un certificat racine
    if premier_certificat.issuer == premier_certificat.subject:
        print(Fore.CYAN + "Le premier certificat est un certificat racine")
    else:
        print(Fore.RED + "Erreur : le premier certificat n'est pas un certificat racine. La vérification est arrêtée")
        return

    certificat_precedent = None
    for chemin_fichier in chemins_fichiers:
        certificat = charger_certificat(chemin_fichier, format_fichier)
        sujet, emetteur, cle_publique_pem = obtenir_informations_certificat(certificat)
        print(Fore.MAGENTA + f'| Sujet : {sujet} |')
        print(Fore.MAGENTA + f'| Emetteur : {emetteur} |')
        print(Fore.MAGENTA + f'| Cle Publique : {cle_publique_pem} |')
        print(Fore.MAGENTA + f"| Format du fichier : {format_fichier} |")

        utilisation_cle = verifier_utilisation_cle(certificat)
        if utilisation_cle is not None:
            print(Fore.MAGENTA + f'Utilisation de la clé : {utilisation_cle}')

        if verifier_periode_validite(certificat):
            print(Fore.GREEN + 'Le certificat est valide.')
        else:
            print(Fore.RED + 'Le certificat n\'est pas  valide.')

        # Appeler la fonction verifier_basic_constraints et afficher le résultat
        verifier_basic_constraints(certificat)

        # Vérification du statut de révocation
        verifier_statut_revocation(certificat)


        if certificat_precedent is not None:
            extraire_et_verifier_signature2(certificat, certificat_precedent.public_key())
        else:
            extraire_et_verifier_signature(certificat, None)

        certificat_precedent = certificat

    print(Fore.GREEN + "Validation de la chaîne de certificats terminée et réussie !")


# Créer un analyseur d'arguments de ligne de commande

def extraire_et_verifier_signature(certificat, cle_publique_parente):
    print(Fore.BLUE + "Extraction de l'algorithme de signature...")
    algorithme_signature_oid = certificat.signature_algorithm_oid
    print(Fore.MAGENTA + f'Algorithme de signature : {algorithme_signature_oid}')

    print(Fore.BLUE + "Vérification de la signature...")
    if cle_publique_parente is None:
        # Si aucune clé publique parente n'est fournie, utilisez la clé publique du certificat lui-même
        cle_publique = certificat.public_key()
    else:
        cle_publique = cle_publique_parente

    try:
        if isinstance(cle_publique, rsa.RSAPublicKey):
            print(Fore.BLUE + "Vérification de la signature RSA...")
            cle_publique.verify(
                certificat.signature,
                certificat.tbs_certificate_bytes,
                padding.PKCS1v15(),
                certificat.signature_hash_algorithm
            )
            print(Fore.GREEN + "Signature RSA vérifiée.")
        elif isinstance(cle_publique, ec.EllipticCurvePublicKey):
            print(Fore.BLUE + "Vérification de la signature ECDSA...")
            cle_publique.verify(
                certificat.signature,
                certificat.tbs_certificate_bytes,
                ec.ECDSA(certificat.signature_hash_algorithm),
            )
            print(Fore.GREEN + "Signature ECDSA vérifiée.")
    except InvalidSignature:
        print(Fore.RED + "Erreur : echec de la vérification de la signature")


def extraire_et_verifier_signature2(certificat, cle_publique_parente):
    print(Fore.BLUE + "Extraction de l'algorithme de signature...")
    algorithme_signature_oid = certificat.signature_algorithm_oid
    print(Fore.MAGENTA + f'Algorithme de signature : {algorithme_signature_oid}')

    print(Fore.BLUE + "Vérification de la signature...")
    if cle_publique_parente is None:
        # Si aucune clé publique parente n'est fournie, utilisez la clé publique du certificat lui-même
        cle_publique = certificat.public_key()
    else:
        cle_publique = cle_publique_parente

    try:
        if isinstance(cle_publique, rsa.RSAPublicKey):
            print(Fore.BLUE + "Vérification mathématique de la signature RSA...")
            # Convertir la signature en entier
            signature_int = int.from_bytes(certificat.signature, byteorder='big')

            # Récupérer l'exposant public et le module depuis la clé publique
            public_numbers = cle_publique.public_numbers()
            e = public_numbers.e
            n = public_numbers.n

            # "Déchiffrer" la signature en utilisant l'exposant public et le module
            decrypted_signature_int = pow(signature_int, e, n)

            # Convertir le résultat en bytes
            decrypted_signature_bytes = decrypted_signature_int.to_bytes((n.bit_length() + 7) // 8, byteorder='big')

            # Calculer le hash attendu des données TBS
            algorithme_hachage = certificat.signature_hash_algorithm.name.upper()
            if algorithme_hachage == 'SHA256':
                expected_hash = hashlib.sha256(certificat.tbs_certificate_bytes).digest()
            elif algorithme_hachage == 'SHA1':
                expected_hash = hashlib.sha1(certificat.tbs_certificate_bytes).digest()
            # Ajouter d'autres algorithmes de hachage si nécessaire

            # Comparer le hash extrait avec le hash attendu
            if decrypted_signature_bytes.endswith(expected_hash):
                print(Fore.GREEN + "Signature RSA vérifiée mathématiquement")
            else:
                print(Fore.RED + "Échec de la vérification mathématique de la signature RSA")
        elif isinstance(cle_publique, ec.EllipticCurvePublicKey):
            cle_publique_parente = cle_publique
            public_numbers_parente = cle_publique.public_numbers()
            # Convertir la clé publique parente en format compatible ecdsa
            nom_courbe = cle_publique.curve.name

            # Faire la correspondance entre le nom de la courbe de 'cryptography' et les objets de courbe dans 'ecdsa'
            correspondance_courbe = {
                'secp256r1': curves.NIST256p,
                'secp384r1': curves.NIST384p,
                'secp521r1': curves.NIST521p,
                # Ajouter d'autres correspondances de courbes ici si nécessaire
            }

            # Trouver l'objet de courbe ECDSA correspondant
            courbe_ecdsa = correspondance_courbe.get(nom_courbe.lower())
            if courbe_ecdsa is None:
                raise ValueError(Fore.RED + f"Erreur : courbe non prise en charge : {nom_courbe}")

            generateur = courbe_ecdsa.generator

            cle_publique_parente_ecdsa = VerifyingKey.from_public_point(
                ellipticcurve.Point(courbe_ecdsa.curve, public_numbers_parente.x, public_numbers_parente.y),
                curve=courbe_ecdsa
            )

            # Extraire la signature du certificat enfant
            signature = certificat.signature

            # Décodage de la signature
            r, s = sigdecode_der(signature, courbe_ecdsa.order)

            # Calcul du hachage des données signées
            algorithme_hachage = certificat.signature_hash_algorithm.name
            fonction_hachage = getattr(hashlib, algorithme_hachage)
            tbs_hache = fonction_hachage(certificat.tbs_certificate_bytes).digest()

            # Effectuer la vérification mathématique de la signature
            ordre = courbe_ecdsa.order
            w = numbertheory.inverse_mod(s, ordre)
            u1 = (int.from_bytes(tbs_hache, 'big') * w) % ordre
            u2 = (r * w) % ordre
            point = u1 * generateur + u2 * cle_publique_parente_ecdsa.pubkey.point
            if point.x() % ordre == r:
                print(Fore.GREEN + "Signature valide, vérification par les courbes.")
            else:
                print(Fore.RED + "Erreur : signature invalide.")
    except Exception as e:
        print(Fore.RED + "Erreur : signature invalide :", e)

# Fonction principale
if __name__ == "__main__":
    analyseur = argparse.ArgumentParser(description='Valider un certificat ou une chaîne de certificats.')
    analyseur.add_argument('format_fichier', type=str, choices=['PEM', 'DER'], help='Le format des fichiers de certificat.')
    analyseur.add_argument('chemins_fichiers', type=str, nargs='+', help='Les chemins vers les fichiers de certificat, dans l\'ordre.')
    analyseur.add_argument('--chaine', action='store_true', help='Valider une chaîne de certificats au lieu d\'un seul certificat.')
    args = analyseur.parse_args()

    # Validation du certificat ou de la chaîne de certificats
    if args.chaine:
        valider_chaine_certificats(args.chemins_fichiers, args.format_fichier)
    else:
        if len(args.chemins_fichiers) != 1:
            print(Fore.YELLOW + "Warning : veuillez fournir exactement un chemin de fichier lors de la validation d'un seul certificat. Pour une chaîne, spécifiez --chain avant le format")
        else:
            valider_certificat(args.chemins_fichiers[0], args.format_fichier)


