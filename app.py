import datetime
import pygame
from cryptography import x509
from cryptography.hazmat._oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key, pkcs7
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from button import Button
from textbox import Textbox
from helpers import *


class App:
    def __init__(self):
        self.window = pygame.display.set_mode((900, 600))
        self.icon = pygame.image.load("konon.jpg")
        self.font = pygame.font.SysFont("Arial", 16)

        self.verify_file = None
        self.certificate = None
        self.signed_file = None
        self.sign_key = None
        self.text_content = None

        button1 = Button(self.window, 20, 160, 100, 30, "select file", self.chosen_verification_file)
        button2 = Button(self.window, 470, 160, 100, 30, "select file", self.chosen_signing_file)
        button3 = Button(self.window, 20, 280, 100, 30, "select key", self.chosen_certificate)
        button4 = Button(self.window, 470, 280, 100, 30, "select key", self.chosen_signing_key)
        button5 = Button(self.window, 580, 280, 120, 30, "generate key", self.generate_key)
        button6 = Button(self.window, 20, 430, 400, 30, "verify", self.verify)
        button7 = Button(self.window, 470, 430, 400, 30, "sign", self.sign)
        self.textbox = Textbox(self.window, 470, 330, 400, 30)
        self.buttons = [button1, button2, button3, button4, button5, button6, button7]

    def run(self):
        pygame.display.set_caption("File signature project")
        pygame.display.set_icon(self.icon)
        while True:
            self.window.fill((30, 30, 30))
            self.draw_buttons()
            self.textbox.draw()
            self.draw_verification()
            self.draw_signing()
            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    quit()
                if event.type == pygame.MOUSEBUTTONDOWN:
                    self.click()
                if event.type == pygame.KEYDOWN:
                    self.type(event)
            pygame.display.update()

    def draw_verification(self):
        title_box = pygame.Rect(20, 10, 400, 70)
        file_box = pygame.Rect(20, 80, 400, 70)
        key_box = pygame.Rect(20, 200, 400, 70)

        draw_text(self.window, title_box, "Verify a document", pygame.font.SysFont("Arial", 30))
        pygame.draw.rect(self.window, (70, 70, 70), file_box)
        pygame.draw.rect(self.window, (70, 70, 70), key_box)
        draw_text(self.window, file_box, self.verify_file if self.verify_file else "No file selected", self.font)
        draw_text(self.window, key_box, "Certificate selected" if self.certificate else "No certificate selected",
                  self.font)
        draw_text(self.window, pygame.Rect(20, 200, 100, 30), "Certificate:", self.font)

    def draw_signing(self):
        title_box = pygame.Rect(470, 10, 400, 70)
        file_box = pygame.Rect(470, 80, 400, 70)
        key_box = pygame.Rect(470, 200, 400, 70)

        draw_text(self.window, title_box, "Sign a document", pygame.font.SysFont("Arial", 30))
        pygame.draw.rect(self.window, (70, 70, 70), file_box)
        pygame.draw.rect(self.window, (70, 70, 70), key_box)
        draw_text(self.window, file_box, self.signed_file if self.signed_file else "No file selected", self.font)
        draw_text(self.window, key_box, "Private key selected" if self.sign_key else "No key selected", self.font)
        draw_text(self.window, pygame.Rect(470, 200, 100, 30), "Private key:", self.font)
        draw_text(self.window, pygame.Rect(470, 330, 70, 30), "Name:", self.font)

    def draw_buttons(self):
        for button in self.buttons:
            if button.mouse_over(pygame.mouse.get_pos()):
                button.hover = True
            else:
                button.hover = False
            button.draw()

    def click(self):
        for button in self.buttons:
            if button.mouse_over(pygame.mouse.get_pos()):
                button.func()
        if self.textbox.mouse_over(pygame.mouse.get_pos()):
            self.textbox.active = True
        else:
            self.textbox.active = False

    def type(self, event):
        if self.textbox.active:
            if event.key == pygame.K_BACKSPACE:
                self.textbox.text = self.textbox.text[:-1]
            elif (event.unicode.isalnum() or event.unicode == ' ' or event.unicode == '-') and len(self.textbox.text) <= 30:
                self.textbox.text += event.unicode
            self.text_content = self.textbox.text

    def create_certificate(self, key):
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, self.text_content)
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=10)
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        ).sign(key, hashes.SHA256())
        with open("certificate.pem", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    def sign(self):
        if self.sign_key and self.text_content:
            key = load_pem_private_key(self.sign_key, password=None)
            if isinstance(key, rsa.RSAPrivateKey):
                self.create_certificate(key)
                content = bytes(open(self.signed_file).read(), 'utf-8')
                signature = key.sign(
                    content,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                file = open("signed_file.sgn", "wb")
                #file.write(bytes("-----BEGIN SIGNATURE-----\n", 'utf-8'))
                file.write(signature)
                #file.write(bytes("\n-----END SIGNATURE-----\n", 'utf-8'))
                file.write(content)
                file.close()
                print("File signed.")
            else:
                print("Choose a valid private key.")

    def verify(self):
        if self.certificate:
            cert = x509.load_pem_x509_certificate(self.certificate)
            valid = True
            cert_usage = str(cert.extensions.get_extension_for_oid(oid=ExtensionOID.KEY_USAGE).value)
            if cert_usage != "<KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, " \
                            "data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False, " \
                            "encipher_only=False, decipher_only=False)>":
                valid = False  # We assume that key should only be used in digital signature
            key = cert.public_key()
            if isinstance(key, rsa.RSAPublicKey) and valid:
                message = open(self.verify_file, "rb").read()
                signature = open("signed_file.sgn", "rb").read()
                try:
                    key.verify(
                        signature,
                        message,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    name = cert.issuer.get_attributes_for_oid(oid=NameOID.COMMON_NAME).pop().value
                    print("Signature is valid. Signed by: " + str(name))
                except:
                    print("Signature is invalid.")
            else:
                print("Invalid certificate.")

    def chosen_verification_file(self):
        self.verify_file = chosen_file()

    def chosen_signing_file(self):
        self.signed_file = chosen_file()

    def chosen_certificate(self):
        result = chosen_file((("pem", "*.pem"),))
        if result:
            self.certificate = open(result, "rb").read()

    def chosen_signing_key(self):
        result = chosen_file((("pvk", "*.pvk"),))
        if result:
            self.sign_key = open(result, "rb").read()

    def generate_key(self):
        key = rsa.generate_private_key(
            backend=default_backend(),
            public_exponent=65537,
            key_size=2048
        )
        private_key = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
        file_out = open("generated_private_key.pvk", "wb")
        file_out.write(private_key)
        file_out.close()
        print("Key generated.")
        self.sign_key = private_key
