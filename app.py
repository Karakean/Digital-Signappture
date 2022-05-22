from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from button import Button
from helpers import *
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


class App:
    def __init__(self):
        self.window = pygame.display.set_mode((900, 600))
        self.icon = pygame.image.load("konon.jpg")
        self.font = pygame.font.SysFont("Arial", 16)

        self.verify_file = None
        self.verify_key = None
        self.sign_file = None
        self.sign_key = None

        button1 = Button(self.window, 20, 160, 100, 30, "select file", self.chose_verification_file)
        button2 = Button(self.window, 470, 160, 100, 30, "select file", self.chose_signing_file)
        button3 = Button(self.window, 20, 280, 100, 30, "select key", self.chose_verification_key)
        button4 = Button(self.window, 470, 280, 100, 30, "select key", self.chose_signing_key)
        button5 = Button(self.window, 580, 280, 120, 30, "generate keys", self.generate_key)
        button6 = Button(self.window, 20, 330, 400, 30, "verify", self.verify)
        button7 = Button(self.window, 470, 330, 400, 30, "sign", self.sign)
        self.buttons = [button1, button2, button3, button4, button5, button6, button7]

    def run(self):
        pygame.display.set_caption("File signature project")
        pygame.display.set_icon(self.icon)
        while True:
            self.window.fill((30, 30, 30))
            self.draw_verification()
            self.draw_signing()
            self.draw_buttons()
            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    quit()
                if event.type == pygame.MOUSEBUTTONDOWN:
                    self.click()
            pygame.display.update()

    def draw_verification(self):
        title_box = pygame.Rect(20, 10, 400, 70)
        file_box = pygame.Rect(20, 80, 400, 70)
        key_box = pygame.Rect(20, 200, 400, 70)

        draw_text(self.window, title_box, "Verify a document", pygame.font.SysFont("Arial", 30))
        pygame.draw.rect(self.window, (70, 70, 70), file_box)
        pygame.draw.rect(self.window, (70, 70, 70), key_box)
        draw_text(self.window, file_box, self.verify_file if self.verify_file else "No file selected", self.font)
        draw_text(self.window, key_box, "Public key selected" if self.verify_key else "No key selected", self.font)
        draw_text(self.window, pygame.Rect(20, 200, 100, 30), "Public key:", self.font)

    def draw_signing(self):
        title_box = pygame.Rect(470, 10, 400, 70)
        file_box = pygame.Rect(470, 80, 400, 70)
        key_box = pygame.Rect(470, 200, 400, 70)

        draw_text(self.window, title_box, "Sign a document", pygame.font.SysFont("Arial", 30))
        pygame.draw.rect(self.window, (70, 70, 70), file_box)
        pygame.draw.rect(self.window, (70, 70, 70), key_box)
        draw_text(self.window, file_box, self.sign_file if self.sign_file else "No file selected", self.font)
        draw_text(self.window, key_box, "Private key selected" if self.sign_key else "No key selected", self.font)
        draw_text(self.window, pygame.Rect(470, 200, 100, 30), "Private key:", self.font)

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

    def verify(self):
        if isinstance(self.verify_key, str):
            key = load_pem_public_key(bytes(self.verify_key, 'utf-8'))
            if isinstance(key, rsa.RSAPublicKey):
                message = open(self.verify_file, "rb").read()
                signature = open("signature.sgn", "rb").read()
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
                    print("git")
                except:
                    print("Oj kolezko cos tu sciemniasz scamerze hinduski")
            else:
                print("Choose a valid public key.")

    def sign(self):
        if isinstance(self.sign_key, str):
            key = load_pem_private_key(bytes(self.sign_key, 'utf-8'), password=None)
            if isinstance(key, rsa.RSAPrivateKey):
                signature = key.sign(
                    bytes(open(self.sign_file).read(), 'utf-8'),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                file = open("signature.sgn", "wb")
                file.write(signature)
                file.close()
                print("Podpisane legancko w pewien sposob de besta.")
            else:
                print("Choose a valid private key.")

    def chose_verification_file(self):
        self.verify_file = chosen_file()

    def chose_signing_file(self):
        self.sign_file = chosen_file()

    def chose_verification_key(self):
        self.verify_key = open(chosen_key()).read()

    def chose_signing_key(self):
        self.sign_key = open(chosen_key()).read()

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
        public_key = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        file_out = open("generated_public_key.plk", "wb")
        file_out.write(public_key)
        file_out.close()

        self.sign_key = private_key
