# Import des modules
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
from queue import Queue
from threading import Thread
from io import StringIO
from contextlib import redirect_stdout
from validate_certificate import valider_certificat, valider_chaine_certificats
from colorama import Fore, Back, Style

# Mapping des couleurs entre Colorama et Tkinter
COLOR_MAP = {
    Fore.BLUE: "blue",
    Fore.GREEN: "green",
    Fore.RED: "red",
    Fore.YELLOW: "orange",
    Fore.MAGENTA: "purple",
    Fore.CYAN: "cyan",
    Style.RESET_ALL: None
}

# Classe principale de l'application
class CertificateValidatorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Certificate Validator")

        self.files_to_validate = []
        self.format = tk.StringVar()
        self.format.set("PEM")

        self.create_widgets()

    def create_widgets(self):
        # Frame pour la sélection de fichier
        file_frame = tk.Frame(self.root)
        file_frame.pack(padx=10, pady=10)

        tk.Label(file_frame, text="Sélectionner le(s) fichier(s):").pack(side=tk.LEFT)

        tk.Button(file_frame, text="Ajouter un fichier", command=self.add_file).pack(side=tk.LEFT, padx=5)
        tk.Button(file_frame, text="Effacer les fichiers", command=self.clear_files).pack(side=tk.LEFT, padx=5)

        # Frame pour la sélection du format
        format_frame = tk.Frame(self.root)
        format_frame.pack(padx=10, pady=5)

        tk.Label(format_frame, text="Sélectionner le format:").pack(side=tk.LEFT)
        tk.Radiobutton(format_frame, text="PEM", variable=self.format, value="PEM").pack(side=tk.LEFT)
        tk.Radiobutton(format_frame, text="DER", variable=self.format, value="DER").pack(side=tk.LEFT)

        # Bouton pour valider
        tk.Button(self.root, text="Valider", command=self.validate_files).pack(pady=10)

        # Bouton pour effacer les logs
        tk.Button(self.root, text="Effacer les logs", command=self.clear_logs).pack(pady=5)

        # Zone de sortie
        output_frame = tk.Frame(self.root)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD)
        self.output_text.pack(fill=tk.BOTH, expand=True)

        # Frame pour afficher les fichiers sélectionnés
        self.selected_files_frame = tk.Frame(self.root)
        self.selected_files_frame.pack(padx=10, pady=5, fill=tk.X)

        # Étiquette pour afficher les fichiers sélectionnés
        self.selected_files_label = tk.Label(self.selected_files_frame, text="Fichiers sélectionnés:")
        self.selected_files_label.pack(side=tk.LEFT)

        # Étiquette pour afficher les chemins des fichiers sélectionnés
        self.selected_files_text = tk.Label(self.selected_files_frame, text="")
        self.selected_files_text.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

    def add_file(self):
        file_paths = filedialog.askopenfilenames()
        if file_paths:
            self.files_to_validate.extend(file_paths)
            self.update_output(f"Ajouté {len(file_paths)} fichier(s) à la liste.")

            # Afficher les chemins des fichiers sélectionnés
            selected_files_text = "\n".join(self.files_to_validate)
            self.selected_files_text.config(text=selected_files_text)

    def clear_files(self):
        self.files_to_validate.clear()
        self.update_output("Liste des fichiers effacée.")
        self.selected_files_text.config(text="")


    def validate_files(self):
        if not self.files_to_validate:
            messagebox.showwarning("Attention", "Aucun fichier sélectionné.")
            return

        format_chosen = self.format.get()
        output_queue = Queue()

        def worker():
            with StringIO() as buffer, redirect_stdout(buffer):
                if len(self.files_to_validate) == 1:
                    valider_certificat(self.files_to_validate[0], format_chosen)
                else:
                    valider_chaine_certificats(self.files_to_validate, format_chosen)
                output_queue.put(buffer.getvalue())

        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, "Validation en cours...\n")

        thread = Thread(target=worker)
        thread.start()

        def poll():
            try:
                result = output_queue.get(block=False)
                self.update_output(result)
            except:
                if thread.is_alive():
                    self.root.after(100, poll)
                else:
                    self.update_output("Validation terminée.")

        self.root.after(100, poll)

    def clear_logs(self):
        self.output_text.delete(1.0, tk.END)

    def update_output(self, message):
        colorized_message = self.colorize_message(message)
        self.output_text.insert(tk.END, colorized_message)
        self.output_text.see(tk.END)

    def colorize_message(self, message):
        colorized_message = message
        for color in COLOR_MAP:
            colorized_message = colorized_message.replace(color, "")
        for color in COLOR_MAP:
            colorized_message = colorized_message.replace(f'<{COLOR_MAP[color]}>', color)
        return colorized_message


# Fonction principale pour exécuter l'application
def main():
    root = tk.Tk()
    app = CertificateValidatorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
