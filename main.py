import main  # Das kompilierte Modul importieren

if __name__ == "__main__":
    app = main.TechNovasafe()  # Erstelle eine Instanz der TechNovasafe-Klasse
    app.setup_ui()  # Richte die UI ein
    app.root.mainloop()  # Starte die Tkinter-Event-Schleife
