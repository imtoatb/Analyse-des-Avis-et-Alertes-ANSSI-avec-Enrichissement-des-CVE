# Projet ANSSI - Analyse des Avis et Alertes

## Équipe
- Membre A - ananasdufutur : Extraction et enrichissement des données (Data scientist)
- Membre B - imtoatb : Analyse, visualisation et Machine Learning (ML engineer)
- Membre C - tarkhog25 : Alertes emails, coordination,  analyses & rapport + ppt (Data analyst + Automatisation)

## Planning 
J1 (jeudi) :
├── Tous : Constitution équipe + lecture complète sujet
├── A : Extraction RSS + JSON → liste brute CVE
├── B : Mise en place structure notebook + chargement données
└── C : Analyse des API externes + préparation templates

J2 (vendredi) :
├── A : API MITRE + EPSS (avec rate limiting 2s)
├── B : Exploration + premières visualisations simples
└── C : Développage du module d'alertes (structure)

J3 (samedi) :
├── A : Consolidation DataFrame final + export CSV
├── B : ML non supervisé (clustering)
└── C : Tests alertes + documentation début

J4 (dimanche) :
├── A : Corrections bugs + intégration fichiers locaux
├── B : ML supervisé + validation modèles
└── C : Emails finaux + README + début vidéo

J5 (lundi avant 23h) :
├── A : Finalisation backend + relecture
├── B : Visualisations finales + notebook propre
└── C : Vidéo 3 min + export HTML + dépôt final




## Prérequis pour la partie de imtoatb (VS Code avec un terminal PowerShell)

### 1. Installation de VS Code

Télécharger VS Code : https://code.visualstudio.com/

### 2. Extensions VS Code à installer

```powershell
# Ouvrir VS Code et installer les extensions
code --install-extension ms-python.python
code --install-extension ms-toolsai.jupyter
code --install-extension ms-python.vscode-pylance

python --version

# Si non installé, télécharger sur https://python.org
# OU via winget
winget install Python.Python.3.12

# Créer l'environnement virtuel
python -m venv venv

# Activer l'environnement
.\venv\Scripts\activate

# Vérifier l'activation (doit montrer (venv) dans le prompt)


# S'assurer que pip est à jour
python -m pip install --upgrade pip

# Installer les librairies nécessaires
pip install pandas numpy matplotlib seaborn plotly scikit-learn jupyter
```