# Analyse-des-Avis-et-Alertes-ANSSI-avec-Enrichissement-des-CVE

## Presentation du projet

### Contexte

En France, l'ANSSI (Agence Nationale de la Securite des Systemes d'Information) publie regulierement des avis et alertes de securite via son CERT-FR. Cependant, contrairement au NIST americain qui propose une API complete, l'ANSSI met seulement a disposition un flux RSS sommaire. Les informations detaillees necessitent de naviguer dans le DOM des pages web ou les fichiers JSON pour etre extraites.

### Objectifs du projet

Ce projet a pour objectif de:

- Extraireautomatiquement les donnees des flux RSS des avis et alertes ANSSI
- Identifierles CVE (Common Vulnerabilities and Exposures) mentionnees dans les bulletins
- Enrichir les CVE avec des informations complementaires via les API externes (MITRE pour CVSS/CWE, FIRST pour EPSS)
- Consoliderles donnees dans un DataFrame Pandas exploitable
- Analyser et visualiserles vulnerabilites pour en tirer des conclusions exploitables
- Predire la criticite des vulnerabilites via des modeles de Machine Learning
- Generer des alertes personnalisees pour les produits affectes

### Jeux de donnees utilises

| Source | Type | Contenu |
|--------|------|---------|
| ANSSI CERT-FR | Flux RSS | Avis et alertes de securite francais |
| MITRE CVE API | API REST | Scores CVSS et types CWE |
| FIRST EPSS API | API REST | Probabilite d'exploitation des vulnerabilites |

### Volume de donnees traite

| Indicateur | Valeur |
|------------|--------|
| Total bulletins analyses | 1282 |
| Total CVE uniques | 1237 |
| Period d'analyse | 15 mai - 12 juin 2026 |
| Taux de disponibilite CVSS | 41.3% |
| Taux de disponibilite EPSS | 99.1% |

---

## Version Python requise

Python 3.11.9


## Installation


### Etape 1: Installation

```bash
# Cloner le projet
git clone https://github.com/imtoatb/Analyse-des-Avis-et-Alertes-ANSSI-avec-Enrichissement-des-CVE.git
cd Analyse-des-Avis-et-Alertes-ANSSI-avec-Enrichissement-des-CVE

# Creer l'environnement virtuel
python -m venv venv

# Activer l'environnement (Windows)
venv\Scripts\activate

# Activer l'environnement (MacOS/Linux)
source venv/bin/activate

# Installer les dependances
pip install -r requirements.txt
```

### Etape 2: Lancer Jupyter Notebook
```bash

jupyter notebook
```

### Etape 3: Executer les notebooks dans l'ordre
|Ordre|	Notebook|	
|-----|---------|
|1 | analyse_anssi.ipynb|	
|2 | visualisation_anssi.ipynb|
|3 | ml_anssi.ipynb	Modeles de|



### Etape 4: Utilisation du cache local (optionnel mais recommande)

Pour eviter de surcharger les API, le projet peut utiliser des fichiers locaux:

```python

import json

# Charger depuis le cache
with open("cache/mitre/CVE-2026-42897.json", "r") as f:
    data = json.load(f)
```




