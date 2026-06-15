# Tous les imports necessaires
import feedparser
import requests
import re
import time
import pandas as pd
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from jinja2 import Template

# CONFIGURATION
RSS_URL = "https://www.cert.ssi.gouv.fr/feed/"
OUTPUT_CSV = "anssi_cve_consolidated.csv"
SLEEP_BETWEEN_REQUESTS = 0.1

EMAIL_EXPEDITEUR = "votre_email@gmail.com"
EMAIL_PASSWORD = "mot_de_passe_application"
EMAIL_DESTINATAIRES = ["destinataire@gmail.com"]

SEUIL_CVSS_CRITIQUE = 9.0
SEUIL_CVSS_ELEVE = 7.0
SEUIL_EPSS = 0.60


def extraire_flux_rss(url):
    print("Extraction du flux RSS ANSSI...")
    rss_feed = feedparser.parse(url)
    print(f"  {len(rss_feed.entries)} bulletins trouves")
    return rss_feed


def extraire_cves(rss_feed):
    print("Extraction des CVE depuis les bulletins...")
    cve_pattern = r"CVE-\d{4}-\d{4,7}"
    res = []
    urls_json = []

    for entry in rss_feed.entries:
        urls_json.append(entry.link + "json/")

    for url in urls_json:
        response = requests.get(url, timeout=10)

        if response.status_code == 404:
            print(f"  Pas de JSON pour : {url}")
            res.append(set())
            continue

        if response.status_code != 200:
            print(f"  Erreur {response.status_code} pour : {url}")
            res.append(set())
            continue

        if not response.text.strip():
            print(f"  Reponse vide pour : {url}")
            res.append(set())
            continue

        try:
            data = response.json()
        except Exception as e:
            print(f"  JSON invalide pour {url} : {e}")
            res.append(set())
            continue

        cve_list = set(re.findall(cve_pattern, str(data)))
        res.append(cve_list)

    print("  Extraction terminee")
    return res


def get_cvss_cwe(cve_id):
    try:
        url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            return None, None, None
        data = response.json()
        cna = data["containers"]["cna"]

        try:
            description = cna["descriptions"][0]["value"]
        except:
            description = "Non disponible"

        cvss_score = None
        try:
            metrics = cna.get("metrics", [{}])[0]
            for key in ["cvssV3_1", "cvssV3_0", "cvssV2_0"]:
                if key in metrics:
                    cvss_score = metrics[key]["baseScore"]
                    break
        except:
            pass

        cwe = "Non disponible"
        try:
            problemtype = cna.get("problemTypes", [])
            if problemtype and "descriptions" in problemtype[0]:
                cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
        except:
            pass

        return description, cvss_score, cwe

    except Exception as e:
        print(f"  Erreur MITRE pour {cve_id} : {e}")
        return None, None, None


def get_epss(cve_id):
    try:
        url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        response = requests.get(url, timeout=10)
        data = response.json()
        epss_data = data.get("data", [])
        if epss_data:
            return float(epss_data[0]["epss"])
        return None
    except Exception as e:
        print(f"  Erreur EPSS pour {cve_id} : {e}")
        return None


def enrichir_cves(res):
    print("Enrichissement des CVE via API MITRE et FIRST...")
    all_cves = set()
    for cve_set in res:
        all_cves.update(cve_set)

    print(f"  {len(all_cves)} CVE uniques a enrichir")
    cve_enriched = {}

    for cve_id in all_cves:
        print(f"  Enrichissement de {cve_id}...")
        description, cvss_score, cwe = get_cvss_cwe(cve_id)
        epss_score = get_epss(cve_id)
        cve_enriched[cve_id] = {
            "description": description,
            "cvss_score": cvss_score,
            "cwe": cwe,
            "epss_score": epss_score
        }
        time.sleep(SLEEP_BETWEEN_REQUESTS)

    print("  Enrichissement termine")
    return cve_enriched


def consolider_donnees(rss_feed, cve_enriched):
    print("Consolidation des donnees dans un DataFrame...")
    cve_pattern = r"CVE-\d{4}-\d{4,7}"
    rows = []

    for entry in rss_feed.entries:
        url_json = entry.link + "json/"

        try:
            response = requests.get(url_json, timeout=10)
            if response.status_code != 200:
                continue
            data = response.json()
        except:
            continue

        bulletin_id = data.get("id", "Non disponible")
        titre = entry.title.replace("\n", " ").replace("\r", " ")
        date_pub = entry.published
        lien = entry.link
        type_bulletin = "Alerte" if "alerte" in lien.lower() or "ale" in bulletin_id.lower() else "Avis"

        cve_list = list(set(re.findall(cve_pattern, str(data))))

        if not cve_list:
            rows.append({
                "ID ANSSI": bulletin_id,
                "Titre": titre,
                "Type": type_bulletin,
                "Date": date_pub,
                "CVE": None,
                "CVSS Score": None,
                "CWE": None,
                "EPSS Score": None,
                "Description": None,
                "Lien": lien
            })
            continue

        for cve_id in cve_list:
            enriched = cve_enriched.get(cve_id, {})
            description = enriched.get("description")
            if description:
                description = description.replace("\n", " ").replace("\r", " ").replace(";", ",")
            rows.append({
                "ID ANSSI": bulletin_id,
                "Titre": titre,
                "Type": type_bulletin,
                "Date": date_pub,
                "CVE": cve_id,
                "CVSS Score": enriched.get("cvss_score"),
                "CWE": enriched.get("cwe"),
                "EPSS Score": enriched.get("epss_score"),
                "Description": description,
                "Lien": lien
            })

    df = pd.DataFrame(rows)
    df.to_csv(OUTPUT_CSV, index=False, sep=";")
    print(f"  DataFrame consolide : {df.shape[0]} lignes, {df.shape[1]} colonnes")
    print(f"  Fichier exporte : {OUTPUT_CSV}")
    return df


def classifier_priorite(cvss, epss, type_bulletin):
    cvss = cvss if pd.notna(cvss) else 0.0
    epss = epss if pd.notna(epss) else 0.0

    if type_bulletin == "Alerte" and cvss >= SEUIL_CVSS_CRITIQUE:
        return "CRITIQUE"
    if cvss >= SEUIL_CVSS_CRITIQUE or (cvss >= SEUIL_CVSS_ELEVE and epss >= SEUIL_EPSS):
        return "CRITIQUE"
    if cvss >= SEUIL_CVSS_ELEVE or epss >= SEUIL_EPSS or type_bulletin == "Alerte":
        return "ELEVEE"
    return "MODEREE"


def filtrer_alertes(df):
    df = df.copy()
    df["CVSS Score"] = pd.to_numeric(df["CVSS Score"], errors="coerce")
    df["EPSS Score"] = pd.to_numeric(df["EPSS Score"], errors="coerce")

    masque = (
            (df["CVSS Score"] >= SEUIL_CVSS_ELEVE) |
            (df["EPSS Score"] >= SEUIL_EPSS) |
            (df["Type"].str.strip() == "Alerte")
    )

    alertes = df[masque].copy()
    alertes["Priorite"] = alertes.apply(
        lambda r: classifier_priorite(r["CVSS Score"], r["EPSS Score"], r["Type"]),
        axis=1
    )

    ordre = {"CRITIQUE": 0, "ELEVEE": 1, "MODEREE": 2}
    alertes["_tri"] = alertes["Priorite"].map(ordre)
    alertes = alertes.sort_values(["_tri", "CVSS Score"], ascending=[True, False])
    alertes = alertes.drop(columns=["_tri"])

    print(f"  {len(alertes)} vulnerabilite(s) declenchent une alerte "
          f"({(alertes['Priorite'] == 'CRITIQUE').sum()} critiques, "
          f"{(alertes['Priorite'] == 'ELEVEE').sum()} elevees, "
          f"{(alertes['Priorite'] == 'MODEREE').sum()} moderees)")
    return alertes


TEMPLATE_HTML = """<!DOCTYPE html>
<html lang="fr">
<head><meta charset="UTF-8">
<style>
  body{font-family:Arial,sans-serif;background:#f4f4f4;margin:0;padding:0}
  .wrap{max-width:800px;margin:30px auto;background:#fff;border-radius:8px;
        box-shadow:0 2px 8px rgba(0,0,0,.15);overflow:hidden}
  .hdr{background:#c0392b;color:#fff;padding:22px 30px}
  .hdr h1{margin:0;font-size:20px}
  .hdr p{margin:4px 0 0;font-size:12px;opacity:.8}
  .stats{display:flex;border-bottom:1px solid #eee}
  .stat{flex:1;text-align:center;padding:14px 8px}
  .stat span{display:block;font-size:26px;font-weight:bold}
  .stat label{font-size:11px;color:#777;text-transform:uppercase}
  .c{color:#c0392b}.e{color:#e67e22}.m{color:#2980b9}.t{color:#555}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th{background:#2c3e50;color:#fff;padding:9px 12px;text-align:left}
  td{padding:8px 12px;border-bottom:1px solid #eee;vertical-align:top}
  tr:hover td{background:#fafafa}
  .b{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:bold;color:#fff}
  .bC{background:#c0392b}.bE{background:#e67e22}.bM{background:#2980b9}
  .bAl{background:#8e44ad}.bAv{background:#27ae60}
  .details{padding:20px 30px}
  .details h2{color:#c0392b;font-size:15px;margin-top:0}
  .card{border-left:4px solid #c0392b;padding:10px 14px;margin-bottom:12px;
        background:#fff5f5;border-radius:4px;font-size:13px}
  .ftr{padding:16px 30px;font-size:11px;color:#aaa;text-align:center;border-top:1px solid #eee}
  a{color:#2980b9}
  .na{color:#bbb;font-style:italic}
</style>
</head>
<body><div class="wrap">
  <div class="hdr">
    <h1>Rapport d'Alertes ANSSI - CVE Critiques</h1>
    <p>Genere le {{ date }} | {{ total }} vulnerabilite(s) a traiter</p>
  </div>
  <div class="stats">
    <div class="stat"><span class="c">{{ nb_c }}</span><label>Critique(s)</label></div>
    <div class="stat"><span class="e">{{ nb_e }}</span><label>Elevee(s)</label></div>
    <div class="stat"><span class="m">{{ nb_m }}</span><label>Moderee(s)</label></div>
    <div class="stat"><span class="t">{{ total }}</span><label>Total</label></div>
  </div>
  <table>
    <thead><tr>
      <th>Priorite</th><th>CVE</th><th>CVSS</th><th>EPSS</th>
      <th>Titre bulletin</th><th>Date</th><th>Lien ANSSI</th>
    </tr></thead>
    <tbody>
    {% for r in rows %}
    <tr>
      <td><span class="b b{{ r.priorite_code }}">{{ r.Priorite }}</span></td>
      <td>
        <strong>{{ r.CVE if r.CVE else '-' }}</strong><br>
        <span class="b b{{ 'Al' if r.Type=='Alerte' else 'Av' }}">{{ r.Type }}</span>
      </td>
      <td>{% if r.cvss_ok %}<strong>{{ r.CVSS }}</strong>{% else %}<span class="na">N/A</span>{% endif %}</td>
      <td>{% if r.epss_ok %}{{ r.EPSS }}{% else %}<span class="na">N/A</span>{% endif %}</td>
      <td><small>{{ r.Titre }}</small></td>
      <td><small>{{ r.Date }}</small></td>
      <td><a href="{{ r.Lien }}">{{ r['ID ANSSI'] }}</a></td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% if critiques %}
  <div class="details">
    <h2>Detail des vulnerabilites CRITIQUES</h2>
    {% for r in critiques %}
    <div class="card">
      <strong>{{ r.CVE }}</strong> - {{ r.Titre }}<br>
      {% if r.desc_ok %}<span style="color:#555">{{ r.Description }}</span><br>{% endif %}
      <small style="color:#888">
        CWE : {{ r.CWE if r.cwe_ok else 'N/A' }} |
        CVSS : {{ r.CVSS if r.cvss_ok else 'N/A' }} |
        EPSS : {{ r.EPSS if r.epss_ok else 'N/A' }}
      </small>
    </div>
    {% endfor %}
  </div>
  {% endif %}
  <div class="ftr">Message genere automatiquement par le systeme de veille ANSSI-CVE.</div>
</div></body></html>"""

TEMPLATE_TEXT = """=== RAPPORT ANSSI-CVE - {{ date }} ===
CRITIQUE: {{ nb_c }} | ELEVEE: {{ nb_e }} | MODEREE: {{ nb_m }} | TOTAL: {{ total }}

{% for r in rows %}[{{ r.Priorite }}] {{ r.CVE if r.CVE else 'CVE inconnue' }} - {{ r.Type }}
  Titre : {{ r.Titre }}
  CVSS  : {{ r.CVSS if r.cvss_ok else 'N/A' }} | EPSS : {{ r.EPSS if r.epss_ok else 'N/A' }}
  Lien  : {{ r.Lien }}
{% endfor %}
---
Message automatique."""


def _preparer_rows(alertes):
    rows = []
    for _, r in alertes.iterrows():
        cvss_ok = pd.notna(r["CVSS Score"])
        epss_ok = pd.notna(r["EPSS Score"])
        desc_ok = pd.notna(r.get("Description")) and str(r.get("Description", "")).strip() != ""
        cwe_ok = pd.notna(r.get("CWE")) and str(r.get("CWE", "")).strip() not in ("", "nan")
        p = r["Priorite"]
        rows.append({
            "ID ANSSI": r["ID ANSSI"],
            "Titre": r["Titre"],
            "Type": r["Type"],
            "Date": str(r["Date"])[:10],
            "CVE": r["CVE"] if pd.notna(r.get("CVE")) else None,
            "CVSS": f"{r['CVSS Score']:.1f}" if cvss_ok else None,
            "EPSS": f"{r['EPSS Score']:.2f}" if epss_ok else None,
            "CWE": r.get("CWE"),
            "Description": r.get("Description"),
            "Lien": r["Lien"],
            "Priorite": p,
            "priorite_code": p[0],
            "cvss_ok": cvss_ok,
            "epss_ok": epss_ok,
            "desc_ok": desc_ok,
            "cwe_ok": cwe_ok,
        })
    return rows


def generer_email(alertes):
    rows = _preparer_rows(alertes)
    critiques = [r for r in rows if r["Priorite"] == "CRITIQUE"]
    nb_c = sum(1 for r in rows if r["Priorite"] == "CRITIQUE")
    nb_e = sum(1 for r in rows if r["Priorite"] == "ELEVEE")
    nb_m = sum(1 for r in rows if r["Priorite"] == "MODEREE")

    ctx = dict(
        date=datetime.now().strftime("%d/%m/%Y a %H:%M"),
        rows=rows, critiques=critiques,
        nb_c=nb_c, nb_e=nb_e, nb_m=nb_m, total=len(rows)
    )

    subject = (
        f"[ANSSI-CVE] {nb_c} CRITIQUE(S) | {nb_e} ELEVEE(S) - "
        f"{datetime.now().strftime('%d/%m/%Y')}"
    )
    return {
        "subject": subject,
        "body_html": Template(TEMPLATE_HTML).render(**ctx),
        "body_text": Template(TEMPLATE_TEXT).render(**ctx),
    }


def envoyer_email(destinataires, subject, body_html, body_text):
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = EMAIL_EXPEDITEUR
        msg["To"] = ", ".join(destinataires)
        msg.attach(MIMEText(body_text, "plain", "utf-8"))
        msg.attach(MIMEText(body_html, "html", "utf-8"))
        with smtplib.SMTP("smtp.gmail.com", 587) as srv:
            srv.ehlo()
            srv.starttls()
            srv.login(EMAIL_EXPEDITEUR, EMAIL_PASSWORD)
            srv.sendmail(EMAIL_EXPEDITEUR, destinataires, msg.as_string())
        print(f"  Email envoye a : {', '.join(destinataires)}")
    except Exception as e:
        print(f"  Envoi impossible ({e}), affichage du mail :")
        print(f"\n  Destinataires : {', '.join(destinataires)}")
        print(f"  Sujet : {subject}")
        print(f"\n{body_text}")


def sauvegarder_alertes(alertes, email, output_dir="output_alertes"):
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_path = os.path.join(output_dir, f"alertes_{ts}.csv")
    html_path = os.path.join(output_dir, f"email_{ts}.html")
    alertes.to_csv(csv_path, index=False, encoding="utf-8-sig")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(email["body_html"])
    print(f"  CSV sauvegarde  : {csv_path}")
    print(f"  HTML sauvegarde : {html_path}")


def generer_alertes(df):
    print("Generation des alertes...")
    alertes = filtrer_alertes(df)

    if alertes.empty:
        print("  Aucune vulnerabilite ne declenche d'alerte")
        return

    email = generer_email(alertes)
    sauvegarder_alertes(alertes, email)
    envoyer_email(EMAIL_DESTINATAIRES, email["subject"], email["body_html"], email["body_text"])
    print("  Alertes terminees")


if __name__ == "__main__":
    rss_feed = extraire_flux_rss(RSS_URL)
    res = extraire_cves(rss_feed)
    cve_enriched = enrichir_cves(res)
    df = consolider_donnees(rss_feed, cve_enriched)
    generer_alertes(df)
    print("\nPipeline termine.")
