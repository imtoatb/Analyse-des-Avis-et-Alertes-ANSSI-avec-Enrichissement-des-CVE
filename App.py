# Tous les imports necessaires
import feedparser
import requests
import re
import time
import pandas as pd

# La configuration de base
RSS_URL = "https://www.cert.ssi.gouv.fr/feed/"
OUTPUT_CSV = "anssi_cve_consolidated.csv"
Rate_limit = 0.5

# Emails pour les alertes
EMAIL_EXPEDITEUR = "test@gmail.com"
EMAIL_DESTINATAIRE = "test@email.com"


def extraire_flux_rss(url):
    print("Extraction du flux RSS ANSSI...")
    rss_feed = feedparser.parse(url)
    print(f"  {len(rss_feed.entries)} bulletins trouvés")
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
            print(f"  Réponse vide pour : {url}")
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

    print(f"  Extraction terminée")
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

    print(f"  {len(all_cves)} CVE uniques à enrichir")
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
        time.sleep(Rate_limit)

    print("  Enrichissement terminé")
    return cve_enriched


def consolider_donnees(rss_feed, cve_enriched):
    print("Consolidation des données dans un DataFrame...")
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
    print(f"  DataFrame consolidé : {df.shape[0]} lignes, {df.shape[1]} colonnes")
    print(f"  Fichier exporté : {OUTPUT_CSV}")
    return df


if __name__ == "__main__":
    rss_feed = extraire_flux_rss(RSS_URL)
    res = extraire_cves(rss_feed)
    cve_enriched = enrichir_cves(res)
    df = consolider_donnees(rss_feed, cve_enriched)
    print("\nEnvoie Finis Terminé.")