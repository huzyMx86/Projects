import json
import re
from pathlib import Path
from datetime import datetime, timezone
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

# Import external libraries for NLP and threat intelligence processing
import spacy
import iocextract
import tldextract
from rapidfuzz import process, fuzz
from stix2 import (
    Bundle,
    Indicator,
    ThreatActor,
    Malware,
    AttackPattern,
    Campaign,
    Tool,
    Identity,
    Vulnerability,
    ObservedData,
    Relationship,
    File,
    Location,
)

# Load the spaCy English language model for entity recognition
try:
    nlp = spacy.load("en_core_web_sm")
    # Disable unnecessary pipeline components to improve performance
    for p in list(nlp.pipe_names):
        if p != "ner":
            nlp.disable_pipes(p)
except OSError:
    print("SpaCy model not found. Please run: python -m spacy download en_core_web_sm")
    raise

# Initialise Flask application with static and template folders
app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app)


# Helper function to safely load JSON files
def load_json_safe(filepath, default=None):
    """
    Loads a JSON file and returns its contents.
    Returns a default value if the file doesn't exist or has errors.
    """
    try:
        if Path(filepath).exists():
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        print("Warning loading", filepath, "->", str(e))
    if default is None:
        return {}
    return default


# Load threat intelligence data from cache files
TI_TERMS = load_json_safe("ti_terms_cache.json", {})
TI_CLASS = load_json_safe("ti_classifications.json", {})
THREAT_ACTORS = load_json_safe("threat_actors.json", [])
ORGS = load_json_safe("organizations.json", [])
TOOLS = load_json_safe("tools_software.json", [])
VICTIM_TERMS = load_json_safe("victim_classification.json", [])

# Create lookup dictionaries for faster searching
THREAT_ACTORS_MAP = {str(x).lower(): x for x in (THREAT_ACTORS or [])}
ORGS_MAP = {str(x).lower(): x for x in (ORGS or [])}
TOOLS_MAP = {str(x).lower(): x for x in (TOOLS or [])}
VICTIM_TERMS = [str(x).lower() for x in (VICTIM_TERMS or [])]

# Combine all terms for the suggestion feature
ALL_TERMS = list(TI_TERMS.values()) + THREAT_ACTORS + ORGS + TOOLS

# Define generic terms for fallback detection
GENERIC_TA_TERMS = {"adversary", "attacker", "attackers", "threat actor", "threat actors", "apt"}
GENERIC_TA_NAME = "Adversary"

GENERIC_MALWARE_TERMS = {"malware", "ransomware", "trojan", "backdoor", "wiper", "worm", "virus", "spyware"}
GENERIC_MALWARE_NAME = "Unknown Malware"


class SmartSTIXConverter:
    """Main class for converting text to STIX format"""
    
    def _clean_campaign_name(self, raw_name):
        """
        Cleans up campaign names by removing common prefixes and suffixes.
        Returns None if the name is too generic.
        """
        if not raw_name:
            return None
        name = str(raw_name).strip().lower()
        # Remove common leading words that don't add value
        leadins = r"(?:observed|coordinated|suspected|known|ongoing|the|a|an)\s+"
        changed = True
        while changed:
            new_name = re.sub(r"^" + leadins, "", name)
            changed = new_name != name
            name = new_name
        # Remove 'campaign' suffix if present
        name = re.sub(r"\s*campaign$", "", name).strip()
        if not name or name in {"the", "a", "an"}:
            return None
        return f"{name.title()} Campaign"

    def _infer_campaign_name(self, text):
        """
        Creates a campaign name based on the content if no specific name is found.
        Uses date information if available, otherwise uses current date.
        """
        tl = text.lower()
        # Determine campaign type based on keywords
        if "phish" in tl:
            base = "Phishing"
        elif "ransom" in tl:
            base = "Ransomware"
        elif "credential" in tl:
            base = "Credential Theft"
        elif "ddos" in tl or "denial of service" in tl:
            base = "DDoS"
        elif "espionage" in tl or "apt" in tl:
            base = "Espionage"
        elif any(k in tl for k in ["operation", "campaign", "attack", "intrusion"]):
            base = "Cyber"
        else:
            base = "Observed"
        # Try to find a date in the text
        m = re.search(r"((January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},\s+\d{4})", text)
        if not m:
            m = re.search(r"(\d{4}-\d{2}-\d{2})", text)
        suffix = m.group(1) if m else datetime.now(timezone.utc).date().isoformat()
        return f"{base} Campaign {suffix}"

    def _determine_hash_type(self, h):
        """
        Identifies the type of hash based on its length and format.
        Returns MD5, SHA1, SHA256, or None.
        """
        h = str(h).lower()
        if re.fullmatch(r"[a-f0-9]{32}", h):
            return "MD5"
        if re.fullmatch(r"[a-f0-9]{40}", h):
            return "SHA1"
        if re.fullmatch(r"[a-f0-9]{64}", h):
            return "SHA256"
        return None

    def _extract_coded_actors(self, tl):
        """
        Extracts threat actor codes like APT28, TA505, FIN7 from text.
        Returns a set of formatted actor names.
        """
        hits = set()
        # Look for different threat actor naming patterns
        for m in re.finditer(r"\bapt[\s\-]?(\d{1,3})\b", tl):
            hits.add(f"APT{m.group(1)}")
        for m in re.finditer(r"\bta[\s\-]?(\d{1,4})\b", tl):
            hits.add(f"TA{m.group(1)}")
        for m in re.finditer(r"\bfin[\s\-]?(\d{1,4})\b", tl):
            hits.add(f"FIN{m.group(1)}")
        for m in re.finditer(r"\bunc[\s\-]?(\d{2,5})\b", tl):
            hits.add(f"UNC{m.group(1)}")
        for m in re.finditer(r"\bstorm[\s\-]?(\d{2,5})\b", tl):
            hits.add(f"STORM{m.group(1)}")
        return hits

    def extract_all_entities(self, text):
        """
        Main extraction method that finds all threat intelligence entities in text.
        Returns a dictionary containing all found entities organized by type.
        """
        # Initialise entity storage
        entities = {
            "ips": [],
            "domains": [],
            "urls": [],
            "emails": [],
            "hashes": [],
            "cves": [],
            "threat_actors": set(),
            "tools": set(),
            "identities": set(),
            "attack_patterns": set(),
            "campaigns": set(),
            "malware": set(),
            "vulnerabilities": set(),
            "locations": set(),
            "victim_identities": set(),
        }
        text_lower = text.lower()

        # Extract IOCs using iocextract library
        entities["ips"] = list(iocextract.extract_ipv4s(text, refang=True))
        entities["urls"] = list(iocextract.extract_urls(text, refang=True))
        entities["emails"] = list(iocextract.extract_emails(text, refang=True))

        # Clean up email addresses that look like user@IP
        clean_emails = []
        for em in entities["emails"]:
            dom = em.split("@")[-1]
            # Skip emails with IP addresses as domains
            if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", dom):
                continue
            clean_emails.append(em)
        entities["emails"] = clean_emails

        entities["hashes"] = list(iocextract.extract_hashes(text))

        # Extract CVE identifiers
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        cves_found = re.findall(cve_pattern, text, re.IGNORECASE)
        entities["cves"] = [cve.upper() for cve in cves_found]

        # Extract domain names from URLs
        for url in entities["urls"]:
            extracted = tldextract.extract(url)
            if extracted.domain and extracted.suffix:
                domain = f"{extracted.domain}.{extracted.suffix}"
                if extracted.subdomain:
                    domain = f"{extracted.subdomain}.{domain}"
                if domain not in entities["domains"]:
                    entities["domains"].append(domain)

        # Additional domain extraction using regex
        domain_pattern = r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|gov|edu|co\.uk|io|info|biz)\b"
        for d in re.findall(domain_pattern, text):
            # Avoid false positives from IP addresses
            ok = True
            for ip in entities["ips"]:
                if d.startswith(ip.split(".")[0]):
                    ok = False
                    break
            if ok and d not in entities["domains"]:
                entities["domains"].append(d)

        # Search for known threat intelligence terms
        for term_key, term_name in TI_TERMS.items():
            k = str(term_key).lower()
            # Skip very short or generic terms
            if len(k) <= 3 or k in ["malware", "tool", "software", "attack", "threat"]:
                continue
            if re.search(r"\b" + re.escape(k) + r"\b", text_lower):
                term_class = TI_CLASS.get(term_key, "")
                # Categorize based on classification
                if term_class == "attack-pattern":
                    if len(str(term_name)) > 3 and str(term_name).lower() not in ["attack", "threat", "malware"]:
                        entities["attack_patterns"].add(term_name)
                elif term_class == "malware":
                    entities["malware"].add(term_name)
                elif term_class in ["threat-actor", "intrusion-set"]:
                    entities["threat_actors"].add(term_name)
                elif term_class == "tool":
                    entities["tools"].add(term_name)
                elif term_class == "campaign":
                    cleaned = self._clean_campaign_name(term_name)
                    if cleaned:
                        entities["campaigns"].add(cleaned)

        # Search for known threat actors with flexible matching
        for actor in THREAT_ACTORS:
            a = str(actor).lower()
            # Allow for spaces or hyphens in actor names
            body = re.sub(r"[\s\-]+", r"[-\\s]?", re.escape(a))
            pattern = r"\b" + body + r"\b"
            if re.search(pattern, text_lower):
                entities["threat_actors"].add(actor)

        # Search for known tools
        for tool in TOOLS:
            tl = str(tool).lower()
            if len(tl) > 2 and re.search(r"\b" + re.escape(tl) + r"\b", text_lower):
                entities["tools"].add(tool)

        # Search for organisations
        for org in ORGS:
            ol = str(org).lower()
            if re.search(r"\b" + re.escape(ol) + r"\b", text_lower):
                entities["identities"].add(org)

        # Look for patterns that indicate named entities
        rules = [
            (r"(?:group|actor|team|apt|intrusion set)\s+(?:called|named|dubbed|known as)\s+([A-Za-z0-9][A-Za-z0-9\-\s]{1,50})", "threat-actor"),
            (r"(?:malware|ransomware|trojan|backdoor|wiper|worm)\s+(?:called|named|dubbed|known as)\s+([A-Za-z0-9][A-Za-z0-9\-\._\s]{1,50})", "malware"),
            (r"(?:operation|campaign)\s+(?:called|named|dubbed|known as)\s+([A-Za-z0-9][A-Za-z0-9\-\s]{1,50})", "campaign"),
        ]
        for pat, kind in rules:
            for m in re.finditer(pat, text_lower):
                name = m.group(1).strip(" .,:;\"'()[]{}").strip()
                if not name:
                    continue
                # Don't classify organisations as threat actors
                if kind == "threat-actor" and name.lower() in ORGS_MAP:
                    continue
                if kind == "threat-actor":
                    entities["threat_actors"].add(name)
                elif kind == "malware":
                    entities["malware"].add(name)
                elif kind == "campaign":
                    cleaned = self._clean_campaign_name(name)
                    if cleaned:
                        entities["campaigns"].add(cleaned)

        # Use spaCy NER for organisation and location detection
        doc = nlp(text)
        for ent in doc.ents:
            if ent.label_ == "ORG":
                ent_text = ent.text.strip()
                ent_lower = ent_text.lower()
                # Filter out generic organisational terms
                skip = ["hr", "it", "department", "team", "group", "security", "admin", "support"]
                if any(s in ent_lower for s in skip) or len(ent_text.split()) < 2:
                    pass
                else:
                    # Only add if not already classified
                    if ent_lower not in THREAT_ACTORS_MAP and ent_lower not in TOOLS_MAP and ent_lower not in ORGS_MAP:
                        if 3 < len(ent_text) < 50:
                            entities["identities"].add(ent_text)
            elif ent.label_ in ("GPE", "LOC"):
                loc = ent.text.strip()
                if 2 <= len(loc) <= 80:
                    entities["locations"].add(loc)

        # Extract coded threat actor names
        entities["threat_actors"].update(self._extract_coded_actors(text_lower))

        # Identify victim organisations based on context
        for org in list(entities["identities"]):
            for m in re.finditer(re.escape(org), text, flags=re.IGNORECASE):
                # Look at surrounding text for victim indicators
                start = max(0, m.start() - 60)
                end = min(len(text_lower), m.end() + 60)
                window = text_lower[start:end]
                got = False
                for vt in VICTIM_TERMS:
                    if vt and vt in window:
                        got = True
                        break
                if got:
                    entities["victim_identities"].add(org)
                    break

        # Convert CVEs to vulnerabilities
        for cve in entities["cves"]:
            entities["vulnerabilities"].add(cve)

        # Generate a campaign if context suggests one exists
        if not entities["campaigns"]:
            if any(k in text_lower for k in ["campaign", "phish", "operation", "attack", "intrusion", "compromise"]):
                inferred = self._infer_campaign_name(text)
                if inferred:
                    entities["campaigns"].add(inferred)

        # Add generic entities if nothing specific was found
        if not entities["threat_actors"]:
            # Check if there are coded actors that weren't caught
            has_code = re.search(r"\b(apt|ta|fin|unc|storm)[\s\-]?\d{1,5}\b", text_lower)
            if any(t in text_lower for t in GENERIC_TA_TERMS) and not has_code:
                entities["threat_actors"].add(GENERIC_TA_NAME)

        if not entities["malware"]:
            for t in GENERIC_MALWARE_TERMS:
                if t in text_lower:
                    entities["malware"].add(GENERIC_MALWARE_NAME)
                    break

        return entities

    def create_stix_bundle(self, entities, relationships):
        """
        Creates a STIX bundle from extracted entities and user-defined relationships.
        Returns a JSON-serialisable dictionary containing all STIX objects.
        """
        stix_objects = []
        id_map = {}
        now = datetime.now(timezone.utc)

        # Create indicators for network observables
        for ip in entities["ips"]:
            indicator = Indicator(
                pattern=f"[ipv4-addr:value = '{ip}']",
                pattern_type="stix",
                name=f"IP: {ip}",
                labels=["malicious-activity"],
                valid_from=now,
            )
            stix_objects.append(indicator)
            id_map[f"IP: {ip}"] = indicator.id

        for domain in entities["domains"]:
            indicator = Indicator(
                pattern=f"[domain-name:value = '{domain}']",
                pattern_type="stix",
                name=f"Domain: {domain}",
                labels=["malicious-activity"],
                valid_from=now,
            )
            stix_objects.append(indicator)
            id_map[f"Domain: {domain}"] = indicator.id

        for url in entities["urls"]:
            indicator = Indicator(
                pattern=f"[url:value = '{url}']",
                pattern_type="stix",
                name=f"URL: {url}",
                labels=["malicious-activity"],
                valid_from=now,
            )
            stix_objects.append(indicator)
            id_map[f"URL: {url}"] = indicator.id

        for email in entities["emails"]:
            indicator = Indicator(
                pattern=f"[email-addr:value = '{email}']",
                pattern_type="stix",
                name=f"Email: {email}",
                labels=["malicious-activity"],
                valid_from=now,
            )
            stix_objects.append(indicator)
            id_map[f"Email: {email}"] = indicator.id

        # Create observed data for file hashes
        for h in entities["hashes"]:
            htype = self._determine_hash_type(h)
            if not htype:
                continue
            file_sco = File(hashes={htype: h})
            stix_objects.append(file_sco)
            # Create observed data object referencing the file
            obs = ObservedData(
                first_observed=now,
                last_observed=now,
                number_observed=1,
                object_refs=[file_sco.id],
                created=now,
                modified=now,
            )
            stix_objects.append(obs)

        # Create threat actor objects
        for actor in entities["threat_actors"]:
            ta = ThreatActor(name=actor)
            stix_objects.append(ta)
            id_map[actor] = ta.id

        # Create tool objects
        for tool in entities["tools"]:
            t = Tool(name=tool)
            stix_objects.append(t)
            id_map[tool] = t.id

        # Create identity objects for organisations
        for ident in entities["identities"]:
            i = Identity(name=ident, identity_class="organization")
            stix_objects.append(i)
            id_map[ident] = i.id

        # Create attack pattern objects
        for ap in entities["attack_patterns"]:
            a = AttackPattern(name=ap)
            stix_objects.append(a)
            id_map[ap] = a.id

        # Create campaign objects
        for camp in entities["campaigns"]:
            c = Campaign(name=camp)
            stix_objects.append(c)
            id_map[camp] = c.id

        # Create malware objects
        for mw in entities["malware"]:
            m = Malware(name=mw, is_family=True)
            stix_objects.append(m)
            id_map[mw] = m.id

        # Create vulnerability objects
        for cve in entities["vulnerabilities"]:
            v = Vulnerability(name=cve)
            stix_objects.append(v)
            id_map[cve] = v.id

        # Create location objects
        for loc in entities.get("locations", []):
            try:
                l = Location(name=loc)
                stix_objects.append(l)
                id_map[loc] = l.id
            except Exception as e:
                print("Location error:", str(e))

        # Automatically create "targets" relationships for identified victims
        victims = entities.get("victim_identities") or set()
        if victims:
            for actor in entities["threat_actors"]:
                for vic in victims:
                    if actor in id_map and vic in id_map:
                        rel = Relationship(
                            relationship_type="targets",
                            source_ref=id_map[actor],
                            target_ref=id_map[vic],
                        )
                        stix_objects.append(rel)

        # Add user-defined relationships from the UI
        for rel in (relationships or []):
            source_name = rel.get("source_name")
            target_name = rel.get("target_name")
            rel_type = rel.get("relationship_type")
            if not (source_name and target_name and rel_type):
                continue
            # Only create relationship if both objects exist
            if source_name in id_map and target_name in id_map:
                relationship = Relationship(
                    relationship_type=rel_type,
                    source_ref=id_map[source_name],
                    target_ref=id_map[target_name],
                )
                stix_objects.append(relationship)

        # Create the final STIX bundle
        bundle = Bundle(objects=stix_objects)
        return json.loads(bundle.serialize())


# Create converter instance
converter = SmartSTIXConverter()


# Route for the landing page
@app.route("/")
def landing_page():
    """Renders the landing page with project information"""
    return render_template("landing.html")


# Route for the main converter page
@app.route("/main")
def main_page():
    """Renders the main converter interface"""
    return render_template("main.html")


# Route for the results page
@app.route("/results")
def results_page():
    """Renders the results page showing generated STIX"""
    return render_template("results.html")


# API endpoint for live word suggestions
@app.route("/api/live-suggestions", methods=["POST"])
def live_suggestions():
    """
    Provides real-time suggestions for threat intelligence terms.
    Uses fuzzy matching to find similar terms from the database.
    """
    try:
        data = request.get_json(silent=True) or {}
        current_word = (data or {}).get("current_word", "").strip()
        if not current_word:
            return jsonify({"suggestions": []})

        # Prepare candidates for fuzzy matching
        candidates = ALL_TERMS
        norm_choices = []
        index_to_orig = []
        seen = set()
        for c in candidates:
            lc = str(c).lower()
            if lc in seen:
                continue
            seen.add(lc)
            norm_choices.append(lc)
            index_to_orig.append(c)

        # Find best matches using fuzzy string matching
        matches = process.extract(
            current_word.lower(),
            norm_choices,
            scorer=fuzz.WRatio,
            limit=5,
        )

        # Format suggestions for response
        suggestions = []
        for choice, score, idx in matches:
            original = index_to_orig[idx]
            suggestions.append({"word": original, "score": int(score)})

        return jsonify({"suggestions": suggestions})
    except Exception as e:
        print("Suggestions error:", str(e))
        return jsonify({"suggestions": []})


# API endpoint to extract objects from text
@app.route("/api/get-objects", methods=["POST"])
def get_objects():
    """
    Extracts STIX objects from the input text.
    Returns a list of detected objects for the relationship builder.
    """
    try:
        data = request.get_json(silent=True) or {}
        text = data.get("text", "")
        # Require minimum text length
        if not text or len(re.findall(r"\w+", text)) < 10:
            return jsonify({"objects": []})

        entities = converter.extract_all_entities(text)
        objects = []

        # Format indicators with descriptive names
        for ip in entities["ips"]:
            objects.append({"name": f"IP: {ip}", "type": "indicator", "value": ip})
        for domain in entities["domains"]:
            objects.append({"name": f"Domain: {domain}", "type": "indicator", "value": domain})
        for url in entities["urls"]:
            objects.append({"name": f"URL: {url}", "type": "indicator", "value": url})
        for email in entities["emails"]:
            objects.append({"name": f"Email: {email}", "type": "indicator", "value": email})
        
        # Format hashes with shortened display
        for hash_val in entities["hashes"]:
            # Determine hash type for display
            if re.fullmatch(r"[a-f0-9]{64}", hash_val.lower()):
                ht = "SHA-256"
            elif re.fullmatch(r"[a-f0-9]{40}", hash_val.lower()):
                ht = "SHA1"
            elif re.fullmatch(r"[a-f0-9]{32}", hash_val.lower()):
                ht = "MD5"
            else:
                ht = None
            if ht:
                objects.append({"name": f"{ht}: {hash_val[:8]}...", "type": "indicator", "value": hash_val})

        # Add SDOs (STIX Domain Objects)
        for actor in entities["threat_actors"]:
            objects.append({"name": actor, "type": "threat-actor", "value": actor})
        for tool in entities["tools"]:
            objects.append({"name": tool, "type": "tool", "value": tool})
        for identity in entities["identities"]:
            objects.append({"name": identity, "type": "identity", "value": identity})
        for attack in entities["attack_patterns"]:
            objects.append({"name": attack, "type": "attack-pattern", "value": attack})
        for campaign in entities["campaigns"]:
            objects.append({"name": campaign, "type": "campaign", "value": campaign})
        for malware in entities["malware"]:
            objects.append({"name": malware, "type": "malware", "value": malware})
        for cve in entities["vulnerabilities"]:
            objects.append({"name": cve, "type": "vulnerability", "value": cve})
        for loc in entities.get("locations", []):
            objects.append({"name": loc, "type": "location", "value": loc})

        return jsonify({"objects": objects})
    except Exception as e:
        print("Get objects error:", str(e))
        return jsonify({"error": "Failed to extract objects"}), 500


# Main API endpoint for STIX conversion
@app.route("/api/convert", methods=["POST"])
def convert_to_stix():
    """
    Converts input text to STIX format.
    Returns a STIX bundle and summary statistics.
    """
    try:
        data = request.get_json(silent=True) or {}
        text = data.get("text", "")
        relationships = data.get("relationships", [])
        
        # Validate input length
        if not text or len(re.findall(r"\w+", text)) < 10:
            return jsonify({"error": "Please provide more text (at least 10 words)"}), 400

        # Extract entities and create STIX bundle
        entities = converter.extract_all_entities(text)
        stix_bundle = converter.create_stix_bundle(entities, relationships)

        # Calculate summary statistics
        summary = {
            "total_objects": len(stix_bundle["objects"]),
            "indicators": len([o for o in stix_bundle["objects"] if o["type"] == "indicator"]),
            "threat_actors": len([o for o in stix_bundle["objects"] if o["type"] == "threat-actor"]),
            "tools": len([o for o in stix_bundle["objects"] if o["type"] == "tool"]),
            "attack_patterns": len([o for o in stix_bundle["objects"] if o["type"] == "attack-pattern"]),
            "campaigns": len([o for o in stix_bundle["objects"] if o["type"] == "campaign"]),
            "identities": len([o for o in stix_bundle["objects"] if o["type"] == "identity"]),
            "vulnerabilities": len([o for o in stix_bundle["objects"] if o["type"] == "vulnerability"]),
            "observed_data": len([o for o in stix_bundle["objects"] if o["type"] == "observed-data"]),
            "relationships": len([o for o in stix_bundle["objects"] if o["type"] == "relationship"]),
            "malware": len([o for o in stix_bundle["objects"] if o["type"] == "malware"]),
            "locations": len([o for o in stix_bundle["objects"] if o["type"] == "location"]),
        }

        return jsonify({"stix": stix_bundle, "summary": summary})
    except Exception as e:
        print("Convert error:", str(e))
        return jsonify({"error": f"Conversion failed: {str(e)}"}), 500


# Application entry point
if __name__ == "__main__":
    print(f"Starting STIX converter with {len(ALL_TERMS)} threat intelligence terms")
    print("Libraries loaded: spaCy, iocextract, tldextract, rapidfuzz, stix2")
    app.run(debug=True, port=5001)