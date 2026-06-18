def calculate_risk(results):
    score = 0
    findings = []

    for r in results:
        data_type = str(r.get("data_type", "")).lower()
        value = str(r.get("value", "")).lower()

        if data_type == "error":
            continue

        if data_type in ["email", "phone", "ip"]:
            score += 15
            findings.append(f"Found {data_type}: {r.get('value')}")

        elif data_type in ["breach", "leak", "password"]:
            score += 30
            findings.append(f"High risk finding: {r.get('value')}")

        elif data_type in ["profile", "username", "social"]:
            score += 10
            findings.append(f"Public profile found: {r.get('value')}")

        elif data_type in ["domain", "dns", "subdomain"]:
            score += 12
            findings.append(f"Domain-related finding: {r.get('value')}")

        elif "not found" in value:
            score += 0

        else:
            score += 5

    if score > 100:
        score = 100

    if score >= 70:
        level = "High"
    elif score >= 40:
        level = "Medium"
    elif score > 0:
        level = "Low"
    else:
        level = "None"

    return {
        "score": score,
        "level": level,
        "findings": findings[:10]
    }