import sys, re, json, csv, ast
from typing import Tuple, Dict, Any, List

EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
IPV4_REGEX = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b')
PASSPORT_REGEX = re.compile(r'\b(?:(?:[A-PR-WYa-pr-wy])[0-9]{7})\b')
AADHAR_REGEX = re.compile(r'\b(?:\d{4}\s?\d{4}\s?\d{4})\b')
TEN_DIGIT_REGEX = re.compile(r'(?<!\d)(\d{10})(?!\d)')

UPI_DOMAINS = {
    "upi","ybl","ibl","oksbi","okhdfcbank","okicici","okaxis","okyesbank","apl","axl","sbi","paytm","ptsbi","jupiter","airtel",
    "oksbi","okaxis","okicici","okhdfcbank","okyesbank","yapl","hsbc","freecharge","mobikwik","gpay"
}
UPI_REGEX = re.compile(r'\b([A-Za-z0-9._-]{2,})@([A-Za-z][A-Za-z0-9._-]{1,})\b')

PHONE_KEYS = {"phone","contact","mobile","alt_phone"}
AADHAR_KEYS = {"aadhar","aadhar_number","aadhaar","aadhaar_number","address_proof"}
PASSPORT_KEYS = {"passport","passport_no","passport_number"}
UPI_KEYS = {"upi","upi_id","vpa"}
NAME_KEYS = {"name"}
FIRST_KEYS = {"first_name"}
LAST_KEYS = {"last_name"}
EMAIL_KEYS = {"email","username"}
ADDRESS_KEYS = {"address","address_line","street"}
CITY_KEYS = {"city"}
STATE_KEYS = {"state"}
PIN_KEYS = {"pin_code","pincode","zip","zipcode","postal_code"}
DEVICE_KEYS = {"device_id","device","android_id","ios_id"}
IP_KEYS = {"ip","ip_address"}

def parse_json_safe(text: str) -> Dict[str, Any]:
    if text is None:
        return {}
    text = text.strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except Exception:
        try:
            return ast.literal_eval(text)
        except Exception:
            try:
                return json.loads(text.replace("'", '"'))
            except Exception:
                return {}

def hide_phone(value: str) -> str:
    def sub_func(m):
        d = m.group(1)
        return d[:2] + "XXXXXX" + d[-2:]
    return TEN_DIGIT_REGEX.sub(sub_func, value)

def only_digits(s: str) -> str:
    return re.sub(r'\D', '', s)

def hide_aadhar(value: str) -> str:
    digits = only_digits(value)
    if len(digits) != 12:
        return value
    hidden = "XXXXXXXX" + digits[-4:]
    return " ".join([hidden[i:i+4] for i in range(0, len(hidden), 4)])

def hide_passport(value: str) -> str:
    return "[REDACTED_PII]"

def hide_upi(value: str) -> str:
    def sub_func(m):
        user, domain = m.group(1), m.group(2)
        if domain.lower() not in UPI_DOMAINS:
            return m.group(0)
        return user[:2] + "****@" + domain
    return UPI_REGEX.sub(sub_func, value)

def hide_email(value: str) -> str:
    def sub_func(m):
        addr = m.group(0)
        local, domain = addr.split("@",1)
        return local[:2] + "****@" + domain
    return EMAIL_REGEX.sub(sub_func, value)

def check_name(val: str) -> bool:
    if not isinstance(val, str): return False
    parts = [p for p in re.split(r'\s+', val.strip()) if p]
    if len(parts) < 2: return False
    alpha = [p for p in parts if re.fullmatch(r"[A-Za-z.\-']{2,}", p)]
    return len(alpha) >= 2

def hide_name(value: str) -> str:
    if not isinstance(value, str): return value
    def mask_word(w: str) -> str:
        if len(w) <= 1: return "X"
        return w[0] + "X" * (len(w)-1)
    return " ".join(mask_word(p) for p in value.split())

def check_address(val: str) -> bool:
    if not isinstance(val, str): return False
    return re.search(r'\d', val) and re.search(r'[A-Za-z]', val) and re.search(r'\b\d{6}\b', val)

def check_ip(val: str) -> bool:
    return isinstance(val, str) and IPV4_REGEX.search(val) is not None

def check_email(val: str) -> bool:
    return isinstance(val, str) and EMAIL_REGEX.search(val) is not None

def check_upi(val: str) -> bool:
    if not isinstance(val, str): return False
    return any(m.group(2).lower() in UPI_DOMAINS for m in UPI_REGEX.finditer(val))

def check_phone(val: str) -> bool:
    return isinstance(val, str) and TEN_DIGIT_REGEX.search(val) is not None

def check_aadhar(val: str) -> bool:
    if not isinstance(val, str): return False
    if AADHAR_REGEX.search(val):
        return True
    return len(only_digits(val)) == 12

def check_passport(val: str) -> bool:
    return isinstance(val, str) and PASSPORT_REGEX.search(val) is not None

def scrub_record(record: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    hit_flag = False
    combos = set()
    clean_rec = dict(record)

    for k, v in list(record.items()):
        key = str(k).lower()
        sval = v if isinstance(v, str) else (str(v) if v is not None else "")

        if key in PHONE_KEYS and check_phone(sval):
            hit_flag = True
        if key in AADHAR_KEYS and check_aadhar(sval):
            hit_flag = True
        if key in PASSPORT_KEYS and check_passport(sval):
            hit_flag = True
        if key in UPI_KEYS and check_upi(sval):
            hit_flag = True
        if key in ADDRESS_KEYS and (check_phone(sval) or check_aadhar(sval) or check_upi(sval)):
            hit_flag = True

        if key in NAME_KEYS and check_name(sval):
            combos.add("name")
        if key in FIRST_KEYS and sval:
            combos.add("first")
        if key in LAST_KEYS and sval:
            combos.add("last")
        if key in EMAIL_KEYS and check_email(sval):
            combos.add("email")
        if key in ADDRESS_KEYS and check_address(sval):
            combos.add("address")
        if key in CITY_KEYS and sval:
            combos.add("city")
        if key in STATE_KEYS and sval:
            combos.add("state")
        if key in PIN_KEYS and re.fullmatch(r'\d{6}', str(sval) if sval is not None else ""):
            combos.add("pin")
        if key in DEVICE_KEYS and sval:
            combos.add("device")
        if key in IP_KEYS and check_ip(sval):
            combos.add("ip")

    if ("city" in combos and "pin" in combos) or ("city" in combos and "state" in combos):
        combos.add("address")

    combo_count = 0
    if "name" in combos or ("first" in combos and "last" in combos):
        combo_count += 1
    if "email" in combos:
        combo_count += 1
    if "address" in combos:
        combo_count += 1
    if "device" in combos or "ip" in combos:
        combo_count += 1

    pii_flag = hit_flag or (combo_count >= 2)

    if pii_flag:
        for k, v in list(clean_rec.items()):
            key = str(k).lower()
            sval = v if isinstance(v, str) else (str(v) if v is not None else "")

            if key in PHONE_KEYS and check_phone(sval):
                clean_rec[k] = hide_phone(sval)
                continue
            if key in AADHAR_KEYS and check_aadhar(sval):
                clean_rec[k] = hide_aadhar(sval)
                continue
            if key in PASSPORT_KEYS and check_passport(sval):
                clean_rec[k] = hide_passport(sval)
                continue
            if key in UPI_KEYS and check_upi(sval):
                clean_rec[k] = hide_upi(sval)
                continue

            if (("name" in combos) or ("first" in combos and "last" in combos)) and (key in NAME_KEYS or key in FIRST_KEYS or key in LAST_KEYS):
                clean_rec[k] = hide_name(sval)
                continue
            if "email" in combos and key in EMAIL_KEYS and check_email(sval):
                clean_rec[k] = hide_email(sval)
                continue
            if "address" in combos and (key in ADDRESS_KEYS or key in CITY_KEYS or key in STATE_KEYS or key in PIN_KEYS):
                if key in ADDRESS_KEYS:
                    clean_rec[k] = re.sub(r'\d', 'X', sval)
                else:
                    clean_rec[k] = sval
                continue
            if ("device" in combos or "ip" in combos) and (key in DEVICE_KEYS or key in IP_KEYS):
                clean_rec[k] = "[REDACTED_PII]"
                continue

            if isinstance(v, str) and key in ADDRESS_KEYS:
                clean_rec[k] = hide_phone(hide_upi(hide_aadhar(hide_passport(v))))

    return clean_rec, pii_flag

def handle_csv(infile: str, outfile: str):
    rows_out: List[Dict[str, Any]] = []
    with open(infile, newline='', encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rec_id = row.get("record_id")
            raw = row.get("Data_json", "") or row.get("data_json","")
            data = parse_json_safe(raw)
            redacted, flag = scrub_record(data)
            rows_out.append({
                "record_id": rec_id,
                "redacted_data_json": json.dumps(redacted, ensure_ascii=False),
                "is_pii": str(bool(flag))
            })
    with open(outfile, "w", newline='', encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["record_id","redacted_data_json","is_pii"])
        writer.writeheader()
        writer.writerows(rows_out)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 detector_Azimusshan_Khan.py input.csv [output.csv]")
        sys.exit(1)
    inp = sys.argv[1]
    outp = sys.argv[2] if len(sys.argv) > 2 else "redacted_output_candidate_full_name.csv"
    handle_csv(inp, outp)
    print(f"Wrote {outp}")
