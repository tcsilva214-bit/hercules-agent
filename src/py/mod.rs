//! Build 3: the few pieces of Python behaviour the bridge's finding checker relies on, reproduced
//! exactly so the runtime's checker (checker.rs) gives the bridge's verdicts byte for byte.
//! Character classes come from tables generated with the hub's Python (tables.rs, gen_tables.py);
//! nothing here guesses at Unicode properties.

pub mod re;
mod tables;

fn in_table(t: &[(u32, u32)], c: char) -> bool {
    let cp = c as u32;
    t.binary_search_by(|&(a, b)| {
        if cp < a {
            std::cmp::Ordering::Greater
        } else if cp > b {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Equal
        }
    })
    .is_ok()
}

/// re's `\w` (Unicode str patterns).
pub fn is_word(c: char) -> bool {
    if c.is_ascii() {
        return c.is_ascii_alphanumeric() || c == '_';
    }
    in_table(&tables::WORD, c)
}

/// re's `\d`: any Unicode decimal digit (category Nd).
pub fn is_digit(c: char) -> bool {
    if c.is_ascii() {
        return c.is_ascii_digit();
    }
    in_table(&tables::DIGIT, c)
}

/// The value `int()` gives a decimal digit. Every Nd run is 0..9 in order (checked by gen_tables.py).
pub fn digit_value(c: char) -> Option<u32> {
    let cp = c as u32;
    tables::DIGIT
        .iter()
        .find(|&&(a, b)| cp >= a && cp <= b)
        .map(|&(a, _)| (cp - a) % 10)
}

/// `int(s)` for a string of decimal digits (what the checker's patterns capture).
pub fn int_of_digits(s: &str) -> u64 {
    s.chars().fold(0u64, |acc, c| acc.saturating_mul(10).saturating_add(digit_value(c).unwrap_or(0) as u64))
}

/// re's `\s` and `str.isspace()` (identical in Python 3.14, checked by gen_tables.py's output).
pub fn is_space(c: char) -> bool {
    in_table(&tables::STRSPACE, c)
}

pub fn is_printable(c: char) -> bool {
    in_table(&tables::PRINTABLE, c)
}

/// With re.IGNORECASE, does pattern character `p` match text character `c`?
pub fn fold_eq(p: char, c: char) -> bool {
    if p == c {
        return true;
    }
    let lp = p.to_ascii_lowercase();
    if lp.is_ascii_lowercase() {
        if let Some((_, eq)) = tables::FOLD.iter().find(|(l, _)| *l == lp) {
            return eq.contains(&c);
        }
    }
    false
}

/// `str.lower()`.
pub fn lower(s: &str) -> String {
    if s.contains('\u{3A3}') {
        // Final sigma depends on context; Rust applies the same Unicode rule.
        return s.to_lowercase();
    }
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let cp = c as u32;
        match tables::LOWER.binary_search_by_key(&cp, |&(k, _)| k) {
            Ok(i) => {
                let enc = tables::LOWER[i].1;
                out.push_str(enc);
            }
            Err(_) => out.push(c),
        }
    }
    out
}

/// `" ".join(s.split())`.
pub fn ws(s: &str) -> String {
    s.split(is_space).filter(|t| !t.is_empty()).collect::<Vec<_>>().join(" ")
}

/// `s.strip()`, `s.lstrip()`.
pub fn strip(s: &str) -> &str {
    s.trim_matches(is_space)
}
pub fn lstrip(s: &str) -> &str {
    s.trim_start_matches(is_space)
}

/// `len(s)` in code points.
pub fn len(s: &str) -> usize {
    s.chars().count()
}

/// `s[:n]` in code points.
pub fn head(s: &str, n: usize) -> &str {
    match s.char_indices().nth(n) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

/// `s.splitlines()`.
pub fn splitlines(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut it = s.char_indices().peekable();
    while let Some((i, c)) = it.next() {
        let brk = matches!(c, '\n' | '\x0b' | '\x0c' | '\r' | '\x1c' | '\x1d' | '\x1e' | '\u{85}' | '\u{2028}' | '\u{2029}');
        if brk {
            out.push(&s[start..i]);
            let mut next = i + c.len_utf8();
            if c == '\r' {
                if let Some(&(j, '\n')) = it.peek() {
                    it.next();
                    next = j + 1;
                }
            }
            start = next;
        }
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

/// `repr()` of a str.
pub fn repr_str(s: &str) -> String {
    let q = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
    let mut out = String::new();
    out.push(q);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == q => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => out.push_str(&format!("\\x{:02x}", c as u32)),
            c if c.is_ascii() => out.push(c),
            c if is_printable(c) => out.push(c),
            c if (c as u32) <= 0xff => out.push_str(&format!("\\x{:02x}", c as u32)),
            c if (c as u32) <= 0xffff => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push_str(&format!("\\U{:08x}", c as u32)),
        }
    }
    out.push(q);
    out
}

/// `repr()` of a float (Python's shortest round-trip form).
pub fn repr_float(x: f64) -> String {
    if x.is_nan() {
        return "nan".into();
    }
    if x.is_infinite() {
        return if x > 0.0 { "inf".into() } else { "-inf".into() };
    }
    if x == 0.0 {
        return if x.is_sign_negative() { "-0.0".into() } else { "0.0".into() };
    }
    // Rust's {:e} gives the shortest round-trip digits: d.ddde<exp>.
    let e = format!("{:e}", x);
    let (mant, exp) = e.split_once('e').unwrap();
    let exp: i32 = exp.parse().unwrap();
    let neg = mant.starts_with('-');
    let digits: String = mant.chars().filter(|c| c.is_ascii_digit()).collect();
    let sign = if neg { "-" } else { "" };
    if (-4..16).contains(&exp) {
        let n = digits.len() as i32;
        let s = if exp >= 0 {
            if n <= exp + 1 {
                format!("{}{}.0", digits, "0".repeat((exp + 1 - n) as usize))
            } else {
                format!("{}.{}", &digits[..(exp + 1) as usize], &digits[(exp + 1) as usize..])
            }
        } else {
            format!("0.{}{}", "0".repeat((-exp - 1) as usize), digits)
        };
        format!("{sign}{s}")
    } else {
        let m = if digits.len() > 1 { format!("{}.{}", &digits[..1], &digits[1..]) } else { digits.clone() };
        let es = if exp < 0 { format!("-{:02}", -exp) } else { format!("+{:02}", exp) };
        format!("{sign}{m}e{es}")
    }
}

/// `repr()` of a value parsed from JSON (dict keys in the order serde_json keeps them).
pub fn repr(v: &serde_json::Value) -> String {
    use serde_json::Value;
    match v {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Number(n) => num_str(n),
        Value::String(s) => repr_str(s),
        Value::Array(a) => format!("[{}]", a.iter().map(repr).collect::<Vec<_>>().join(", ")),
        Value::Object(o) => format!(
            "{{{}}}",
            o.iter().map(|(k, v)| format!("{}: {}", repr_str(k), repr(v))).collect::<Vec<_>>().join(", ")
        ),
    }
}

fn num_str(n: &serde_json::Number) -> String {
    if let Some(i) = n.as_i64() {
        i.to_string()
    } else if let Some(u) = n.as_u64() {
        u.to_string()
    } else {
        repr_float(n.as_f64().unwrap_or(0.0))
    }
}

/// `str()` of a value parsed from JSON.
pub fn str_of(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        other => repr(other),
    }
}

/// Python truthiness of a JSON value.
pub fn truthy(v: &serde_json::Value) -> bool {
    use serde_json::Value;
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().map(|x| x != 0.0).unwrap_or(true),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// `str(d.get(key) or "")`.
pub fn get_str_or_empty(o: &serde_json::Map<String, serde_json::Value>, key: &str) -> String {
    match o.get(key) {
        Some(v) if truthy(v) => str_of(v),
        _ => String::new(),
    }
}

/// `isinstance(v, int) and not isinstance(v, bool)` for a JSON value.
pub fn is_int(v: &serde_json::Value) -> bool {
    matches!(v, serde_json::Value::Number(n) if n.is_i64() || n.is_u64())
}

/// `type(v).__name__` for a JSON value.
pub fn type_name(v: &serde_json::Value) -> &'static str {
    use serde_json::Value;
    match v {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(n) if n.is_i64() || n.is_u64() => "int",
        Value::Number(_) => "float",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn float_repr_matches_python() {
        for (x, want) in [
            (1e16, "1e+16"), (1e-5, "1e-05"), (123.0, "123.0"), (0.1, "0.1"), (1.5e300, "1.5e+300"),
            (-2.5, "-2.5"), (1234567890123456.0, "1234567890123456.0"), (0.0001, "0.0001"), (12.25, "12.25"),
        ] {
            assert_eq!(repr_float(x), want, "{x}");
        }
    }

    #[test]
    fn classes_and_strings() {
        assert!(is_word('é') && is_word('_') && !is_word('-') && is_word('٣'));
        assert!(is_digit('٣') && digit_value('٣') == Some(3) && !is_digit('²'));
        assert!(is_space('\u{a0}') && is_space('\x1c') && !is_space('\u{200b}'));
        assert_eq!(ws("  a \t b\u{a0}c  "), "a b c");
        assert_eq!(splitlines("a\r\nb\rc\n"), vec!["a", "b", "c"]);
        assert_eq!(repr_str("it's"), "\"it's\"");
        assert_eq!(repr_str("a'\"b"), "'a\\'\"b'");
        assert!(fold_eq('k', '\u{212a}') && fold_eq('s', '\u{17f}') && fold_eq('i', '\u{130}'));
        assert_eq!(lower("ÀBİ"), "àbi\u{307}");
    }
}
