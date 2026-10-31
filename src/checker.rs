//! Build 3: the bridge's finding checker (the host bridge's hercules_lane.py, EVIDENCE_V1 with
//! COMPARE_V1, PLACE_V1/V2, FLAT_V1, COUNT_CHECK_V1, CONTRADICTED_V1 and CROSSFILE_V1), ported line for
//! line so that evidence.check and answer.submit give the model, during its session, the verdict the
//! bridge will give after it. Every message is the bridge's own text. The shared corpus
//! (tests/checker/) holds the Python's results for the same cases; this file must agree exactly.
//!
//! The function names follow the Python ones; read the two side by side.

use crate::py::re::{Regex, I, NONE};
use crate::py::{self, int_of_digits, ws};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashSet};
use std::sync::OnceLock;

pub const FRAGMENT_MIN_CHARS: usize = 12;
pub const JOIN_MAX_LINES: usize = 3;

const NUM_WORDS: [&str; 21] = [
    "zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven", "twelve",
    "thirteen", "fourteen", "fifteen", "sixteen", "seventeen", "eighteen", "nineteen", "twenty",
];

struct Pats {
    source_id: Regex,
    bare: Regex,
    total: Regex,
    parts: [Regex; 3],
    unit: Regex,
    unit_after: Regex,
    sum: Regex,
    sentences: Regex,
    line_no: Regex,
    ellipsis: Regex,
    key: Regex,
    dash: Regex,
    number: Regex,
    contradiction: Regex,
    finding_n: Regex,
    side_id: Regex,
}

fn pats() -> &'static Pats {
    static P: OnceLock<Pats> = OnceLock::new();
    P.get_or_init(|| {
        let num = format!(r"(\d{{1,4}}|{})", NUM_WORDS.join("|"));
        let end = r"(?![\w\-/]|[.,]\w)";
        Pats {
            source_id: Regex::must(r"(?<![A-Za-z0-9_])S(\d{1,2})(?![0-9])", NONE),
            bare: Regex::must(&format!(r"(?<![\w.\-/]){num}{end}"), I),
            total: Regex::must(&format!(r"(?<![\w.\-/]){num}\s+(?:[A-Za-z_`'-]+\s+){{0,2}}?[A-Za-z_`'-]+s\b"), I),
            parts: [
                Regex::must(&format!(r"[\w`'-]+\s*(?:has|have|gets|=|:)\s*{num}{end}"), I),
                Regex::must(&format!(r"[\w`'-]+\s*\(\s*{num}{end}"), I),
                Regex::must(&format!(r#"(?<![\w.\-/]){num}\s+(?:to|for|in|under|on)\s+(?:the\s+)?[`'"]?[\w-]+"#), I),
            ],
            unit: Regex::must(r"\s+((?:[A-Za-z_`'-]+\s+){0,2})([A-Za-z_`'-]+)\s*\)", NONE),
            // COUNT_CHECK_V3 (Build 3.4, with the bridge): what a "worker has 7 classes" part counts, and a sum
            // written out with plus signs ("7 + 5 + 3 + 2 = 16", "... + 2 operator_only, which sum to 16").
            unit_after: Regex::must(r"\s+([A-Za-z_`'-]+)(?:\s+([A-Za-z_`'-]+))?\s*(?:[,;.)]|$|and\s)", NONE),
            sum: Regex::must(
                &format!(
                    r#"(?<![A-Za-z0-9_./:'‘"“`{signs}])(?<![0-9'‘"“`{signs}][ \t])(?<![0-9],)({part}(?:[ \t]*\+[ \t]*{part}){{1,19}})(?:[ \t]*=[ \t]*|,?[ \t]+(?:which[ \t]+|that[ \t]+)?(?:sums?|adds?[ \t]+up)[ \t]+to[ \t]+)([0-9]{{1,5}})(?![A-Za-z0-9_/:'’"”`{signs}]|[.,][A-Za-z0-9_]|[ \t]+[0-9{signs}])"#,
                    part = r"[0-9]{1,4}(?:[ \t]+[A-Za-z_][A-Za-z0-9_`'-]*){0,2}",
                    signs = SUM_SIGNS
                ),
                NONE,
            ),
            sentences: Regex::must(r"(?<=[.;!?])\s+|\n+", NONE),
            line_no: Regex::must(r"^\s*(?:line\s+)?\d{1,6}\s*[|:]\s?", I),
            ellipsis: Regex::must(r"^(?:\.\.\.|…)\s*|\s*(?:\.\.\.|…)$", NONE),
            key: Regex::must(r"(?:^|\s)-?\s*([A-Za-z_][\w.\-/]*):(?=\s|$)", NONE),
            dash: Regex::must(r"^-\s+", NONE),
            number: Regex::must(r"\b\d+\b", NONE),
            contradiction: Regex::must(
                r#"; the bridge counts \d|" is not a line of S\d|" is in S\d[^"]*, not in S\d|does not fit one place in S\d|says "different", but both|says "same", but S\d"#,
                NONE,
            ),
            finding_n: Regex::must(r"finding (\d+)", NONE),
            side_id: Regex::must(r"S\d{1,2}", NONE),
        }
    })
}

/// `_n`: a captured count as a number. None where Python's `_NUM_WORDS[tok.lower()]` would raise
/// (a number word matched under re.I through U+017F, U+0130 or U+0131); total_mismatch then gives no
/// verdict, where the bridge would stop with an error.
fn n_of(tok: &str) -> Option<u64> {
    if tok.chars().all(py::is_digit) {
        Some(int_of_digits(tok))
    } else {
        let l = py::lower(tok);
        NUM_WORDS.iter().position(|w| *w == l).map(|i| i as u64)
    }
}

fn chars(s: &str) -> Vec<char> {
    s.chars().collect()
}

/// `_sentences`.
fn sentences(text: &str) -> Vec<String> {
    pats().sentences.split(text).into_iter().filter(|s| !py::strip(s).is_empty()).collect()
}

/// `_same_word`: one word, singular or plural.
fn same_word(a: &str, b: &str) -> bool {
    a == b || a == format!("{b}s") || a == format!("{b}es") || b == format!("{a}s") || b == format!("{a}es")
}

/// `_units_known` (COUNT_CHECK_V3): enough parts name what they count (at most one without, at least two with).
fn units_known(units: &[Option<Vec<String>>]) -> bool {
    units.iter().filter(|u| u.is_none()).count() <= 1 && units.iter().filter(|u| u.is_some()).count() >= 2
}

/// `total_mismatch` (COUNT_CHECK_V1, V2 from Build 3.3, V3 from Build 3.4).
pub fn total_mismatch(sentence: &str, previous: &str) -> Option<String> {
    let p = pats();
    let (head, tail) = sentence.split_once(':')?;
    let tail_c = chars(tail);
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut parts: Vec<u64> = Vec::new();
    let mut units: Vec<Option<Vec<String>>> = Vec::new();
    for (k, rx) in p.parts.iter().enumerate() {
        for m in rx.find_iter(&tail_c) {
            let span = m.groups[0].unwrap();
            if spans.iter().any(|&(a, b)| a <= span.0 && span.0 < b) {
                continue;
            }
            spans.push(span);
            parts.push(n_of(&tail_c[span.0..span.1].iter().collect::<String>())?);
            // `_UNIT.match(tail, span[1])`: "worker (7 classes)", what the part counts; V3 (Build 3.4):
            // `_UNIT_AFTER.match(tail, span[1])` likewise for "worker has 7 classes,"
            let u: Option<Vec<String>> = match k {
                1 => p.unit.match_at(&tail_c, span.1, false).and_then(|u| u.group(&tail_c, 2)).map(|w| vec![py::lower(&w)]),
                0 => p.unit_after.match_at(&tail_c, span.1, false).map(|u| {
                    [u.group(&tail_c, 1), u.group(&tail_c, 2)].into_iter().flatten().map(|w| py::lower(&w)).collect()
                }),
                _ => None,
            };
            units.push(u);
        }
    }
    if parts.len() < 2 {
        return None;
    }
    if p.bare.findall(tail).len() != parts.len() {
        return None;
    }
    let mut head = head.to_string();
    let mut from_previous = false;
    if p.bare.findall(&head).is_empty() && !previous.is_empty() {
        head = previous.to_string();
        from_previous = true;
    }
    let head_c = chars(&head);
    let found = p.total.find_iter(&head_c);
    let mut totals: Vec<u64> = found.iter().map(|m| n_of(&m.group(&head_c, 1).unwrap_or_default())).collect::<Option<Vec<_>>>()?;
    // COUNT_CHECK_V2 (Build 3.3, with the bridge): the sentence before counts only when it also gives
    // the number of parts; a lone number of parts that counts other things than the parts is no total.
    let n_parts = parts.len() as u64;
    if from_previous && !totals.contains(&n_parts) {
        return None;
    }
    if totals.len() > 1 {
        if let Some(i) = totals.iter().position(|&t| t == n_parts) {
            totals.remove(i);
        }
    } else if totals.len() == 1 && totals[0] == n_parts && units_known(&units) {
        let whole = found[0].group(&head_c, 0).unwrap_or_default();
        let noun = py::lower(whole.split(py::is_space).filter(|w| !w.is_empty()).last().unwrap_or(""));
        if !units.iter().flatten().flatten().any(|u| same_word(&noun, u)) {
            return None;
        }
    }
    if totals.len() != 1 || p.bare.findall(&head).len() != p.total.findall(&head).len() {
        return None;
    }
    let sum: u64 = parts.iter().sum();
    if totals[0] == sum {
        return None;
    }
    Some(format!(
        "says {} in total but its parts {} make {}",
        totals[0],
        parts.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(" + "),
        sum
    ))
}

/// COUNT_CHECK_V3: `_SUM_SIGNS`, `_SUM_OPS`, `_SUM_OF`, `_SUM_UNITS` (see the bridge's comment above `_SUM_PART`).
const SUM_SIGNS: &str = "+=*×÷/^%−–—·⋅-";
const SUM_OPS: [&str; 9] = ["minus", "plus", "times", "x", "by", "less", "over", "multiplied", "divided"];
const SUM_OF: [&str; 7] = ["half", "quarter", "third", "twice", "double", "triple", "percent"];
const SUM_UNITS: [&str; 53] = [
    "ms", "millisecond", "milliseconds", "s", "sec", "secs", "second", "seconds", "min", "mins", "minute", "minutes", "h", "hr",
    "hrs", "hour", "hours", "day", "days", "week", "weeks", "month", "months", "year", "years", "b", "byte", "bytes", "kb",
    "kib", "mb", "mib", "gb", "gib", "tb", "tib", "k", "m", "g", "kilobyte", "kilobytes", "megabyte", "megabytes",
    "gigabyte", "gigabytes", "percent", "mm", "cm", "km", "meter", "meters", "metre", "metres",
];

fn is_tab_space(c: char) -> bool {
    c == ' ' || c == '\t'
}

/// `_word_before`: the ASCII word that ends, after spaces or tabs, just before char position `at`; "" if none.
fn word_before(text: &[char], at: usize) -> String {
    let mut i = at;
    while i > 0 && is_tab_space(text[i - 1]) {
        i -= 1;
    }
    let mut j = i;
    while j > 0 && text[j - 1].is_ascii_alphabetic() {
        j -= 1;
    }
    if j < i && i < at { text[j..i].iter().collect::<String>().to_ascii_lowercase() } else { String::new() }
}

/// `_word_after`: the ASCII word that starts, after spaces or tabs, just after char position `at`; "" if none.
fn word_after(text: &[char], at: usize) -> String {
    let mut i = at;
    while i < text.len() && is_tab_space(text[i]) {
        i += 1;
    }
    let mut j = i;
    while j < text.len() && text[j].is_ascii_alphabetic() {
        j += 1;
    }
    if at < i && i < j { text[i..j].iter().collect::<String>().to_ascii_lowercase() } else { String::new() }
}

/// `_quoted`: is char position `at` inside a quoted span ("...", `...` or curly double quotes) of the sentence?
fn quoted(text: &[char], at: usize) -> bool {
    let before = &text[..at];
    let n = |c: char| before.iter().filter(|&&x| x == c).count();
    n('"') % 2 == 1 || n('`') % 2 == 1 || n('\u{201c}') > n('\u{201d}')
}

/// `sum_mismatches` (COUNT_CHECK_V3, Build 3.4): every written-out sum in the sentence whose result is not the
/// sum of its parts.
pub fn sum_mismatches(sentence: &str) -> Vec<String> {
    let p = pats();
    let c = chars(sentence);
    let unit = |w: &str| SUM_UNITS.contains(&w);
    let mut out = Vec::new();
    for m in p.sum.find_iter(&c) {
        let mut before = word_before(&c, m.start);
        if before == "of" {
            // "half of 4 + 2 = 4": the word before "of"
            let mut h = m.start;
            while h > 0 && is_tab_space(c[h - 1]) {
                h -= 1;
            }
            let w = word_before(&c, h.saturating_sub(2));
            before = if w.is_empty() { "of".to_string() } else { w };
        }
        let after = word_after(&c, m.end);
        if quoted(&c, m.start) || SUM_OPS.contains(&before.as_str()) || SUM_OF.contains(&before.as_str()) || SUM_OPS.contains(&after.as_str()) {
            continue;
        }
        let addends = m.group(&c, 1).unwrap_or_default();
        let pieces: Vec<Vec<&str>> = addends.split('+').map(|p| p.split(is_tab_space).filter(|w| !w.is_empty()).collect()).collect();
        let parts: Vec<u64> = pieces.iter().map(|p| p.first().map(|d| int_of_digits(d)).unwrap_or(0)).collect();
        let words: Vec<String> = pieces.iter().map(|p| p.get(1).map(|w| w.to_ascii_lowercase()).unwrap_or_default()).collect();
        let mut all: Vec<&str> = words.iter().map(String::as_str).collect();
        if !after.is_empty() {
            all.push(after.as_str());
        }
        let any_unit = words.iter().any(|w| unit(w)) || unit(&after);
        if any_unit && !all.iter().all(|w| !w.is_empty() && same_word(w, &words[0])) {
            continue; // units of measure that differ: a conversion
        }
        let total = int_of_digits(&m.group(&c, 2).unwrap_or_default());
        let sum: u64 = parts.iter().sum();
        if total != sum {
            out.push(format!(
                "says {total} in total but its parts {} make {sum}",
                parts.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(" + ")
            ));
        }
    }
    out
}

/// `count_mismatches`.
pub fn count_mismatches(parsed: &Value) -> Vec<String> {
    let Some(o) = parsed.as_object() else { return vec![] };
    let mut texts: Vec<(String, Option<&Value>)> = vec![("summary".into(), o.get("summary"))];
    if let Some(Value::Array(fs)) = o.get("findings") {
        for (n, f) in fs.iter().enumerate() {
            if let Some(fo) = f.as_object() {
                texts.push((format!("finding {}", n + 1), fo.get("claim")));
            }
        }
    }
    let mut out = Vec::new();
    for (wh, text) in texts {
        let Some(Value::String(text)) = text else { continue };
        let ss = sentences(text);
        for (i, s) in ss.iter().enumerate() {
            let prev = if i > 0 { ss[i - 1].as_str() } else { "" };
            if let Some(bad) = total_mismatch(s, prev) {
                out.push(format!("{wh} {bad}"));
            }
            for bad in sum_mismatches(s) {
                out.push(format!("{wh} {bad}"));
            }
        }
    }
    out
}

/// `normalize_shape` (LIST_SHAPE_V1): returns what was changed.
pub fn normalize_shape(parsed: &mut Value) -> Vec<String> {
    let Some(o) = parsed.as_object_mut() else { return vec![] };
    let Some(Value::String(s)) = o.get("uncertainties") else { return vec![] };
    let t = py::strip(s).to_string();
    o.insert("uncertainties".into(), if t.is_empty() { Value::Array(vec![]) } else { Value::Array(vec![Value::String(t)]) });
    vec!["uncertainties: one string, made a one-item list".into()]
}

// ------------------------------------------------------------------ EVIDENCE_V1

/// `source_lines`.
pub fn source_lines(text: &str) -> Vec<String> {
    let mut lines: Vec<&str> = text.split('\n').collect();
    if lines.last() == Some(&"") {
        lines.pop();
    }
    lines
        .into_iter()
        .map(|ln| {
            let ln = ln.strip_suffix('\r').unwrap_or(ln);
            ln.chars()
                .map(|c| {
                    let cp = c as u32;
                    if cp <= 0x08 || (0x0b..=0x1f).contains(&cp) || cp == 0x7f || c == '\u{2028}' || c == '\u{2029}' {
                        '\u{fffd}'
                    } else {
                        c
                    }
                })
                .collect()
        })
        .collect()
}

fn pair_close(c: char) -> Option<char> {
    match c {
        '"' => Some('"'),
        '\'' => Some('\''),
        '`' => Some('`'),
        '\u{201c}' => Some('\u{201d}'),
        '\u{2018}' => Some('\u{2019}'),
        _ => None,
    }
}

fn strip_pair(cand: &str) -> Option<String> {
    let cs = chars(cand);
    if cs.len() >= 2 && pair_close(cs[0]) == Some(cs[cs.len() - 1]) {
        Some(ws(&cs[1..cs.len() - 1].iter().collect::<String>()))
    } else {
        None
    }
}

/// `_quote_candidates`.
fn quote_candidates(line: &str) -> Vec<String> {
    let p = pats();
    let mut out: Vec<String> = Vec::new();
    let base = ws(line);
    let no_num = ws(&p.line_no.sub_empty(line, 1));
    for cand in [base, no_num] {
        if cand.is_empty() {
            continue;
        }
        out.push(cand.clone());
        let mut cand = cand;
        if let Some(inner) = strip_pair(&cand) {
            cand = inner;
            out.push(cand.clone());
        }
        let trimmed = ws(&p.ellipsis.sub_empty(&cand, 0));
        if trimmed != cand {
            out.push(trimmed);
        }
    }
    let mut seen = HashSet::new();
    out.into_iter().filter(|c| seen.insert(c.clone())).filter(|c| !c.is_empty()).collect()
}

pub struct Indexed {
    pub text: String,
    pub lines: Vec<String>,
    pub set: HashSet<String>,
    pub joined: Vec<String>,
    pub raw: Vec<String>,
    pub paths: Vec<(usize, String)>,
}

/// `_paths` (PLACE_V1).
fn paths_of(raw: &[String]) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut stack: Vec<(usize, String)> = Vec::new();
    for (i, r) in raw.iter().enumerate() {
        if py::strip(r).is_empty() {
            continue;
        }
        let depth = py::len(r) - py::len(py::lstrip(r));
        while stack.last().map(|s| s.0 >= depth).unwrap_or(false) {
            stack.pop();
        }
        let line = ws(r);
        if let Some(top) = stack.last() {
            out.push((i, format!("{} {}", top.1, line)));
            if stack.len() > 1 {
                out.push((i, format!("{} {} {}", stack[stack.len() - 2].1, top.1, line)));
            }
        }
        stack.push((depth, line));
    }
    out
}

fn join_nonempty(xs: &[String]) -> String {
    xs.iter().filter(|x| !x.is_empty()).cloned().collect::<Vec<_>>().join(" ")
}

/// `_joins`.
fn joins(lines: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for k in 2..=JOIN_MAX_LINES {
        let n = (lines.len() + 1).saturating_sub(k);
        for i in 0..n {
            out.push(join_nonempty(&lines[i..i + k]));
        }
    }
    out
}

impl Indexed {
    pub fn new(text: &str) -> Indexed {
        let raw = source_lines(text);
        let lines: Vec<String> = raw.iter().map(|l| ws(l)).collect();
        let set = lines.iter().cloned().collect();
        let joined = joins(&lines);
        let paths = paths_of(&raw);
        Indexed { text: text.to_string(), lines, set, joined, raw, paths }
    }
}

/// `quote_in`.
fn quote_in(line: &str, ix: &Indexed) -> bool {
    for cand in quote_candidates(line) {
        if ix.set.contains(&cand) {
            return true;
        }
        if py::len(&cand) < FRAGMENT_MIN_CHARS {
            continue;
        }
        if ix.lines.iter().any(|ln| ln.contains(&cand)) {
            return true;
        }
        if ix.joined.iter().any(|j| j.contains(&cand)) {
            return true;
        }
        if ix.paths.iter().any(|(_, t)| t.contains(&cand)) {
            return true;
        }
    }
    false
}

/// `line_spans` (PLACE_V1).
fn line_spans(line: &str, ix: &Indexed) -> Vec<(usize, usize)> {
    for cand in quote_candidates(line) {
        let long = py::len(&cand) >= FRAGMENT_MIN_CHARS;
        let spans: Vec<(usize, usize)> = ix
            .lines
            .iter()
            .enumerate()
            .filter(|(_, ln)| **ln == cand || (long && ln.contains(&cand)))
            .map(|(i, _)| (i, i))
            .collect();
        if !spans.is_empty() {
            return spans;
        }
        if !long {
            continue;
        }
        for k in 2..=JOIN_MAX_LINES {
            let n = (ix.lines.len() + 1).saturating_sub(k);
            let spans: Vec<(usize, usize)> =
                (0..n).filter(|&i| join_nonempty(&ix.lines[i..i + k]).contains(&cand)).map(|i| (i, i + k - 1)).collect();
            if !spans.is_empty() {
                return spans;
            }
        }
        let mut set: Vec<(usize, usize)> = ix.paths.iter().filter(|(_, t)| t.contains(&cand)).map(|(i, _)| (*i, *i)).collect();
        set.sort();
        set.dedup();
        if !set.is_empty() {
            return set;
        }
    }
    vec![]
}

fn indent(ix: &Indexed, i: usize) -> usize {
    match ix.raw.get(i) {
        Some(r) => py::len(r) - py::len(py::lstrip(r)),
        None => 0,
    }
}

/// `_same_entry`.
fn same_entry(ix: &Indexed, a: usize, b: usize) -> bool {
    let floor = indent(ix, a).min(indent(ix, b));
    ((a + 1)..b).all(|j| py::strip(&ix.raw[j]).is_empty() || indent(ix, j) > floor)
}

/// `_chains`.
fn chains_of(qlines: &[String], ix: &Indexed) -> Vec<Vec<(usize, usize)>> {
    let spans: Vec<Vec<(usize, usize)>> = qlines.iter().map(|q| line_spans(q, ix)).collect();
    if spans.is_empty() || spans.iter().any(|s| s.is_empty()) {
        return vec![];
    }
    let mut out = Vec::new();
    for &first in &spans[0] {
        let mut chain = vec![first];
        let mut ok = true;
        for later in &spans[1..] {
            let end = chain.last().unwrap().1;
            let nxt = if later.len() == 1 {
                if later[0].0 > end { Some(later[0]) } else { None }
            } else {
                let n = later.iter().copied().find(|&(a, _)| a > end);
                match n {
                    Some(x) if same_entry(ix, end, x.0) => Some(x),
                    _ => None,
                }
            };
            match nxt {
                None => {
                    ok = false;
                    break;
                }
                Some(x) => chain.push(x),
            }
        }
        if ok {
            out.push(chain);
        }
    }
    out
}

/// `placements`.
fn placements(qlines: &[String], ix: &Indexed) -> Vec<usize> {
    chains_of(qlines, ix).iter().map(|c| c[0].0 + 1).collect()
}

/// `_ancestors` (PLACE_V2).
fn ancestors(ix: &Indexed, i: usize) -> Vec<usize> {
    let mut out = Vec::new();
    let mut depth = indent(ix, i);
    for j in (0..i).rev() {
        let r = &ix.raw[j];
        if !py::strip(r).is_empty() && indent(ix, j) < depth {
            out.push(j);
            depth = indent(ix, j);
            if depth == 0 {
                break;
            }
        }
    }
    out
}

/// `_parent`.
fn parent(ix: &Indexed, i: usize) -> Option<String> {
    let depth = indent(ix, i);
    for j in (0..i.min(ix.raw.len())).rev() {
        let r = &ix.raw[j];
        if !py::strip(r).is_empty() && py::len(r) - py::len(py::lstrip(r)) < depth {
            return Some(ws(r));
        }
    }
    None
}

/// `flat_repeat` (FLAT_V1).
fn flat_repeat(qlines: &[String], ix: &Indexed) -> usize {
    let chains = chains_of(qlines, ix);
    if chains.len() < 2 {
        return 0;
    }
    let mut texts: HashSet<Vec<String>> = HashSet::new();
    for chain in &chains {
        let lines: Vec<usize> = chain.iter().flat_map(|&(a, b)| a..=b).collect();
        if lines.iter().any(|&i| indent(ix, i) > 0 || parent(ix, i).is_some()) {
            return 0;
        }
        texts.insert(lines.iter().map(|&i| ix.lines[i].clone()).collect());
    }
    if texts.len() == 1 { chains.len() } else { 0 }
}

/// `unbacked_numbers`.
fn unbacked_numbers(claim: &str, evidence: &str) -> Vec<String> {
    let p = pats();
    let have: HashSet<String> = p.number.findall(evidence).into_iter().collect();
    let mut seen = HashSet::new();
    p.number.findall(claim).into_iter().filter(|n| seen.insert(n.clone())).filter(|n| !have.contains(n)).collect()
}

/// `_short`.
pub fn short(text: &str, n: usize) -> String {
    let t = ws(text);
    if py::len(&t) <= n { t } else { format!("{}...", py::head(&t, n - 3)) }
}

/// `place_problem` (PLACE_V1, FLAT_V1).
fn place_problem(qlines: &[String], ix: &Indexed, sid: &str) -> Option<String> {
    let places = placements(qlines, ix);
    if places.len() == 1 || flat_repeat(qlines, ix) > 0 {
        return None;
    }
    if places.is_empty() {
        return Some(format!(
            "does not fit one place in {sid}: each quoted line must be the next match after the line before it, top to bottom. A key line followed by a value from another entry does not fit"
        ));
    }
    let nums = places.iter().take(6).map(|p| p.to_string()).collect::<Vec<_>>().join(", ") + if places.len() > 6 { ", ..." } else { "" };
    let mut parents: Vec<String> = Vec::new();
    for &n in &places {
        if let Some(pp) = parent(ix, n - 1) {
            if !pp.is_empty() && !parents.contains(&pp) {
                parents.push(pp);
            }
        }
    }
    let under = if parents.len() > 1 {
        format!(
            "; each sits under a different entry ({}{})",
            parents.iter().take(4).map(|p| format!("\"{}\"", short(p, 40))).collect::<Vec<_>>().join(", "),
            if parents.len() > 4 { ", ..." } else { "" }
        )
    } else {
        String::new()
    };
    Some(format!(
        "fits {} places in {sid} (lines {nums}){under}. Quote it with the line that says which entry it belongs to, for example that entry's key line above it, so it fits one place",
        places.len()
    ))
}

/// `grep_count`: what grep -c -F prints.
pub fn grep_count(text: &str, needle: &str, ignore_case: bool) -> u64 {
    let mut lines: Vec<&str> = text.split('\n').collect();
    if lines.last() == Some(&"") {
        lines.pop();
    }
    if ignore_case {
        let n = py::lower(needle);
        lines.iter().filter(|l| py::lower(l).contains(&n)).count() as u64
    } else {
        lines.iter().filter(|l| l.contains(needle)).count() as u64
    }
}

fn ids_in(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for x in pats().source_id.findall(text) {
        let id = format!("S{}", int_of_digits(&x));
        if !out.contains(&id) {
            out.push(id);
        }
    }
    out
}

fn sid_num(s: &str) -> u64 {
    int_of_digits(&s[1..])
}

fn sorted_ids(mut v: Vec<String>) -> Vec<String> {
    v.sort_by_key(|s| sid_num(s));
    v
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Check {
    pub verified: Vec<String>,
    pub unverified: Vec<String>,
    pub set_evidence: BTreeMap<usize, String>,
}

/// `verify_findings`: check every finding against the approved copies ({"S1": text, ...}).
pub fn verify_findings(findings: Option<&Value>, texts: &BTreeMap<String, String>) -> Check {
    let idx: BTreeMap<String, Indexed> = texts.iter().map(|(k, t)| (k.clone(), Indexed::new(t))).collect();
    let mut c = Check::default();
    let Some(Value::Array(findings)) = findings else {
        c.unverified.push("findings is not a list".into());
        return c;
    };
    for (n0, f) in findings.iter().enumerate() {
        let n = n0 + 1;
        let wh = format!("finding {n}");
        let Some(f) = f.as_object() else {
            c.unverified.push(format!("{wh}: not an object with claim, evidence and source"));
            continue;
        };
        let claim = py::get_str_or_empty(f, "claim");
        if py::strip(&claim).is_empty() {
            c.unverified.push(format!("{wh}: no claim"));
            continue;
        }
        let ids = ids_in(&py::get_str_or_empty(f, "source"));
        if matches!(f.get("compare"), Some(v) if !v.is_null()) {
            let (ok, msg, ev) = check_comparison(n, f, &ids, &idx);
            if ok {
                c.verified.push(msg);
                c.set_evidence.insert(n, ev);
            } else {
                c.unverified.push(msg);
            }
            continue;
        }
        if ids.is_empty() {
            c.unverified.push(format!("{wh}: \"source\" names no approved source id (S1, S2, ...)"));
            continue;
        }
        if ids.len() > 1 {
            c.unverified.push(format!(
                "{wh}: cites {}; a quote or count rests on ONE file. Give one finding per file, and a comparison finding for how they compare",
                ids.join(", ")
            ));
            continue;
        }
        let sid = ids[0].clone();
        let Some(ix) = idx.get(&sid) else {
            c.unverified.push(format!("{wh}: {sid} is not an approved source"));
            continue;
        };
        let wh = format!("finding {n} ({sid})");
        let others: Vec<String> = sorted_ids(ids_in(&claim).into_iter().filter(|x| *x != sid).collect());
        if !others.is_empty() {
            c.unverified.push(format!(
                "{wh}: the claim also speaks about {}; a quote or count describes only its own file. State how files compare in a comparison finding",
                others.join(", ")
            ));
            continue;
        }
        if let Some(count) = f.get("count").filter(|v| !v.is_null()) {
            let co = count.as_object();
            let text_ = co.and_then(|o| o.get("text"));
            let lines_ = co.and_then(|o| o.get("lines"));
            let ic = co.and_then(|o| o.get("ignore_case")) == Some(&Value::Bool(true));
            let text_ok = matches!(text_, Some(Value::String(s)) if !s.is_empty());
            let lines_ok = matches!(lines_, Some(v) if py::is_int(v) && !v.as_i64().map(|x| x < 0).unwrap_or(false));
            let extra = co.map(|o| o.keys().any(|k| !["text", "lines", "ignore_case"].contains(&k.as_str()))).unwrap_or(false);
            if !text_ok || !lines_ok || extra {
                c.unverified.push(format!("{wh}: \"count\" must be {{\"text\": \"<exact text>\", \"lines\": <number>}}"));
                continue;
            }
            let text_ = text_.and_then(Value::as_str).unwrap();
            let want = lines_.unwrap();
            let real = grep_count(&ix.text, text_, ic);
            let equal = want.as_u64() == Some(real);
            if !equal {
                c.unverified.push(format!(
                    "{wh}: says {} lines of {sid} contain \"{}\"; the bridge counts {real}",
                    py::str_of(want),
                    short(text_, 60)
                ));
                continue;
            }
            c.set_evidence.insert(
                n,
                format!(
                    "lines of {sid} containing \"{text_}\"{}: {real} (recounted by the bridge)",
                    if ic { " (any case)" } else { "" }
                ),
            );
            c.verified.push(format!("{wh}: count of \"{}\" = {real}, recounted", short(text_, 60)));
            continue;
        }
        let evidence = f.get("evidence");
        let qlines: Vec<String> = match evidence {
            Some(Value::String(e)) => e.split('\n').filter(|l| !py::strip(l).is_empty()).map(String::from).collect(),
            _ => vec![],
        };
        if qlines.is_empty() {
            c.unverified.push(format!("{wh}: no evidence; quote whole line(s) of {sid}, or give a count"));
            continue;
        }
        let missing: Vec<&String> = qlines.iter().filter(|l| !quote_in(l, ix)).collect();
        if missing.is_empty() {
            if let Some(wp) = place_problem(&qlines, ix, &sid) {
                let shown = if qlines.len() == 1 { qlines[0].clone() } else { qlines.join(" / ") };
                c.unverified.push(format!("{wh}: \"{}\" {wp}", short(&shown, 80)));
                continue;
            }
            let s = if qlines.len() > 1 { "s" } else { "" };
            let repeats = flat_repeat(&qlines, ix);
            if repeats > 0 {
                let ev = evidence.and_then(Value::as_str).unwrap_or("");
                let numbers = unbacked_numbers(&claim, ev);
                if !numbers.is_empty() {
                    c.unverified.push(format!(
                        "{wh}: the quoted line{s} repeat{} {repeats} times in {sid}, so the quote cannot show the number {} in the claim. Give that number in a count finding",
                        if qlines.len() > 1 { "" } else { "s" },
                        numbers.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
                    ));
                    continue;
                }
                c.verified.push(format!(
                    "{wh}: {} quoted line{s} found in {sid}, {repeats} identical places (first at line {})",
                    qlines.len(),
                    placements(&qlines, ix)[0]
                ));
                continue;
            }
            c.verified.push(format!("{wh}: {} quoted line{s} found in {sid}, at line {}", qlines.len(), placements(&qlines, ix)[0]));
            continue;
        }
        let bad = missing[0];
        let other: Vec<String> =
            sorted_ids(idx.iter().filter(|(s, o)| **s != sid && quote_in(bad, o)).map(|(s, _)| s.clone()).collect());
        if !other.is_empty() {
            c.unverified.push(format!("{wh}: \"{}\" is in {}, not in {sid}", short(bad, 100), other.join(", ")));
        } else {
            let more = if missing.len() > 1 { format!(" (and {} more of its lines)", missing.len() - 1) } else { String::new() };
            c.unverified.push(format!("{wh}: \"{}\" is not a line of {sid}{more}", short(bad, 100)));
        }
    }
    c
}

// ------------------------------------------------------------------ COMPARE_V1, PLACE_V2

/// `_clean_line`.
fn clean_line(line: &str) -> String {
    let p = pats();
    let mut cand = ws(&p.line_no.sub_empty(line, 1));
    if let Some(inner) = strip_pair(&cand) {
        cand = inner;
    }
    ws(&p.ellipsis.sub_empty(&cand, 0))
}

/// `line_value`: (key, value) of one quoted line.
fn line_value(line: &str) -> (Option<String>, String) {
    let p = pats();
    let text = clean_line(line);
    let t = chars(&text);
    let keys = p.key.find_iter(&t);
    let (key, value) = match keys.last() {
        Some(m) => (m.group(&t, 1), t[m.end..].iter().collect::<String>()),
        None => (None, p.dash.sub_empty(&text, 1)),
    };
    let mut value = py::strip(&value).to_string();
    let vc = chars(&value);
    if vc.len() >= 2 && pair_close(vc[0]) == Some(vc[vc.len() - 1]) {
        value = py::strip(&vc[1..vc.len() - 1].iter().collect::<String>()).to_string();
    }
    (key, value)
}

/// `_side_text`.
fn side_text(side: &str) -> String {
    side.split('\n').filter(|x| !py::strip(x).is_empty()).map(clean_line).collect::<Vec<_>>().join(" / ")
}

/// `comparison_side` (PLACE_V2): (problem, value line).
fn comparison_side(side: &str, sid: &str, idx: &BTreeMap<String, Indexed>) -> (Option<String>, String) {
    let qlines: Vec<String> = side.split('\n').filter(|x| !py::strip(x).is_empty()).map(String::from).collect();
    let ix = &idx[sid];
    for line in &qlines {
        if !quote_in(line, ix) {
            let other: Vec<String> =
                sorted_ids(idx.iter().filter(|(s, o)| *s != sid && quote_in(line, o)).map(|(s, _)| s.clone()).collect());
            if !other.is_empty() {
                return (Some(format!("\"{}\" is in {}, not in {sid}", short(line, 100), other.join(", "))), String::new());
            }
            return (Some(format!("\"{}\" is not a line of {sid}", short(line, 100))), String::new());
        }
    }
    if let Some(wp) = place_problem(&qlines, ix, sid) {
        return (Some(format!("\"{}\" {wp}", short(&side_text(side), 80))), String::new());
    }
    if qlines.len() > 1 {
        let chain = chains_of(&qlines, ix).into_iter().next().unwrap();
        let last = *chain.last().unwrap();
        let parents: HashSet<usize> = ancestors(ix, last.0).into_iter().collect();
        for (q, span) in qlines[..qlines.len() - 1].iter().zip(chain[..chain.len() - 1].iter()) {
            if span.0 != span.1 || !parents.contains(&span.0) {
                return (
                    Some(format!(
                        "the {sid} side has \"{}\" above its value line \"{}\"; only the value's own key line(s) may stand above it",
                        short(&clean_line(q), 50),
                        short(&clean_line(qlines.last().unwrap()), 50)
                    )),
                    String::new(),
                );
            }
        }
    }
    (None, qlines.last().cloned().unwrap_or_default())
}

/// `check_comparison`: (verified?, message, bridge evidence).
fn check_comparison(n: usize, f: &Map<String, Value>, source_ids: &[String], idx: &BTreeMap<String, Indexed>) -> (bool, String, String) {
    let p = pats();
    let wh = format!("finding {n}");
    let shape = format!(
        "{wh}: \"compare\" must be {{\"S1\": \"<one value line of S1>\", \"S3\": \"<one value line of S3>\", \"relation\": \"same\" or \"different\"}}, two files only"
    );
    let Some(cmp) = f.get("compare").and_then(Value::as_object) else { return (false, shape, String::new()) };
    let rel = match cmp.get("relation") {
        Some(Value::String(r)) if r == "same" || r == "different" => r.clone(),
        _ => return (false, shape, String::new()),
    };
    let sides: Vec<&String> = cmp.keys().filter(|k| *k != "relation").collect();
    if sides.len() != 2
        || !sides.iter().all(|k| p.side_id.fullmatch(k))
        || !sides.iter().all(|k| matches!(cmp.get(*k), Some(Value::String(s)) if !py::strip(s).is_empty()))
    {
        return (false, shape, String::new());
    }
    // sorted(sides, key=int(x[1:])): stable, so equal numbers keep their dict order.
    let mut ss: Vec<String> = sides.iter().map(|s| s.to_string()).collect();
    ss.sort_by_key(|s| sid_num(s));
    let (a, b) = (ss[0].clone(), ss[1].clone());
    let wh = format!("finding {n} ({a} vs {b})");
    if a == b {
        return (false, format!("{wh}: compares a file with itself"), String::new());
    }
    for sid in [&a, &b] {
        if !idx.contains_key(sid) {
            return (false, format!("{wh}: {sid} is not an approved source"), String::new());
        }
    }
    let mut src = source_ids.to_vec();
    src.sort_by_key(|s| sid_num(s));
    if src != vec![a.clone(), b.clone()] {
        return (false, format!("{wh}: \"source\" must name the two compared files, \"{a}, {b}\""), String::new());
    }
    let mut values: BTreeMap<String, String> = BTreeMap::new();
    for sid in [&a, &b] {
        let side = cmp[sid.as_str()].as_str().unwrap();
        let (problem, value_line) = comparison_side(side, sid, idx);
        if let Some(pr) = problem {
            return (false, format!("{wh}: {pr}"), String::new());
        }
        values.insert(sid.clone(), value_line);
    }
    let claim = py::get_str_or_empty(f, "claim");
    let others: Vec<String> = sorted_ids(ids_in(&claim).into_iter().filter(|x| *x != a && *x != b).collect());
    if !others.is_empty() {
        return (
            false,
            format!("{wh}: the claim also speaks about {}; a comparison finding describes only its two files", others.join(", ")),
            String::new(),
        );
    }
    let (ka, va) = line_value(&values[&a]);
    let (kb, vb) = line_value(&values[&b]);
    if let (Some(ka), Some(kb)) = (&ka, &kb) {
        if ka != kb && !ka.is_empty() && !kb.is_empty() {
            return (false, format!("{wh}: compares \"{ka}\" in {a} with \"{kb}\" in {b}; compare lines with the same key"), String::new());
        }
    }
    let real = if va == vb { "same" } else { "different" };
    if rel != real {
        if real == "same" {
            return (false, format!("{wh}: says \"different\", but both values are \"{}\"", short(&va, 80)), String::new());
        }
        return (false, format!("{wh}: says \"same\", but {a} has \"{}\" and {b} has \"{}\"", short(&va, 60), short(&vb, 60)), String::new());
    }
    let ev = format!(
        "{a}: {}\n{b}: {}\n({real}: checked by the bridge)",
        side_text(cmp[a.as_str()].as_str().unwrap()),
        side_text(cmp[b.as_str()].as_str().unwrap())
    );
    (true, format!("{wh}: {real} values, checked"), ev)
}

// ------------------------------------------------------------------ CONTRADICTED_V1

pub fn is_contradiction(message: &str) -> bool {
    pats().contradiction.is_match(message)
}

/// `evidence_error`.
pub fn evidence_error(check: &Check, limit: usize) -> Option<String> {
    let mut bad: Vec<String> = check.unverified.iter().filter(|u| is_contradiction(u)).cloned().collect();
    if bad.is_empty() && check.verified.is_empty() {
        bad = if check.unverified.is_empty() {
            vec!["no findings: give at least one finding that quotes or counts an approved file".into()]
        } else {
            check.unverified.clone()
        };
    }
    if bad.is_empty() {
        return None;
    }
    let mut shown = bad.iter().take(limit).cloned().collect::<Vec<_>>().join("; ");
    if bad.len() > limit {
        shown.push_str(&format!("; and {} more", bad.len() - limit));
    }
    Some(format!(
        "HERCULES findings failed the bridge's evidence check (every quoted line must be in the file the finding cites; every count must equal the bridge's recount; every comparison must match the two lines it quotes): {shown}."
    ))
}

/// `set_aside`: {finding number: why} for findings kept but not verified.
pub fn set_aside(check: &Check) -> BTreeMap<u64, String> {
    let mut out = BTreeMap::new();
    for u in &check.unverified {
        if let Some((t, m)) = pats().finding_n.match_start(u) {
            if !is_contradiction(u) {
                out.insert(int_of_digits(&m.group(&t, 1).unwrap()), u.clone());
            }
        }
    }
    out
}

// ------------------------------------------------------------------ the role output contract

/// `_matches_example_type` (org_bridge.py).
pub fn matches_example_type(value: &Value, example: &Value) -> bool {
    match example {
        Value::Bool(_) => value.is_boolean(),
        Value::String(_) => value.is_string(),
        Value::Number(n) if n.is_i64() || n.is_u64() => py::is_int(value),
        Value::Number(_) => value.is_number(),
        Value::Array(ex) => match value {
            Value::Array(v) => ex.first().map(|e0| v.iter().all(|x| matches_example_type(x, e0))).unwrap_or(true),
            _ => false,
        },
        Value::Object(ex) => match value {
            Value::Object(v) => {
                let a: HashSet<&String> = v.keys().collect();
                let b: HashSet<&String> = ex.keys().collect();
                a == b && ex.iter().all(|(k, e)| matches_example_type(&v[k], e))
            }
            _ => false,
        },
        Value::Null => value.is_null(),
    }
}

fn py_list(items: &[String]) -> String {
    format!("[{}]", items.iter().map(|s| py::repr_str(s)).collect::<Vec<_>>().join(", "))
}

/// `_validate_role_output_contract` for an example the bridge put in the task (None: no contract).
/// The example is given as (key, value) pairs in the bridge's dict order, so the first mismatch named is
/// the bridge's.
pub fn validate_contract(parsed: &Value, example: Option<&[(String, Value)]>, source: &str) -> Result<(), String> {
    let Some(o) = parsed.as_object() else { return Err("Output is not a JSON object".into()) };
    let Some(ex) = example else { return Ok(()) };
    let actual: HashSet<&String> = o.keys().collect();
    let expected: HashSet<&String> = ex.iter().map(|(k, _)| k).collect();
    if actual != expected {
        let mut missing: Vec<String> = expected.difference(&actual).map(|s| s.to_string()).collect();
        let mut extra: Vec<String> = actual.difference(&expected).map(|s| s.to_string()).collect();
        missing.sort();
        extra.sort();
        return Err(format!(
            "role/task output contract mismatch; source={source}; missing={}; extra={}",
            py_list(&missing),
            py_list(&extra)
        ));
    }
    for (k, e) in ex {
        if !matches_example_type(&o[k], e) {
            return Err(format!(
                "role/task output type mismatch; source={source}; key={k}; expected_type={}; actual_type={}",
                py::type_name(e),
                py::type_name(&o[k])
            ));
        }
    }
    Ok(())
}

/// `_validate_for_operator` (org_bridge.py).
pub fn validate_for_operator(parsed: &Value) -> Result<(), String> {
    let Some(o) = parsed.as_object() else { return Err("Output is not a JSON object".into()) };
    let Some(Value::String(fs)) = o.get("for_operator") else { return Err("for_operator is missing or not a string".into()) };
    let lines = py::splitlines(fs);
    if !lines.contains(&"For Operator:") {
        return Err("for_operator missing 'For Operator:' line".into());
    }
    let has = |prefix: &str| {
        lines.iter().any(|l| l.starts_with(prefix) && !py::strip(&l[prefix.len()..]).is_empty())
    };
    if !has("Issue:") {
        return Err("for_operator missing valid 'Issue:' line".into());
    }
    if !has("Negative impact:") {
        return Err("for_operator missing valid 'Negative impact:' line".into());
    }
    if !has("Fix:") {
        return Err("for_operator missing valid 'Fix:' line".into());
    }
    Ok(())
}

// ------------------------------------------------------------------ what the tools use

/// The answer contract the bridge puts in the task (one HERCULES_ANSWER_CONTRACT line).
#[derive(Debug, Clone, Default)]
pub struct AnswerContract {
    pub example: Option<Vec<(String, Value)>>,
    pub example_source: String,
    pub for_operator: bool,
    pub evidence: bool,
    /// Source id -> sandbox-relative path of its approved copy ("staged/<sha256>.snapshot").
    pub sources: BTreeMap<String, String>,
}

/// One finding's verdict for evidence.check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub verdict: &'static str,
    pub detail: String,
}

/// evidence.check: the bridge's verdict on one finding, as "verified", "contradicted" or "not checkable".
/// A claim whose total disagrees with its own parts is contradicted (COUNT_CHECK_V1 rejects it).
pub fn check_one(finding: &Value, texts: &BTreeMap<String, String>) -> Verdict {
    let one = Value::Array(vec![finding.clone()]);
    let c = verify_findings(Some(&one), texts);
    let rename = |m: &str| -> String {
        match m.strip_prefix("finding 1") {
            Some(rest) => format!("this finding{rest}"),
            None => m.to_string(),
        }
    };
    let totals = count_mismatches(&serde_json::json!({ "findings": one }));
    if !totals.is_empty() {
        return Verdict { verdict: "contradicted", detail: rename(&totals[0]) };
    }
    if let Some(v) = c.verified.first() {
        return Verdict { verdict: "verified", detail: rename(v) };
    }
    let u = c.unverified.first().cloned().unwrap_or_default();
    let verdict = if is_contradiction(&u) { "contradicted" } else { "not checkable" };
    Verdict { verdict, detail: rename(&u) }
}

/// answer.submit: every reason the bridge would reject this answer, in the bridge's words (empty: the
/// bridge accepts it). `answer` is normalized in place exactly as the bridge does (LIST_SHAPE_V1).
pub fn submit_problems(answer: &mut Value, contract: &AnswerContract, texts: &BTreeMap<String, String>) -> Vec<String> {
    normalize_shape(answer);
    let mut out = Vec::new();
    if !answer.is_object() {
        out.push("HERCULES answer has no JSON object before the report block".to_string());
        return out;
    }
    if let Err(e) = validate_contract(answer, contract.example.as_deref(), &contract.example_source) {
        out.push(format!("HERCULES role/task output contract failed: {e}"));
    } else if contract.for_operator {
        if let Err(e) = validate_for_operator(answer) {
            out.push(format!("HERCULES for_operator output contract failed: {e}"));
        }
    }
    if contract.evidence {
        let check = verify_findings(answer.get("findings"), texts);
        if let Some(e) = evidence_error(&check, 8) {
            out.push(e);
        }
    }
    let miscounted = count_mismatches(answer);
    if !miscounted.is_empty() {
        out.push(format!(
            "HERCULES total does not match its own parts: {}. Counts must be taken with grep -c and added up.",
            miscounted.join("; ")
        ));
    }
    out
}

#[cfg(test)]
mod shared_corpus {
    use super::{sum_mismatches, total_mismatch};
    #[test]
    fn count_check_v3_written_out_sums() {
        // Arena T20 (Oct 9): both forms in one answer; the parts make 17.
        let t20 = "routes 16 work classes in the work_class_routing section to four tier key values: 7 to worker, 5 to engineering, 3 to deep_reasoning, and 2 to operator_only (7 + 5 + 3 + 2 = 16).";
        assert_eq!(sum_mismatches(t20), ["says 16 in total but its parts 7 + 5 + 3 + 2 make 17"]);
        assert_eq!(sum_mismatches("The 16 work classes consist of 7 worker + 5 engineering + 3 deep_reasoning + 2 operator_only, which sum to 16."),
                   ["says 16 in total but its parts 7 + 5 + 3 + 2 make 17"]);
        for ok in ["7 + 5 + 3 + 2 = 17", "2 * 3 + 4 = 10", "10 - 3 + 2 = 9", "1.5 + 2 = 3", "\"2 + 2 = 5\"", "7 + 5 = 13 + 3", "1,000 + 2 = 5", "3 + 4 = 8%",
                   // the independent review's correct sentences (round 1)
                   "1 minute + 30 seconds = 90 seconds", "2 KB + 512 bytes = 2560 bytes", "10 \u{2013} 3 + 2 = 9", "10 minus 3 + 2 = 9",
                   "2 x 3 + 1 = 7 pods", "2 \u{b7} 3 + 4 = 10", "example '2 + 2 = 5' is wrong", "10:30 + 2 = 12:30", "1 000 + 2 = 1 002",
                   "half of 4 + 2 = 4", "\u{663} + \u{664} = 8"] {
            assert!(sum_mismatches(ok).is_empty(), "{ok}");
        }
        // V3 also reads the unit of "worker has 7 classes": four tiers counting classes is no total
        assert_eq!(total_mismatch("Four tiers: worker has 7 classes, engineering has 5 classes, deep_reasoning has 3 classes, operator_only has 2 classes.", ""), None);
        assert_eq!(total_mismatch("3 tests failed: unit has 2 tests, e2e has 2 tests, lint has 1 test", "").as_deref(),
                   Some("says 3 in total but its parts 2 + 2 + 1 make 5"));
    }

    /// The committed corpus run through the runtime must give exactly the results the bridge's own
    /// Python gave (tests/checker/expected_synthetic.json, from reference.py). Cases where Python
    /// raises (the bridge would stop with an error) are listed there and skipped.
    #[test]
    fn runtime_equals_bridge_on_the_synthetic_corpus() {
        let corpus: serde_json::Value = serde_json::from_str(include_str!("../tests/checker/corpus_synthetic.json")).unwrap();
        let want: serde_json::Value = serde_json::from_str(include_str!("../tests/checker/expected_synthetic.json")).unwrap();
        let got = super::run_cases(&corpus);
        let (w, g) = (want["results"].as_array().unwrap(), got["results"].as_array().unwrap());
        assert_eq!(w.len(), g.len());
        let mut checked = 0;
        for (a, b) in w.iter().zip(g) {
            if a["result"].get("python_raised").is_some() {
                continue;
            }
            assert_eq!(a, b, "case {}", a["id"]);
            checked += 1;
        }
        assert!(checked > 1600, "{checked}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn texts(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn quote_count_compare_and_crossfile() {
        let t = texts(&[
            ("S1", "roles:\n  a_v1:\n    fallback: null\n  b_v1:\n    fallback: null\nPUSH FAILED x\nPUSH FAILED x\n"),
            ("S3", "roles:\n  a_v1:\n    fallback: m2\n"),
        ]);
        let f = json!([
            {"claim": "a has no fallback", "evidence": "  a_v1:\n    fallback: null", "source": "S1"},
            {"claim": "fallback is null", "evidence": "fallback: null", "source": "S1"},
            {"claim": "2 lines", "evidence": "", "source": "S1", "count": {"text": "PUSH FAILED", "lines": 3}},
            {"claim": "S1 differs from S3", "evidence": "fallback: null", "source": "S1"},
            {"claim": "they differ", "evidence": "", "source": "S1, S3",
             "compare": {"S1": "a_v1: fallback: null", "S3": "fallback: m2", "relation": "different"}},
            {"claim": "fails", "evidence": "PUSH FAILED x", "source": "S1"},
            {"claim": "fails 2 times", "evidence": "PUSH FAILED x", "source": "S1"},
            {"claim": "made up", "evidence": "provider: cothinker", "source": "S1"},
        ]);
        let c = verify_findings(Some(&f), &t);
        assert_eq!(c.verified.len(), 3, "{c:?}");
        assert!(c.verified[0].starts_with("finding 1 (S1): 2 quoted lines found in S1, at line 2"));
        assert!(c.unverified[0].contains("fits 2 places in S1 (lines 3, 5)"), "{c:?}");
        assert!(c.unverified[1].ends_with("the bridge counts 2"));
        assert!(c.unverified[2].contains("the claim also speaks about S3"));
        assert!(c.verified[1].starts_with("finding 5 (S1 vs S3): different values"));
        assert!(c.verified[2].contains("2 identical places"));
        assert!(c.unverified[3].contains("cannot show the number 2"));
        assert!(c.unverified[4].contains("is not a line of S1"));
        let err = evidence_error(&c, 8).unwrap();
        assert!(err.contains("fits 2 places") == false && err.contains("counts 2") && err.contains("not a line of S1"));
        assert_eq!(set_aside(&c).keys().copied().collect::<Vec<_>>(), vec![2, 4, 7]);
    }

    #[test]
    fn totals() {
        assert_eq!(
            total_mismatch("18 work classes across 4 tiers: worker has 7, engineering has 5, deep_reasoning has 3, and operator_only has 2", ""),
            Some("says 18 in total but its parts 7 + 5 + 3 + 2 make 17".into())
        );
        assert_eq!(total_mismatch("17 work classes across 4 tiers: worker has 7, engineering has 5, deep_reasoning has 3, and operator_only has 2", ""), None);
        // COUNT_CHECK_V2: the three false positives of the Oct 4-5 benches pass, the real catches still fail.
        assert_eq!(total_mismatch("Four tiers appear: worker (7 classes), engineering (5 classes), deep_reasoning (3 classes), operator_only (2 classes).", ""), None);
        assert_eq!(total_mismatch("The mapping found is: deep_reasoning (3 work classes), engineering (5 work classes), worker (7 work classes), and operator_only (2 work classes).",
            "The file S1 defines a 'tiers' block mapping three tiers to specific models and a 'work_class_routing' block mapping work classes to tier names."), None);
        assert_eq!(total_mismatch("Per tier: worker=7, engineering=5, deep_reasoning=3.",
            "The remaining 2 work classes (production_mutation, production_promotion) are mapped to operator_only, which is defined in escalation but not in the tiers block."), None);
        assert_eq!(total_mismatch("S1 assigns 16 work classes in work_class_routing: 7 to worker, 5 to engineering, 3 to deep_reasoning, and 2 to operator_only.", ""),
            Some("says 16 in total but its parts 7 + 5 + 3 + 2 make 17".into()));
        assert_eq!(total_mismatch("The model-routing.yaml file assigns 16 work classes across four tiers: 'worker' (7 classes), 'engineering' (5 classes), 'deep_reasoning' (3 classes), and 'operator_only' (2 classes).", ""),
            Some("says 16 in total but its parts 7 + 5 + 3 + 2 make 17".into()));
        assert_eq!(total_mismatch("Counts per tier: worker = 7, engineering = 5, deep_reasoning = 3, operator_only = 2.",
            "The work_class_routing block (lines 43-60) maps 16 work classes to 4 distinct tier values."),
            Some("says 16 in total but its parts 7 + 5 + 3 + 2 make 17".into()));
        // Review of 3.3: a lone total equal to the number of parts is still checked when it counts the same
        // things as the parts, or the parts name no unit; two copies of it: only one is set aside.
        assert_eq!(total_mismatch("3 tests failed: unit (2 tests), e2e (2 tests), lint (1 test)", ""),
            Some("says 3 in total but its parts 2 + 2 + 1 make 5".into()));
        assert_eq!(total_mismatch("2 failures: unit has 1, integration has 2", ""), Some("says 2 in total but its parts 1 + 2 make 3".into()));
        assert_eq!(total_mismatch("4 work classes across 4 tiers: worker has 7, engineering has 5, deep_reasoning has 3, and operator_only has 2", ""),
            Some("says 4 in total but its parts 7 + 5 + 3 + 2 make 17".into()));
        assert_eq!(total_mismatch("Three files: a (2 lines), b (1 line), c (4 lines)", ""), None);
        assert_eq!(total_mismatch("Counts: alpha has 3, beta has 4.", "Section 2 lists 2 tiers and 40 lines."), None);
    }

    #[test]
    fn contract() {
        let ex: Vec<(String, Value)> = [("summary", json!("")), ("findings", json!([])), ("uncertainties", json!([])), ("for_operator", json!(""))]
            .into_iter().map(|(k, v)| (k.to_string(), v)).collect();
        let mut a = json!({"summary": "s", "findings": [], "uncertainties": "x", "for_operator": "For Operator:\nIssue: a\nNegative impact: b\nFix: c"});
        let c = AnswerContract { example: Some(ex), example_source: "role_default".into(), for_operator: true, evidence: false, sources: BTreeMap::new() };
        assert!(submit_problems(&mut a, &c, &BTreeMap::new()).is_empty());
        assert_eq!(a["uncertainties"], json!(["x"]));
        let mut b = json!({"summary": "s", "findings": []});
        let p = submit_problems(&mut b, &c, &BTreeMap::new());
        assert_eq!(p, vec!["HERCULES role/task output contract failed: role/task output contract mismatch; source=role_default; missing=['for_operator', 'uncertainties']; extra=[]".to_string()]);
    }
}

// ------------------------------------------------------------------ shared corpus runner

fn texts_of(case: &Value, doc: &Value) -> BTreeMap<String, String> {
    case.get("texts")
        .or_else(|| doc.get("texts"))
        .and_then(Value::as_object)
        .map(|o| o.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string())).collect())
        .unwrap_or_default()
}

/// Parse the HERCULES_ANSWER_CONTRACT object (also used by the corpus).
pub fn contract_from(v: &Value) -> Result<AnswerContract, String> {
    let o = v.as_object().ok_or("the answer contract must be a JSON object")?;
    let example = match o.get("example") {
        None | Some(Value::Null) => None,
        Some(Value::Array(pairs)) => {
            let mut out = Vec::new();
            for p in pairs {
                match p.as_array().map(Vec::as_slice) {
                    Some([Value::String(k), v]) => out.push((k.clone(), v.clone())),
                    _ => return Err("example must be a list of [key, value] pairs".into()),
                }
            }
            Some(out)
        }
        Some(_) => return Err("example must be a list of [key, value] pairs".into()),
    };
    let sources = match o.get("sources") {
        None | Some(Value::Null) => BTreeMap::new(),
        Some(Value::Object(m)) => {
            let mut out = BTreeMap::new();
            for (k, v) in m {
                let p = v.as_str().ok_or("sources values must be strings")?;
                out.insert(k.clone(), p.to_string());
            }
            out
        }
        Some(_) => return Err("sources must be an object".into()),
    };
    Ok(AnswerContract {
        example,
        example_source: o.get("example_source").and_then(Value::as_str).unwrap_or("task").to_string(),
        for_operator: o.get("for_operator") == Some(&Value::Bool(true)),
        evidence: o.get("evidence") == Some(&Value::Bool(true)),
        sources,
    })
}

/// Run every case of a shared-corpus file and return the results in the corpus's own format.
pub fn run_cases(doc: &Value) -> Value {
    let mut out = Vec::new();
    for case in doc.get("cases").and_then(Value::as_array).cloned().unwrap_or_default() {
        let texts = texts_of(&case, doc);
        let kind = case.get("kind").and_then(Value::as_str).unwrap_or("");
        let r = match kind {
            "verify" => {
                let c = verify_findings(case.get("findings"), &texts);
                serde_json::json!({
                    "verified": c.verified, "unverified": c.unverified,
                    "set_evidence": c.set_evidence.iter().map(|(k, v)| (k.to_string(), Value::String(v.clone()))).collect::<Map<String, Value>>(),
                    "evidence_error": evidence_error(&c, 8),
                    "set_aside": set_aside(&c).iter().map(|(k, v)| (k.to_string(), Value::String(v.clone()))).collect::<Map<String, Value>>(),
                })
            }
            "one" => {
                let v = check_one(case.get("finding").unwrap_or(&Value::Null), &texts);
                serde_json::json!({"verdict": v.verdict, "detail": v.detail})
            }
            "submit" => match contract_from(case.get("contract").unwrap_or(&Value::Null)) {
                Ok(contract) => {
                    let mut a = case.get("answer").cloned().unwrap_or(Value::Null);
                    let p = submit_problems(&mut a, &contract, &texts);
                    serde_json::json!({"problems": p, "answer": a})
                }
                Err(e) => serde_json::json!({"contract_error": e}),
            },
            "total" => serde_json::json!({"result": total_mismatch(
                case.get("sentence").and_then(Value::as_str).unwrap_or(""),
                case.get("previous").and_then(Value::as_str).unwrap_or(""))}),
            "counts" => serde_json::json!({"result": count_mismatches(case.get("parsed").unwrap_or(&Value::Null))}),
            other => serde_json::json!({"error": format!("unknown kind {other}")}),
        };
        out.push(serde_json::json!({"id": case.get("id").cloned().unwrap_or(Value::Null), "result": r}));
    }
    serde_json::json!({"results": out})
}
