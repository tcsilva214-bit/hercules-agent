//! Build 3: a small backtracking regular-expression engine with Python `re` semantics, for the
//! handful of patterns the bridge's finding checker uses (checker.rs). It matches the way Python's
//! sre does: leftmost match, alternatives in order, greedy or lazy repeats with backtracking,
//! fixed-width lookbehind, and Python's Unicode `\w`, `\d`, `\s`, `\b` and IGNORECASE. Only the
//! syntax those patterns need is supported; anything else is a compile error (caught by tests).

use super::{fold_eq, is_digit, is_space, is_word};

#[derive(Clone, Copy, Debug, Default)]
pub struct Flags {
    pub ignorecase: bool,
    pub multiline: bool,
}

pub const I: Flags = Flags { ignorecase: true, multiline: false };
pub const NONE: Flags = Flags { ignorecase: false, multiline: false };

#[derive(Debug, Clone)]
enum Item {
    Range(char, char),
    Word(bool),
    Digit(bool),
    Space(bool),
}

#[derive(Debug, Clone)]
enum Node {
    Char(char),
    Class(Vec<Item>, bool),
    Start,
    End,
    WordB(bool),
    Group(Box<Node>, Option<usize>),
    Look { node: Box<Node>, ahead: bool, neg: bool, width: usize },
    Alt(Vec<Node>),
    Seq(Vec<Node>),
    Repeat { node: Box<Node>, min: usize, max: Option<usize>, greedy: bool },
}

#[derive(Debug, Clone)]
pub struct Regex {
    root: Node,
    groups: usize,
    flags: Flags,
}

/// One match: spans in characters (code points), group 0 is the whole match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    pub start: usize,
    pub end: usize,
    pub groups: Vec<Option<(usize, usize)>>,
}

impl Match {
    pub fn group<'a>(&self, chars: &'a [char], i: usize) -> Option<String> {
        if i == 0 {
            return Some(chars[self.start..self.end].iter().collect());
        }
        self.groups.get(i - 1).copied().flatten().map(|(a, b)| chars[a..b].iter().collect())
    }
}

struct Parser<'a> {
    p: Vec<char>,
    i: usize,
    groups: usize,
    _src: &'a str,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<char> {
        self.p.get(self.i).copied()
    }
    fn eat(&mut self, c: char) -> bool {
        if self.peek() == Some(c) {
            self.i += 1;
            true
        } else {
            false
        }
    }
    fn alt(&mut self) -> Result<Node, String> {
        let mut alts = vec![self.seq()?];
        while self.eat('|') {
            alts.push(self.seq()?);
        }
        Ok(if alts.len() == 1 { alts.pop().unwrap() } else { Node::Alt(alts) })
    }
    fn seq(&mut self) -> Result<Node, String> {
        let mut items = Vec::new();
        while let Some(c) = self.peek() {
            if c == '|' || c == ')' {
                break;
            }
            let atom = self.atom()?;
            let atom = self.quant(atom)?;
            items.push(atom);
        }
        Ok(Node::Seq(items))
    }
    fn hex(&mut self, n: usize) -> Result<char, String> {
        let s: String = self.p.get(self.i..self.i + n).ok_or("short escape")?.iter().collect();
        self.i += n;
        let v = u32::from_str_radix(&s, 16).map_err(|e| e.to_string())?;
        char::from_u32(v).ok_or_else(|| "bad escape".to_string())
    }
    fn escape(&mut self) -> Result<Result<char, Item>, String> {
        let c = self.peek().ok_or("trailing backslash")?;
        self.i += 1;
        Ok(match c {
            'd' => Err(Item::Digit(true)),
            'D' => Err(Item::Digit(false)),
            'w' => Err(Item::Word(true)),
            'W' => Err(Item::Word(false)),
            's' => Err(Item::Space(true)),
            'S' => Err(Item::Space(false)),
            'x' => Ok(self.hex(2)?),
            'u' => Ok(self.hex(4)?),
            'n' => Ok('\n'),
            't' => Ok('\t'),
            'r' => Ok('\r'),
            c if !c.is_ascii_alphanumeric() => Ok(c),
            c => return Err(format!("unsupported escape \\{c}")),
        })
    }
    fn atom(&mut self) -> Result<Node, String> {
        let c = self.peek().ok_or("unexpected end")?;
        self.i += 1;
        Ok(match c {
            '^' => Node::Start,
            '$' => Node::End,
            '.' => return Err("'.' is not supported".into()),
            '(' => {
                if self.eat('?') {
                    if self.eat(':') {
                        let n = self.alt()?;
                        self.close()?;
                        Node::Group(Box::new(n), None)
                    } else if self.eat('=') || self.eat('!') {
                        let neg = self.p[self.i - 1] == '!';
                        let n = self.alt()?;
                        self.close()?;
                        Node::Look { node: Box::new(n), ahead: true, neg, width: 0 }
                    } else if self.eat('<') {
                        let neg = if self.eat('!') {
                            true
                        } else if self.eat('=') {
                            false
                        } else {
                            return Err("bad lookbehind".into());
                        };
                        let n = self.alt()?;
                        self.close()?;
                        let width = fixed_width(&n).ok_or("lookbehind requires fixed width")?;
                        Node::Look { node: Box::new(n), ahead: false, neg, width }
                    } else {
                        return Err("unsupported group".into());
                    }
                } else {
                    self.groups += 1;
                    let idx = self.groups;
                    let n = self.alt()?;
                    self.close()?;
                    Node::Group(Box::new(n), Some(idx))
                }
            }
            '[' => self.class()?,
            '\\' => {
                if self.peek() == Some('b') {
                    self.i += 1;
                    Node::WordB(true)
                } else if self.peek() == Some('B') {
                    self.i += 1;
                    Node::WordB(false)
                } else {
                    match self.escape()? {
                        Ok(c) => Node::Char(c),
                        Err(item) => Node::Class(vec![item], false),
                    }
                }
            }
            '*' | '+' | '?' | '{' => return Err(format!("nothing to repeat at {}", self.i)),
            c => Node::Char(c),
        })
    }
    fn close(&mut self) -> Result<(), String> {
        if self.eat(')') {
            Ok(())
        } else {
            Err("missing )".into())
        }
    }
    fn class(&mut self) -> Result<Node, String> {
        let neg = self.eat('^');
        let mut items = Vec::new();
        let mut first = true;
        loop {
            let c = self.peek().ok_or("unterminated class")?;
            if c == ']' && !first {
                self.i += 1;
                break;
            }
            first = false;
            self.i += 1;
            let lo = if c == '\\' {
                match self.escape()? {
                    Ok(c) => c,
                    Err(item) => {
                        items.push(item);
                        continue;
                    }
                }
            } else {
                c
            };
            if self.peek() == Some('-') && self.p.get(self.i + 1).map(|&x| x != ']').unwrap_or(false) {
                self.i += 1;
                let h = self.peek().ok_or("bad range")?;
                self.i += 1;
                let hi = if h == '\\' {
                    match self.escape()? {
                        Ok(c) => c,
                        Err(_) => return Err("bad range".into()),
                    }
                } else {
                    h
                };
                items.push(Item::Range(lo, hi));
            } else {
                items.push(Item::Range(lo, lo));
            }
        }
        Ok(Node::Class(items, neg))
    }
    fn quant(&mut self, atom: Node) -> Result<Node, String> {
        let (min, max) = match self.peek() {
            Some('*') => {
                self.i += 1;
                (0, None)
            }
            Some('+') => {
                self.i += 1;
                (1, None)
            }
            Some('?') => {
                self.i += 1;
                (0, Some(1))
            }
            Some('{') => {
                let save = self.i;
                self.i += 1;
                let mut a = String::new();
                while let Some(c) = self.peek().filter(|c| c.is_ascii_digit()) {
                    a.push(c);
                    self.i += 1;
                }
                let (min, max) = if self.eat(',') {
                    let mut b = String::new();
                    while let Some(c) = self.peek().filter(|c| c.is_ascii_digit()) {
                        b.push(c);
                        self.i += 1;
                    }
                    (a.parse().unwrap_or(0), if b.is_empty() { None } else { Some(b.parse().map_err(|_| "bad count")?) })
                } else {
                    let n: usize = a.parse().map_err(|_| "bad count")?;
                    (n, Some(n))
                };
                if !self.eat('}') {
                    self.i = save;
                    return Err("bad repeat".into());
                }
                (min, max)
            }
            _ => return Ok(atom),
        };
        let greedy = !self.eat('?');
        Ok(Node::Repeat { node: Box::new(atom), min, max, greedy })
    }
}

fn fixed_width(n: &Node) -> Option<usize> {
    match n {
        Node::Char(_) | Node::Class(..) => Some(1),
        Node::Start | Node::End | Node::WordB(_) | Node::Look { .. } => Some(0),
        Node::Group(n, _) => fixed_width(n),
        Node::Seq(v) => v.iter().map(fixed_width).sum(),
        Node::Alt(v) => {
            let w: Vec<_> = v.iter().map(fixed_width).collect();
            let first = w.first().copied().flatten()?;
            if w.iter().all(|x| *x == Some(first)) {
                Some(first)
            } else {
                None
            }
        }
        Node::Repeat { node, min, max, .. } => {
            if Some(*min) == *max {
                Some(fixed_width(node)? * min)
            } else {
                None
            }
        }
    }
}

type Caps = Vec<Option<(usize, usize)>>;

impl Regex {
    pub fn new(pattern: &str, flags: Flags) -> Result<Regex, String> {
        let mut p = Parser { p: pattern.chars().collect(), i: 0, groups: 0, _src: pattern };
        let root = p.alt()?;
        if p.i != p.p.len() {
            return Err(format!("unbalanced pattern at {}", p.i));
        }
        Ok(Regex { root, groups: p.groups, flags })
    }

    /// Compile a pattern that is known to be valid (the checker's own constants).
    pub fn must(pattern: &str, flags: Flags) -> Regex {
        Regex::new(pattern, flags).unwrap_or_else(|e| panic!("bad built-in pattern {pattern}: {e}"))
    }

    fn class_has(&self, items: &[Item], c: char) -> bool {
        items.iter().any(|it| match it {
            Item::Range(a, b) => {
                (*a <= c && c <= *b)
                    || (self.flags.ignorecase
                        && (*a..=*b).any(|p| p.is_ascii_alphabetic() && fold_eq(p, c)))
            }
            Item::Word(pos) => is_word(c) == *pos,
            Item::Digit(pos) => is_digit(c) == *pos,
            Item::Space(pos) => is_space(c) == *pos,
        })
    }

    fn mt(&self, n: &Node, t: &[char], pos: usize, caps: &mut Caps, k: &mut dyn FnMut(usize, &mut Caps) -> bool) -> bool {
        match n {
            Node::Char(p) => {
                if pos < t.len() && (t[pos] == *p || (self.flags.ignorecase && p.is_ascii_alphabetic() && fold_eq(*p, t[pos]))) {
                    k(pos + 1, caps)
                } else {
                    false
                }
            }
            Node::Class(items, neg) => {
                if pos < t.len() && self.class_has(items, t[pos]) != *neg {
                    k(pos + 1, caps)
                } else {
                    false
                }
            }
            Node::Start => {
                let ok = pos == 0 || (self.flags.multiline && t[pos - 1] == '\n');
                ok && k(pos, caps)
            }
            Node::End => {
                let ok = pos == t.len()
                    || (t[pos] == '\n' && (self.flags.multiline || pos + 1 == t.len()));
                ok && k(pos, caps)
            }
            Node::WordB(want) => {
                let before = pos > 0 && is_word(t[pos - 1]);
                let after = pos < t.len() && is_word(t[pos]);
                ((before != after) == *want) && k(pos, caps)
            }
            Node::Group(inner, idx) => match idx {
                None => self.mt(inner, t, pos, caps, k),
                Some(i) => {
                    let i = *i - 1;
                    self.mt(inner, t, pos, caps, &mut |e, caps: &mut Caps| {
                        let old = caps[i];
                        caps[i] = Some((pos, e));
                        if k(e, caps) {
                            true
                        } else {
                            caps[i] = old;
                            false
                        }
                    })
                }
            },
            Node::Look { node, ahead, neg, width } => {
                let mut scratch = caps.clone();
                let found = if *ahead {
                    self.mt(node, t, pos, &mut scratch, &mut |_, _| true)
                } else if pos >= *width {
                    let start = pos - *width;
                    self.mt(node, t, start, &mut scratch, &mut |e, _| e == pos)
                } else {
                    false
                };
                if found != *neg {
                    k(pos, caps)
                } else {
                    false
                }
            }
            Node::Alt(alts) => {
                for a in alts {
                    if self.mt(a, t, pos, caps, k) {
                        return true;
                    }
                }
                false
            }
            Node::Seq(items) => self.seq(items, t, pos, caps, k),
            Node::Repeat { node, min, max, greedy } => self.rep(node, *min, *max, *greedy, 0, t, pos, caps, k),
        }
    }

    fn seq(&self, items: &[Node], t: &[char], pos: usize, caps: &mut Caps, k: &mut dyn FnMut(usize, &mut Caps) -> bool) -> bool {
        match items.split_first() {
            None => k(pos, caps),
            Some((first, rest)) => self.mt(first, t, pos, caps, &mut |e, caps: &mut Caps| self.seq(rest, t, e, caps, k)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn rep(
        &self,
        node: &Node,
        min: usize,
        max: Option<usize>,
        greedy: bool,
        count: usize,
        t: &[char],
        pos: usize,
        caps: &mut Caps,
        k: &mut dyn FnMut(usize, &mut Caps) -> bool,
    ) -> bool {
        let can_more = max.map(|m| count < m).unwrap_or(true);
        let more = |caps: &mut Caps, k: &mut dyn FnMut(usize, &mut Caps) -> bool| -> bool {
            can_more
                && self.mt(node, t, pos, caps, &mut |e, caps: &mut Caps| {
                    if e == pos && count >= min {
                        return false; // an empty iteration cannot make progress
                    }
                    self.rep(node, min, max, greedy, count + 1, t, e, caps, k)
                })
        };
        if greedy {
            if more(caps, k) {
                return true;
            }
            count >= min && k(pos, caps)
        } else {
            if count >= min && k(pos, caps) {
                return true;
            }
            more(caps, k)
        }
    }

    pub fn match_at(&self, t: &[char], pos: usize, full: bool) -> Option<Match> {
        let mut caps: Caps = vec![None; self.groups];
        let mut out: Option<Match> = None;
        let len = t.len();
        self.mt(&self.root, t, pos, &mut caps, &mut |e, caps: &mut Caps| {
            if full && e != len {
                return false;
            }
            out = Some(Match { start: pos, end: e, groups: caps.clone() });
            true
        });
        out
    }

    /// `re.search` from character position `start`.
    pub fn search_from(&self, t: &[char], start: usize) -> Option<Match> {
        (start..=t.len()).find_map(|s| self.match_at(t, s, false))
    }

    /// `re.match` (anchored at the start).
    pub fn match_start(&self, s: &str) -> Option<(Vec<char>, Match)> {
        let t: Vec<char> = s.chars().collect();
        let m = self.match_at(&t, 0, false)?;
        Some((t, m))
    }

    pub fn fullmatch(&self, s: &str) -> bool {
        let t: Vec<char> = s.chars().collect();
        self.match_at(&t, 0, true).is_some()
    }

    pub fn is_match(&self, s: &str) -> bool {
        let t: Vec<char> = s.chars().collect();
        self.search_from(&t, 0).is_some()
    }

    /// `re.finditer` over a char slice.
    pub fn find_iter(&self, t: &[char]) -> Vec<Match> {
        let mut out = Vec::new();
        let mut pos = 0;
        let mut last_end: Option<usize> = None;
        while pos <= t.len() {
            let Some(m) = self.search_from(t, pos) else { break };
            if m.start == m.end && last_end == Some(m.end) {
                // Python skips an empty match right after the previous match.
                pos = m.end + 1;
                continue;
            }
            pos = if m.end == m.start { m.end + 1 } else { m.end };
            last_end = Some(m.end);
            out.push(m);
        }
        out
    }

    /// `re.findall` for a pattern with at most one group: the group's text (or the whole match).
    pub fn findall(&self, s: &str) -> Vec<String> {
        let t: Vec<char> = s.chars().collect();
        self.find_iter(&t)
            .iter()
            .map(|m| if self.groups == 0 { m.group(&t, 0).unwrap() } else { m.group(&t, 1).unwrap_or_default() })
            .collect()
    }

    /// `re.sub(pattern, "", s, count=count)` (count 0 = all). Only an empty replacement is needed.
    pub fn sub_empty(&self, s: &str, count: usize) -> String {
        let t: Vec<char> = s.chars().collect();
        let mut out = String::new();
        let mut last = 0;
        for (n, m) in self.find_iter(&t).into_iter().enumerate() {
            if count > 0 && n >= count {
                break;
            }
            out.extend(&t[last..m.start]);
            last = m.end;
        }
        out.extend(&t[last..]);
        out
    }

    /// `re.split(pattern, s)` for a pattern without groups.
    pub fn split(&self, s: &str) -> Vec<String> {
        let t: Vec<char> = s.chars().collect();
        let mut out = Vec::new();
        let mut last = 0;
        for m in self.find_iter(&t) {
            out.push(t[last..m.start].iter().collect());
            last = m.end;
        }
        out.push(t[last..].iter().collect());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spans(p: &str, f: Flags, s: &str) -> Vec<(usize, usize)> {
        let t: Vec<char> = s.chars().collect();
        Regex::must(p, f).find_iter(&t).iter().map(|m| (m.start, m.end)).collect()
    }

    #[test]
    fn basics() {
        assert_eq!(spans(r"\b\d+\b", NONE, "a 12 b3 45"), vec![(2, 4), (8, 10)]);
        assert_eq!(spans(r"(?<![A-Za-z0-9_])S(\d{1,2})(?![0-9])", NONE, "S1, xS2, S12 S123"), vec![(0, 2), (9, 12)]);
        assert!(Regex::must(r"S\d{1,2}", NONE).fullmatch("S12"));
        assert!(!Regex::must(r"S\d{1,2}", NONE).fullmatch("S123"));
        assert_eq!(Regex::must(r"^-\s+", NONE).sub_empty("- a - b", 0), "a - b");
        assert_eq!(Regex::must(r"(?<=[.;!?])\s+|\n+", NONE).split("A. B\n\nC"), vec!["A.", "B", "C"]);
        assert_eq!(spans(r"seven|seventeen", I, "SEVENTEEN"), vec![(0, 5)]);
        assert_eq!(spans(r"a+?b", NONE, "aaab"), vec![(0, 4)]);
    }
}
