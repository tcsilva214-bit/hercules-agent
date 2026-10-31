//! Gate 10: a unified diff for the write lane's changeset, so a proposal can be reviewed without other tools.
//! Myers' O(ND) line diff, with a size guard: past it the file is shown as a whole replacement.

const MAX_LINES: usize = 20_000;
const MAX_EDIT_DISTANCE: usize = 4_000;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Op {
    Keep,
    Del,
    Add,
}

fn split_lines(b: &[u8]) -> Vec<&[u8]> {
    if b.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<&[u8]> = b.split_inclusive(|c| *c == b'\n').collect();
    if out.last().map(|l| l.is_empty()).unwrap_or(false) {
        out.pop();
    }
    out
}

/// The edit script turning `a` into `b`, or None when the guard is hit.
fn myers(a: &[&[u8]], b: &[&[u8]]) -> Option<Vec<Op>> {
    let (n, m) = (a.len() as isize, b.len() as isize);
    let max = (n + m) as usize;
    let off = max as isize + 1;
    let mut v = vec![0isize; 2 * max + 3];
    let mut trace: Vec<Vec<isize>> = Vec::new();
    let mut found = None;
    for d in 0..=max {
        if d > MAX_EDIT_DISTANCE {
            return None;
        }
        trace.push(v.clone());
        let d = d as isize;
        let mut k = -d;
        while k <= d {
            let i = (k + off) as usize;
            let mut x = if k == -d || (k != d && v[i - 1] < v[i + 1]) { v[i + 1] } else { v[i - 1] + 1 };
            let mut y = x - k;
            while x < n && y < m && a[x as usize] == b[y as usize] {
                x += 1;
                y += 1;
            }
            v[i] = x;
            if x >= n && y >= m {
                found = Some(d);
                break;
            }
            k += 2;
        }
        if found.is_some() {
            break;
        }
    }
    let dmax = found?;
    // Backtrack.
    let mut ops = Vec::new();
    let (mut x, mut y) = (n, m);
    for d in (0..=dmax).rev() {
        let v = &trace[d as usize];
        let k = x - y;
        let i = (k + off) as usize;
        let prev_k = if k == -d || (k != d && v[i - 1] < v[i + 1]) { k + 1 } else { k - 1 };
        let prev_x = v[(prev_k + off) as usize];
        let prev_y = prev_x - prev_k;
        while x > prev_x && y > prev_y {
            ops.push(Op::Keep);
            x -= 1;
            y -= 1;
        }
        if d > 0 {
            if x == prev_x {
                ops.push(Op::Add);
                y -= 1;
            } else {
                ops.push(Op::Del);
                x -= 1;
            }
        }
    }
    while x > 0 && y > 0 {
        ops.push(Op::Keep);
        x -= 1;
        y -= 1;
    }
    ops.reverse();
    Some(ops)
}

fn push_line(out: &mut String, tag: char, line: &[u8]) {
    out.push(tag);
    let text = String::from_utf8_lossy(line);
    out.push_str(&text);
    if !text.ends_with('\n') {
        out.push_str("\n\\ No newline at end of file\n");
    }
}

/// A unified diff of `old` (None = the file does not exist yet) against `new`, labelled `a/<label>`, `b/<label>`.
pub fn unified(old: Option<&[u8]>, new: &[u8], label: &str, context: usize) -> String {
    let mut out = String::new();
    out.push_str(&format!("--- {}\n+++ b/{label}\n", if old.is_some() { format!("a/{label}") } else { "/dev/null".into() }));
    let old_b = old.unwrap_or(&[]);
    if std::str::from_utf8(old_b).is_err() {
        out.push_str("Binary base file differs (not UTF-8); the proposal replaces it with text\n");
        return out;
    }
    let (a, b) = (split_lines(old_b), split_lines(new));
    let ops = if a.len() > MAX_LINES || b.len() > MAX_LINES { None } else { myers(&a, &b) };
    let ops = ops.unwrap_or_else(|| {
        let mut v = vec![Op::Del; a.len()];
        v.extend(std::iter::repeat_n(Op::Add, b.len()));
        v
    });
    // Group into hunks with `context` lines around each change.
    let mut idx = Vec::with_capacity(ops.len()); // (op, a index, b index)
    let (mut i, mut j) = (0usize, 0usize);
    for op in &ops {
        idx.push((*op, i, j));
        match op {
            Op::Keep => {
                i += 1;
                j += 1;
            }
            Op::Del => i += 1,
            Op::Add => j += 1,
        }
    }
    let changed: Vec<usize> = idx.iter().enumerate().filter(|(_, (op, _, _))| *op != Op::Keep).map(|(k, _)| k).collect();
    if changed.is_empty() {
        return out;
    }
    let mut k = 0;
    while k < changed.len() {
        let start = changed[k].saturating_sub(context);
        let mut end = (changed[k] + context + 1).min(idx.len());
        while k + 1 < changed.len() && changed[k + 1] <= end + context {
            k += 1;
            end = (changed[k] + context + 1).min(idx.len());
        }
        let slice = &idx[start..end];
        let a_start = slice.first().map(|s| s.1).unwrap_or(0);
        let b_start = slice.first().map(|s| s.2).unwrap_or(0);
        let a_len = slice.iter().filter(|s| s.0 != Op::Add).count();
        let b_len = slice.iter().filter(|s| s.0 != Op::Del).count();
        let range = |s: usize, l: usize| if l == 0 { format!("{s},0") } else if l == 1 { format!("{}", s + 1) } else { format!("{},{l}", s + 1) };
        out.push_str(&format!("@@ -{} +{} @@\n", range(a_start, a_len), range(b_start, b_len)));
        for (op, ai, bj) in slice {
            match op {
                Op::Keep => push_line(&mut out, ' ', a[*ai]),
                Op::Del => push_line(&mut out, '-', a[*ai]),
                Op::Add => push_line(&mut out, '+', b[*bj]),
            }
        }
        k += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Apply a unified diff produced here to `old`, to check it round-trips (lines keep their own endings).
    fn patch(old: &str, diff: &str) -> String {
        let a: Vec<&str> = old.split_inclusive('\n').collect();
        let d: Vec<&str> = diff.split_inclusive('\n').skip(2).collect();
        let mut out = String::new();
        let mut pos = 0usize;
        let mut k = 0usize;
        while k < d.len() {
            let h = d[k];
            assert!(h.starts_with("@@ -"), "{h}");
            let spec = h[4..].split(' ').next().unwrap();
            let start: usize = spec.split(',').next().unwrap().parse().unwrap();
            let a_start = if spec.ends_with(",0") { start } else { start - 1 };
            while pos < a_start {
                out.push_str(a[pos]);
                pos += 1;
            }
            k += 1;
            while k < d.len() && !d[k].starts_with("@@") {
                let l = d[k];
                let nonl = d.get(k + 1).map(|n| n.starts_with("\\ No newline")).unwrap_or(false);
                let body = if nonl { l[1..].strip_suffix('\n').unwrap_or(&l[1..]) } else { &l[1..] };
                match &l[..1] {
                    " " => {
                        out.push_str(body);
                        pos += 1;
                    }
                    "-" => pos += 1,
                    "+" => out.push_str(body),
                    _ => panic!("bad line {l:?}"),
                }
                k += if nonl { 2 } else { 1 };
            }
        }
        while pos < a.len() {
            out.push_str(a[pos]);
            pos += 1;
        }
        out
    }

    #[test]
    fn round_trips() {
        let cases = [
            ("", "a\nb\n"),
            ("a\nb\n", ""),
            ("a\nb\nc\n", "a\nB\nc\n"),
            ("a\nb\nc", "a\nb\nc\n"),
            ("a\nb\nc\n", "a\nb\nc"),
            ("1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n", "1\nX\n3\n4\n5\n6\n7\n8\n9\n10\nY\n12\n"),
            ("x\r\ny\r\n", "x\r\nz\r\n"),
            ("same\n", "same\n"),
        ];
        for (old, new) in cases {
            let d = unified(Some(old.as_bytes()), new.as_bytes(), "f", 3);
            assert_eq!(patch(old, &d), new, "old={old:?} new={new:?}\n{d}");
        }
        assert_eq!(unified(Some(b"same\n"), b"same\n", "f", 3), "--- a/f\n+++ b/f\n");
        assert!(unified(None, b"hi\n", "n", 3).starts_with("--- /dev/null\n+++ b/n\n@@ -0,0 +1 @@\n+hi\n"));
        assert!(unified(Some(&[0xff, 0xfe]), b"x\n", "bin", 3).contains("Binary base file"));
        // Two far-apart changes give two hunks; near ones merge.
        let old: String = (1..=30).map(|i| format!("{i}\n")).collect();
        let new: String = (1..=30).map(|i| match i { 2 => "two\n".to_string(), 28 => "twenty-eight\n".to_string(), _ => format!("{i}\n") }).collect();
        assert_eq!(unified(Some(old.as_bytes()), new.as_bytes(), "f", 3).matches("@@ -").count(), 2);
    }
}
