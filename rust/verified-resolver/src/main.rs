//! CPU-side version-selection kernel. PEP 440/508, target-wheel admission,
//! authoritative PEP 517 metadata and artifact provenance belong to the Python
//! host's verified callback service; the kernel never guesses package metadata.
//! The line-framed protocol is a REQUIRED backend: errors terminate the solve.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::{self, BufRead, BufReader, Write};

#[derive(Clone, Deserialize, Serialize, Eq, PartialEq)]
struct Requirement {
    name: String,
    text: String,
    #[serde(default)]
    extras: Vec<String>,
    #[serde(default)]
    causes: BTreeSet<String>,
}

#[derive(Clone, Deserialize, Serialize)]
struct Candidate {
    id: String,
    name: String,
    kind: String,
    version: String,
    filename: String,
}

struct Rpc<R: BufRead, W: Write> {
    reader: R,
    writer: W,
}

impl<R: BufRead, W: Write> Rpc<R, W> {
    fn send(&mut self, operation: Value) -> Result<Value, String> {
        serde_json::to_writer(&mut self.writer, &operation).map_err(|e| e.to_string())?;
        self.writer.write_all(b"\n").map_err(|e| e.to_string())?;
        self.writer.flush().map_err(|e| e.to_string())?;
        let mut line = String::new();
        if self.reader.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
            return Err("verified registry callback channel closed".into());
        }
        let answer: Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
        if let Some(error) = answer.get("error").and_then(Value::as_str) {
            return Err(error.to_string());
        }
        answer.get("value").cloned().ok_or_else(|| "verified registry callback lacks value".into())
    }
}

type Requirements = BTreeMap<String, Vec<Requirement>>;
type Extras = BTreeMap<String, BTreeSet<String>>;

fn grouped(entries: &[Requirement]) -> (Requirements, Extras) {
    let mut rows: BTreeMap<String, BTreeMap<String, Requirement>> = BTreeMap::new();
    let mut extras = Extras::new();
    for req in entries {
        extras.entry(req.name.clone()).or_default().extend(req.extras.iter().cloned());
        let entry = rows.entry(req.name.clone()).or_default().entry(req.text.clone());
        entry.and_modify(|old| old.causes.extend(req.causes.iter().cloned()))
             .or_insert_with(|| req.clone());
    }
    (rows.into_iter().map(|(name, value)| (name, value.into_values().collect())).collect(), extras)
}

fn causes(rows: &[Requirement]) -> BTreeSet<String> {
    rows.iter().flat_map(|row| row.causes.iter().cloned()).collect()
}

fn combine(mut left: BTreeSet<String>, right: BTreeSet<String>) -> BTreeSet<String> {
    left.extend(right);
    left
}

#[derive(Serialize)]
struct StateIdentity<'a> {
    requirements: &'a Requirements,
    selected: &'a BTreeMap<String, Candidate>,
    expanded: &'a Extras,
}

struct Engine<R: BufRead, W: Write> {
    io: Rpc<R, W>,
    roots: BTreeSet<String>,
    no_deps: bool,
    domain_cache: HashMap<String, Vec<Candidate>>,
    metadata_cached: HashSet<String>,
    failed_states: HashSet<String>,
    // Failed states are safe to evict. A missing record means recomputation,
    // never admission of an invalid artifact.
    failed_fifo: std::collections::VecDeque<String>,
    failed_budget_bytes: usize,
    failed_bytes: usize,
    nogoods: HashMap<String, Vec<Vec<(String, String)>>>,
    decisions: usize,
    backjumps: usize,
    memo_hits: usize,
}

type Attempt = Result<(Option<BTreeMap<String, Candidate>>, BTreeSet<String>, String), String>;

impl<R: BufRead, W: Write> Engine<R, W> {
    fn domain(&mut self, name: &str, rows: &[Requirement]) -> Result<Vec<Candidate>, String> {
        let reqs: Vec<_> = rows.iter().map(|row| row.text.clone()).collect();
        let token = serde_json::to_string(&(name, &reqs)).map_err(|e| e.to_string())?;
        if let Some(value) = self.domain_cache.get(&token) { return Ok(value.clone()); }
        let response = self.io.send(json!({"op":"domain", "name":name,"requirements":reqs}))?;
        let candidates: Vec<Candidate> = serde_json::from_value(response).map_err(|e| e.to_string())?;
        if candidates.iter().any(|candidate| candidate.name != name) {
            return Err("verified domain returns a mismatched package identity".into());
        }
        self.domain_cache.insert(token, candidates.clone());
        Ok(candidates)
    }

    fn metadata(&mut self, candidate: &Candidate) -> Result<(), String> {
        if self.metadata_cached.contains(&candidate.id) { return Ok(()); }
        let result = self.io.send(json!({"op":"metadata", "id":candidate.id}))?;
        if result != json!({"id": candidate.id}) {
            return Err("verified metadata identity differs from candidate".into());
        }
        self.metadata_cached.insert(candidate.id.clone());
        Ok(())
    }

    fn dependencies(&mut self, candidate: &Candidate, extras: &BTreeSet<String>) -> Result<Vec<Requirement>, String> {
        if self.no_deps { return Ok(Vec::new()); }
        self.metadata(candidate)?;
        let value = self.io.send(json!({"op":"dependencies", "id":candidate.id, "extras":extras}))?;
        serde_json::from_value(value).map_err(|e| e.to_string())
    }

    fn satisfies(&mut self, candidate: &Candidate, rows: &[Requirement]) -> Result<bool, String> {
        let requirements: Vec<_> = rows.iter().map(|row| row.text.as_str()).collect();
        let result = self.io.send(json!({"op":"satisfies", "id":candidate.id, "requirements": requirements,
                                          "name":candidate.name}))?;
        result.as_bool().ok_or_else(|| "verified compatibility callback is not Boolean".into())
    }

    fn record_failure(&mut self, key: String) {
        if !self.failed_states.insert(key.clone()) { return; }
        self.failed_bytes += key.len();
        self.failed_fifo.push_back(key);
        while self.failed_bytes > self.failed_budget_bytes {
            if let Some(evicted) = self.failed_fifo.pop_front() {
                self.failed_bytes -= evicted.len();
                self.failed_states.remove(&evicted);
            } else { break; }
        }
    }

    fn compatibility_conflict(
        &mut self, name: &str, candidate: &Candidate, rows: &[Requirement],
        all: &Requirements, selected: &BTreeMap<String, Candidate>, extras: &Extras,
    ) -> Result<Option<BTreeSet<String>>, String> {
        let active = extras.get(name).cloned().unwrap_or_default();
        let dependencies = self.dependencies(candidate, &active)?;
        for dep in dependencies {
            if dep.name == name {
                if !self.satisfies(candidate, &[dep])? {
                    let mut conflict = causes(rows); conflict.insert(name.into());
                    return Ok(Some(conflict));
                }
            } else if let Some(assigned) = selected.get(&dep.name) {
                if !self.satisfies(assigned, &[dep.clone()])? {
                    let mut conflict = causes(rows);
                    conflict.extend(all.get(&dep.name).map(|x| causes(x)).unwrap_or_default());
                    conflict.insert(name.into()); conflict.insert(dep.name);
                    return Ok(Some(conflict));
                }
            } else if let Some(prior) = all.get(&dep.name) {
                let mut extended = prior.clone(); extended.push(dep.clone());
                if self.domain(&dep.name, &extended)?.is_empty() {
                    let mut conflict = combine(causes(rows), causes(prior));
                    conflict.insert(name.into());
                    return Ok(Some(conflict));
                }
            }
        }
        Ok(None)
    }

    fn search(&mut self, mut entries: Vec<Requirement>, mut selected: BTreeMap<String, Candidate>,
              mut expanded: Extras) -> Attempt {
        loop {
            let (requirements, extras) = grouped(&entries);
            let identity = serde_json::to_string(&StateIdentity {
                requirements: &requirements, selected: &selected, expanded: &expanded,
            }).map_err(|e| e.to_string())?;
            if self.failed_states.contains(&identity) {
                self.memo_hits += 1;
                return Ok((None, selected.keys().cloned().collect(),
                           "memoized unsatisfiable registry state".into()));
            }

            for (name, candidate) in &selected {
                let rows = requirements.get(name).map(Vec::as_slice).unwrap_or(&[]);
                if !self.satisfies(candidate, rows)? {
                    let mut conflict = causes(rows); conflict.insert(name.clone());
                    self.record_failure(identity);
                    return Ok((None, conflict, format!("selected {} violates active requirements", name)));
                }
            }

            let mut additions = Vec::new();
            let mut next_expanded = expanded.clone();
            for (name, candidate) in &selected {
                let active = extras.get(name).cloned().unwrap_or_default();
                if expanded.get(name) == Some(&active) { continue; }
                let mut origins = requirements.get(name).map(|r| causes(r)).unwrap_or_default();
                origins.insert(name.clone());
                for mut dep in self.dependencies(candidate, &active)? {
                    dep.causes = origins.clone();
                    additions.push(dep);
                }
                next_expanded.insert(name.clone(), active);
            }
            if !additions.is_empty() || next_expanded != expanded {
                entries.extend(additions); expanded = next_expanded; continue;
            }

            let mut choices: Vec<(usize, String, Vec<Candidate>)> = Vec::new();
            for (name, rows) in &requirements {
                if selected.contains_key(name) { continue; }
                let candidates = self.domain(name, rows)?;
                if candidates.is_empty() {
                    let conflict = causes(rows);
                    self.record_failure(identity);
                    return Ok((None, conflict, format!("no compatible release for {}", name)));
                }
                choices.push((candidates.len(), name.clone(), candidates));
            }
            if choices.is_empty() { return Ok((Some(selected), BTreeSet::new(), String::new())); }
            // MRV, then original root identity, then canonical package name.
            choices.sort_by(|a, b| a.0.cmp(&b.0)
                .then_with(|| (!self.roots.contains(&a.1)).cmp(&(!self.roots.contains(&b.1))))
                .then_with(|| a.1.cmp(&b.1)));
            let (count, name, candidates) = choices.remove(0);
            let rows = requirements.get(&name).ok_or("selected missing requirement domain")?;
            if count == 1 {
                self.metadata(&candidates[0])?;
                selected.insert(name, candidates[0].clone());
                continue;
            }

            let mut accumulated = BTreeSet::new();
            let mut detail = String::new();
            for candidate in &candidates {
                self.decisions += 1;
                if self.decisions.is_power_of_two() {
                    eprintln!("[pool] Rust resolver: decisions={} backjumps={} memo_hits={}",
                              self.decisions, self.backjumps, self.memo_hits);
                }
                self.metadata(candidate)?;
                let conflict = if let Some(conflict) = self.compatibility_conflict(
                    &name, candidate, rows, &requirements, &selected, &extras)? {
                    conflict
                } else {
                    let mut next = selected.clone(); next.insert(name.clone(), candidate.clone());
                    let (answer, conflict, message) = self.search(entries.clone(), next, expanded.clone())?;
                    if let Some(solution) = answer { return Ok((Some(solution), BTreeSet::new(), String::new())); }
                    detail = message;
                    conflict
                };
                if !conflict.contains(&name) {
                    self.backjumps += 1;
                    self.record_failure(identity);
                    return Ok((None, conflict, detail));
                }
                accumulated.extend(conflict.into_iter().filter(|p| p != &name));
            }
            accumulated.extend(causes(rows));
            self.record_failure(identity);
            return Ok((None, accumulated, detail));
        }
    }
}

fn observed_memory_bytes() -> Result<u64, String> {
    // Require the versioned caller to provide an explicit memory budget instead
    // of selecting an unexplained fixed cache size in the Rust kernel.
    let value = std::env::var("GPT_TRACE_RUST_RESOLVER_MEMO_BYTES")
        .map_err(|_| "missing versioned Rust resolver memo budget".to_owned())?;
    let parsed: u64 = value.parse().map_err(|_| "invalid Rust resolver memo budget".to_owned())?;
    if parsed == 0 { return Err("empty Rust resolver memo budget".into()); }
    Ok(parsed)
}

fn run() -> Result<(), String> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = BufReader::new(stdin.lock());
    let mut first = String::new();
    if input.read_line(&mut first).map_err(|e| e.to_string())? == 0 {
        return Err("missing verified registry initialization".into());
    }
    let init: Value = serde_json::from_str(&first).map_err(|e| e.to_string())?;
    let roots: Vec<Requirement> = serde_json::from_value(
        init.get("roots").cloned().ok_or("missing resolver roots")?
    ).map_err(|e| e.to_string())?;
    let no_deps = init.get("no_deps").and_then(Value::as_bool).ok_or("missing no_deps")?;
    let memo_bytes = usize::try_from(observed_memory_bytes()?).map_err(|e| e.to_string())?;
    let root_names = roots.iter().map(|r| r.name.clone()).collect();
    let mut engine = Engine {
        io: Rpc {reader: input, writer: stdout.lock()}, roots: root_names, no_deps,
        domain_cache: HashMap::new(), metadata_cached: HashSet::new(),
        failed_states: HashSet::new(), failed_fifo: Default::default(),
        failed_budget_bytes: memo_bytes, failed_bytes: 0, nogoods: HashMap::new(),
        decisions: 0, backjumps: 0, memo_hits: 0,
    };
    let (solution, _conflict, detail) = engine.search(roots, BTreeMap::new(), Extras::new())?;
    if let Some(solution) = solution {
        let selected: Vec<_> = solution.into_iter().map(|(name, candidate)| json!({"name":name,"id":candidate.id})).collect();
        serde_json::to_writer(&mut engine.io.writer, &json!({"event":"result","selected":selected,
            "decisions":engine.decisions,"backjumps":engine.backjumps,"memo_hits":engine.memo_hits}))
            .map_err(|e| e.to_string())?;
        engine.io.writer.write_all(b"\n").map_err(|e| e.to_string())?;
        engine.io.writer.flush().map_err(|e| e.to_string())?;
        Ok(())
    } else {
        Err(format!("verified registry dependency resolution is unsatisfiable: {}",detail))
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("[pool] Rust resolver failed: {}", error);
        std::process::exit(1);
    }
}
