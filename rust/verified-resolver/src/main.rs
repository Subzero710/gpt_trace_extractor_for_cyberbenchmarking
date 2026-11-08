//! Production dependency-graph decision engine.
//! All Python packaging / wheel / PEP 517 semantics stay with the verified host
//! callback. This executable exclusively owns search, state propagation, conflict
//! learning, and CPU work. Zero third-party Rust dependencies; offline build.
//! Protocol is typed length-prefixed binary, versioned by source/policy identity.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::time::{Duration, Instant};

fn err<E: std::fmt::Display>(e: E) -> String { e.to_string() }

struct Wire {
    input: BufReader<io::Stdin>,
    output: BufWriter<io::Stdout>,
    max_frame: usize,
}
impl Wire {
    fn new() -> Self {
        Self { input: BufReader::new(io::stdin()), output: BufWriter::new(io::stdout()),
               max_frame: u32::MAX as usize }
    }
    fn raw_u8(&mut self) -> Result<u8, String> {
        let mut b = [0u8; 1]; self.input.read_exact(&mut b).map_err(err)?; Ok(b[0])
    }
    fn raw_u32(&mut self) -> Result<u32, String> {
        let mut b = [0u8; 4]; self.input.read_exact(&mut b).map_err(err)?; Ok(u32::from_be_bytes(b))
    }
    fn raw_u64(&mut self) -> Result<u64, String> {
        let mut b = [0u8; 8]; self.input.read_exact(&mut b).map_err(err)?; Ok(u64::from_be_bytes(b))
    }
    fn raw_string(&mut self) -> Result<String, String> {
        let size = self.raw_u32()? as usize;
        if size > self.max_frame { return Err("resolver IPC string exceeds versioned limit".into()); }
        let mut data = vec![0u8; size]; self.input.read_exact(&mut data).map_err(err)?;
        String::from_utf8(data).map_err(err)
    }
    fn send_u8(&mut self, v: u8) -> Result<(), String> { self.output.write_all(&[v]).map_err(err) }
    fn send_u32(&mut self, v: u32) -> Result<(), String> { self.output.write_all(&v.to_be_bytes()).map_err(err) }
    fn send_len(&mut self, v: usize) -> Result<(), String> {
        self.send_u32(u32::try_from(v).map_err(err)?)
    }
    fn send_string(&mut self, v: &str) -> Result<(), String> {
        if v.len() > self.max_frame { return Err("resolver IPC outbound string exceeds limit".into()); }
        self.send_len(v.len())?; self.output.write_all(v.as_bytes()).map_err(err)
    }
    fn flush(&mut self) -> Result<(), String> { self.output.flush().map_err(err) }
    fn ack(&mut self) -> Result<(), String> {
        match self.raw_u8()? {
            1 => Ok(()),
            0 => Err(self.raw_string()?),
            _ => Err("invalid resolver IPC response status".into()),
        }
    }
    fn strings(&mut self, values: &[String]) -> Result<(), String> {
        self.send_len(values.len())?;
        for s in values { self.send_string(s)?; }
        Ok(())
    }
    fn finish_success(&mut self, selected: &BTreeMap<String, Candidate>, stats: &Stats) -> Result<(), String> {
        self.send_u8(b'S')?; self.send_len(selected.len())?;
        for candidate in selected.values() { self.send_u32(candidate.id)?; }
        self.send_string(&stats.render())?; self.flush()
    }
    fn finish_unsat(&mut self, detail: &str, stats: &Stats) -> Result<(), String> {
        self.send_u8(b'U')?; self.send_string(detail)?; self.send_string(&stats.render())?; self.flush()
    }
    fn finish_error(&mut self, detail: &str) -> Result<(), String> {
        self.send_u8(b'F')?; self.send_string(detail)?; self.flush()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    name: String,
    requirement: String,
    extras: BTreeSet<String>,
    causes: BTreeSet<String>,
}
#[derive(Clone, Debug)]
struct Candidate {
    id: u32,
    kind: String,
    version: String,
    filename: String,
}
#[derive(Default, Clone)]
struct Stats {
    decisions: u64,
    propagations: u64,
    backjumps: u64,
    memo_hits: u64,
    learned_skips: u64,
    forward_prunes: u64,
    decisions_by_name: BTreeMap<String, u64>,
}
impl Stats {
    fn render(&self) -> String {
        let hot = self.decisions_by_name.iter().max_by_key(|(name, n)| (*n, *name));
        let (name, count) = hot.map(|(name, n)| (name.as_str(), *n)).unwrap_or(("-", 0));
        format!("solver decisions={} propagations={} backjumps={} memo_hits={} learned_skips={} forward_prunes={} hottest={}:{}", 
            self.decisions, self.propagations, self.backjumps, self.memo_hits, self.learned_skips,
            self.forward_prunes, name, count)
    }
}
#[derive(Clone)]
struct State {
    entries: Vec<Entry>,
    selected: BTreeMap<String, Candidate>,
    expanded: BTreeMap<String, BTreeSet<String>>,
}
struct Grouped {
    rows: BTreeMap<String, Vec<Entry>>,
    extras: BTreeMap<String, BTreeSet<String>>,
}
fn grouped(entries: &[Entry]) -> Grouped {
    let mut by_key: BTreeMap<(String,String), Entry> = BTreeMap::new();
    let mut extras: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for row in entries {
        extras.entry(row.name.clone()).or_default().extend(row.extras.iter().cloned());
        let key = (row.name.clone(), row.requirement.clone());
        if let Some(old) = by_key.get_mut(&key) { old.causes.extend(row.causes.iter().cloned()); }
        else { by_key.insert(key, row.clone()); }
    }
    let mut rows: BTreeMap<String,Vec<Entry>> = BTreeMap::new();
    for ((_name, _requirement), row) in by_key {
        rows.entry(row.name.clone()).or_default().push(row);
    }
    Grouped { rows, extras }
}
fn causes(rows: &[Entry]) -> BTreeSet<String> {
    rows.iter().flat_map(|r| r.causes.iter().cloned()).collect()
}
type StateKey = (Vec<(String, Vec<String>)>,
                 Vec<(String, String, String, String)>,
                 Vec<(String, Vec<String>)>);
type NogoodKey = (String, String, String, String, Vec<String>, Vec<String>);
type Clause = Vec<(String, (String, String, String))>;

fn current_state_key(state: &State, group: &Grouped) -> StateKey {
    // Literal port of Python state_key: the requirement strings, the selected
    // artifact (kind/version/filename), and expanded extras form the key.
    // Causal provenance is intentionally NOT part of Python's memo identity.
    let requirements = group.rows.iter().map(|(name, rows)|
        (name.clone(), rows.iter().map(|row| row.requirement.clone()).collect())
    ).collect();
    let assignments = state.selected.iter().map(|(name, candidate)|
        (name.clone(), candidate.kind.clone(), candidate.version.clone(),
         candidate.filename.clone())
    ).collect();
    let extras = state.expanded.iter().map(|(name, values)|
        (name.clone(), values.iter().cloned().collect())
    ).collect();
    (requirements, assignments, extras)
}
#[derive(Clone)]
struct Failure { conflict: BTreeSet<String>, detail: String }
enum Outcome { Solved(BTreeMap<String, Candidate>), Failed(Failure) }

struct Solver {
    wire: Wire,
    no_deps: bool,
    roots: BTreeSet<String>,
    deadline: Option<Instant>,
    max_decisions: u64,
    max_depth: usize,
    max_cache_bytes: usize,
    prefetch_width: usize,
    stats: Stats,
    candidate_domains: HashMap<(String,Vec<String>),Vec<Candidate>>,
    metadata_seen: HashSet<u32>,
    expanded_cache: HashMap<(u32,Vec<String>),Vec<Entry>>,
    failed_states: HashSet<StateKey>,
    failed_fifo: VecDeque<StateKey>,
    failed_bytes: usize,
    nogoods: HashMap<NogoodKey,Vec<Clause>>,
    nogood_bytes: usize,
}
impl Solver {
    fn validate_time(&self) -> Result<(), String> {
        // No wall-clock cap for a complete closure. Each host I/O / build
        // operation is bounded by its own independently configured deadline.
        if self.deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            Err("native Rust dependency solve exceeded configured deadline".into())
        } else { Ok(()) }
    }
    fn read_candidate(&mut self) -> Result<Candidate,String> {
        let id = self.wire.raw_u32()?;
        let kind = self.wire.raw_string()?;
        let version = self.wire.raw_string()?;
        let filename = self.wire.raw_string()?;
        if kind != "wheel" && kind != "sdist" { return Err("unrecognized candidate kind".into()); }
        Ok(Candidate {id,kind,version,filename})
    }
    fn domain(&mut self, name: &str, rows: &[Entry]) -> Result<Vec<Candidate>,String> {
        self.validate_time()?;
        let requirements: Vec<String> = rows.iter().map(|e| e.requirement.clone()).collect();
        let key = (name.to_string(), requirements.clone());
        if let Some(cached) = self.candidate_domains.get(&key) { return Ok(cached.clone()); }
        self.wire.send_u8(b'D')?; self.wire.send_string(name)?;
        self.wire.strings(&requirements)?; self.wire.flush()?;
        self.wire.ack()?;
        let count = self.wire.raw_u32()? as usize;
        if count > self.wire.max_frame { return Err("candidate count exceeds IPC safety limit".into()); }
        let mut candidates = Vec::with_capacity(count);
        for _ in 0..count { candidates.push(self.read_candidate()?); }
        self.candidate_domains.insert(key, candidates.clone());
        Ok(candidates)
    }
    fn domains(&mut self, unresolved: &[String], group: &Grouped)
        -> Result<BTreeMap<String, Vec<Candidate>>, String> {
        let mut missing = Vec::new();
        let mut answers = BTreeMap::new();
        for name in unresolved {
            let rows = &group.rows[name];
            let requirements: Vec<String> = rows.iter().map(|r| r.requirement.clone()).collect();
            let key = (name.clone(), requirements.clone());
            if let Some(cached) = self.candidate_domains.get(&key) {
                answers.insert(name.clone(), cached.clone());
            } else {
                missing.push((name.clone(), requirements));
            }
        }
        if !missing.is_empty() {
            self.validate_time()?;
            self.wire.send_u8(b'B')?;
            self.wire.send_len(missing.len())?;
            for (name, requirements) in &missing {
                self.wire.send_string(name)?;
                self.wire.strings(requirements)?;
            }
            self.wire.flush()?;
            self.wire.ack()?;
            let count = self.wire.raw_u32()? as usize;
            if count != missing.len() { return Err("batch domain count differs".into()); }
            for (name, requirements) in missing {
                let size = self.wire.raw_u32()? as usize;
                if size > self.wire.max_frame { return Err("domain candidate count exceeds IPC limit".into()); }
                let mut candidates = Vec::with_capacity(size);
                for _ in 0..size { candidates.push(self.read_candidate()?); }
                self.candidate_domains.insert((name.clone(), requirements), candidates.clone());
                answers.insert(name, candidates);
            }
        }
        Ok(answers)
    }
    fn known_metadata(&mut self, candidates: &[Candidate]) -> Result<BTreeSet<u32>, String> {
        if candidates.is_empty() || self.no_deps { return Ok(BTreeSet::new()); }
        self.wire.send_u8(b'K')?;
        self.wire.send_len(candidates.len())?;
        for candidate in candidates { self.wire.send_u32(candidate.id)?; }
        self.wire.flush()?;
        self.wire.ack()?;
        let mut known = BTreeSet::new();
        for candidate in candidates {
            match self.wire.raw_u8()? {
                1 => { known.insert(candidate.id); },
                0 => {},
                _ => return Err("invalid metadata-known bit".into()),
            }
        }
        Ok(known)
    }
    fn prefetch(&mut self, candidates: &[Candidate], index: usize) -> Result<(), String> {
        // Python's schedule_metadata submits futures without awaiting them.
        // The Python host recomputes its live fairness-adjusted width.
        self.wire.send_u8(b'W')?;
        self.wire.flush()?;
        self.wire.ack()?;
        let width = self.wire.raw_u32()? as usize;
        if width == 0 { return Err("invalid live Rust prefetch width".into()); }
        let stop = std::cmp::min(candidates.len(), index.saturating_add(width));
        self.wire.send_u8(b'A')?;
        self.wire.send_len(stop - index)?;
        for candidate in &candidates[index..stop] { self.wire.send_u32(candidate.id)?; }
        self.wire.flush()?;
        self.wire.ack()
    }
    fn check(&mut self, candidate: &Candidate, rows: &[Entry]) -> Result<bool,String> {
        self.validate_time()?;
        self.wire.send_u8(b'C')?; self.wire.send_u32(candidate.id)?;
        self.wire.strings(&rows.iter().map(|e| e.requirement.clone()).collect::<Vec<_>>())?;
        self.wire.flush()?; self.wire.ack()?;
        match self.wire.raw_u8()? { 0 => Ok(false), 1 => Ok(true), _ => Err("invalid candidate compatibility response".into()) }
    }
    fn metadata_batch(&mut self, ids: &[u32]) -> Result<(),String> {
        self.validate_time()?;
        let missing: Vec<u32> = ids.iter().copied().filter(|id| !self.metadata_seen.contains(id)).collect();
        if missing.is_empty() { return Ok(()); }
        self.wire.send_u8(b'M')?; self.wire.send_len(missing.len())?;
        for id in &missing { self.wire.send_u32(*id)?; }
        self.wire.flush()?; self.wire.ack()?;
        for id in missing { self.metadata_seen.insert(id); }
        Ok(())
    }
    fn expand(&mut self, candidate: &Candidate, extras: &BTreeSet<String>) -> Result<Vec<Entry>,String> {
        if self.no_deps { return Ok(Vec::new()); }
        self.metadata_batch(&[candidate.id])?;
        let extras_key: Vec<String> = extras.iter().cloned().collect();
        let key = (candidate.id, extras_key.clone());
        if let Some(rows) = self.expanded_cache.get(&key) { return Ok(rows.clone()); }
        self.wire.send_u8(b'P')?; self.wire.send_u32(candidate.id)?;
        self.wire.strings(&extras_key)?; self.wire.flush()?; self.wire.ack()?;
        let count = self.wire.raw_u32()? as usize;
        if count > self.wire.max_frame { return Err("dependency count exceeds IPC safety limit".into()); }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let name = self.wire.raw_string()?;
            let requirement = self.wire.raw_string()?;
            let extra_count = self.wire.raw_u32()? as usize;
            if extra_count > self.wire.max_frame { return Err("extra count exceeds IPC safety limit".into()); }
            let mut extras = BTreeSet::new();
            for _ in 0..extra_count { extras.insert(self.wire.raw_string()?); }
            entries.push(Entry {name,requirement,extras,causes:BTreeSet::new()});
        }
        self.expanded_cache.insert(key,entries.clone());
        Ok(entries)
    }
    fn lookahead(&mut self, name: &str, candidate: &Candidate, rows: &[Entry],
                 group: &Grouped, selected: &BTreeMap<String,Candidate>)
       -> Result<Option<(BTreeSet<String>,String)>,String> {
        if self.no_deps { return Ok(None); }
        let extras = group.extras.get(name).cloned().unwrap_or_default();
        let dependencies = self.expand(candidate, &extras)?;
        for dep in dependencies {
            let dep_name = dep.name.as_str();
            let conflict = if dep_name == name {
                !self.check(candidate, &[dep.clone()])?
            } else if let Some(prior) = selected.get(dep_name) {
                !self.check(prior, &[dep.clone()])?
            } else if let Some(prior_rows) = group.rows.get(dep_name) {
                let mut combined = prior_rows.clone(); combined.push(dep.clone());
                self.domain(dep_name, &combined)?.is_empty()
            } else { false };
            if conflict {
                let mut provenance = causes(rows);
                provenance.insert(name.to_string());
                if dep_name != name {
                    if selected.contains_key(dep_name) { provenance.insert(dep.name.clone()); }
                    if let Some(existing) = group.rows.get(dep_name) { provenance.extend(causes(existing)); }
                }
                return Ok(Some((provenance,dep.name)));
            }
        }
        Ok(None)
    }
    fn failed(&mut self, key: StateKey) {
        let size = format!("{:?}", key).len();
        if size > self.max_cache_bytes { return; }
        while self.failed_bytes.saturating_add(size) > self.max_cache_bytes {
            if let Some(old) = self.failed_fifo.pop_front() {
                self.failed_bytes = self.failed_bytes.saturating_sub(format!("{:?}", old).len());
                self.failed_states.remove(&old);
            } else { break; }
        }
        if self.failed_states.insert(key.clone()) {
            self.failed_bytes = self.failed_bytes.saturating_add(size);
            self.failed_fifo.push_back(key);
        }
    }
    fn nogood_key(name: &str,c: &Candidate,rows: &[Entry],extras: &BTreeSet<String>) -> NogoodKey {
        (name.to_string(),c.kind.clone(),c.version.clone(),c.filename.clone(),
         rows.iter().map(|r| r.requirement.clone()).collect(),
         extras.iter().cloned().collect())
    }
    fn nogood_matches(&self, key: &NogoodKey, selected: &BTreeMap<String,Candidate>) -> bool {
        self.nogoods.get(key).map(|clauses| clauses.iter().any(|clause| {
            clause.iter().all(|(name,identity)| selected.get(name).map(|c|
                (&c.kind,&c.version,&c.filename) == (&identity.0,&identity.1,&identity.2)
            ).unwrap_or(false))
        })).unwrap_or(false)
    }
    fn learn_nogood(&mut self,key: NogoodKey, conflict: &BTreeSet<String>, name: &str,
                    selected: &BTreeMap<String,Candidate>) {
        let clause: Clause = conflict.iter()
            .filter(|n| n.as_str()!=name)
            .filter_map(|n| selected.get(n).map(|c|
                (n.clone(),(c.kind.clone(),c.version.clone(),c.filename.clone()))))
            .collect();
        let size = format!("{:?}{:?}", key, clause).len();
        if size > self.max_cache_bytes { return; }
        if self.nogood_bytes.saturating_add(size) > self.max_cache_bytes {
            self.nogoods.clear(); self.nogood_bytes=0;
        }
        let entries = self.nogoods.entry(key).or_default();
        if !entries.contains(&clause) { entries.push(clause); self.nogood_bytes+=size; }
    }
    fn search(&mut self,mut state: State,depth: usize) -> Result<Outcome,String> {
        if depth > self.max_depth { return Err("native Rust solver exceeded configured recursion depth".into()); }
        loop {
            self.validate_time()?;
            let group = grouped(&state.entries);
            let key = current_state_key(&state,&group);
            if self.failed_states.contains(&key) {
                self.stats.memo_hits+=1;
                let conflict = state.selected.keys().cloned().collect();
                return Ok(Outcome::Failed(Failure {conflict, detail:"memoized unsatisfiable resolver state".into()}));
            }
            for (name,c) in &state.selected {
                let rows = group.rows.get(name).map(|x|x.as_slice()).unwrap_or(&[]);
                if !self.check(c,rows)? {
                    let mut conflict=causes(rows); conflict.insert(name.clone());
                    let detail=format!("selected {}=={} violates required constraints",name,c.version);
                    self.failed(key.clone());
                    return Ok(Outcome::Failed(Failure{conflict,detail}));
                }
            }
            let mut next_expanded=state.expanded.clone();
            let mut additions=Vec::new();
            for (name,c) in &state.selected {
                let extras=group.extras.get(name).cloned().unwrap_or_default();
                if state.expanded.get(name)==Some(&extras) { continue; }
                let mut origin=causes(group.rows.get(name).map(|x|x.as_slice()).unwrap_or(&[]));
                origin.insert(name.clone());
                for mut dep in self.expand(c,&extras)? {
                    dep.causes=origin.clone(); additions.push(dep);
                }
                next_expanded.insert(name.clone(),extras);
            }
            if !additions.is_empty() || next_expanded!=state.expanded {
                self.stats.propagations+=additions.len() as u64;
                state.entries.extend(additions);
                state.expanded=next_expanded;
                continue;
            }
            let unresolved: Vec<String> = group.rows.keys().filter(|name|!state.selected.contains_key(*name)).cloned().collect();
            if unresolved.is_empty() { return Ok(Outcome::Solved(state.selected)); }
            let mut choices: Vec<(usize,bool,String,Vec<Candidate>)> = Vec::new();
            let domains = self.domains(&unresolved, &group)?;
            for name in unresolved {
                let rows=&group.rows[&name];
                let candidates=domains[&name].clone();
                if candidates.is_empty() {
                    self.failed(key.clone());
                    return Ok(Outcome::Failed(Failure {conflict: causes(rows),
                        detail:format!("no compatible release for {} under requirements {:?}",name,
                                       rows.iter().map(|r|r.requirement.as_str()).collect::<Vec<_>>())}));
                }
                let mut survivors=Vec::new();
                let mut known_conflict=BTreeSet::new();
                let mut first_detail=None;
                let known = self.known_metadata(&candidates)?;
                for c in candidates {
                    if known.contains(&c.id) {
                        if let Some((involved,dep_name))=self.lookahead(&name,&c,rows,&group,&state.selected)? {
                            known_conflict.extend(involved);
                            if first_detail.is_none() { first_detail=Some(dep_name); }
                            self.stats.forward_prunes+=1;
                            continue;
                        }
                    }
                    survivors.push(c);
                }
                if survivors.is_empty() {
                    self.failed(key.clone());
                    return Ok(Outcome::Failed(Failure{conflict:known_conflict,
                        detail:format!("all cached compatible releases of {} conflict with {}",name,
                            first_detail.unwrap_or_default())}));
                }
                choices.push((survivors.len(),!self.roots.contains(&name),name,survivors));
            }
            choices.sort_by(|a,b| (a.0,a.1,&a.2).cmp(&(b.0,b.1,&b.2)));
            let (count,_is_transitive,name,candidates)=choices.remove(0);
            if count == 1 {
                self.metadata_batch(&[candidates[0].id])?;
                state.selected.insert(name,candidates[0].clone());
                self.stats.propagations+=1;
                continue;
            }
            let rows=&group.rows[&name];
            let branch_causes=causes(rows);
            let extras=group.extras.get(&name).cloned().unwrap_or_default();
            let mut combined_conflict=BTreeSet::new();
            let mut last_detail=String::new();
            for (idx,candidate) in candidates.iter().enumerate() {
                self.validate_time()?;
                let nogood=Self::nogood_key(&name,candidate,rows,&extras);
                if self.nogood_matches(&nogood,&state.selected) {
                    self.stats.learned_skips+=1; continue;
                }
                self.stats.decisions+=1;
                if self.stats.decisions>self.max_decisions {
                    return Err("native Rust solver exceeded configured decision budget".into());
                }
                *self.stats.decisions_by_name.entry(name.clone()).or_default()+=1;
                // Submit, do not wait for the entire metadata prefetch window.
                // Only the current candidate must finish before lookahead.
                self.prefetch(&candidates, idx)?;
                self.metadata_batch(&[candidate.id])?;
                let conflict=self.lookahead(&name,candidate,rows,&group,&state.selected)?;
                let result=if let Some((involved,dep_name))=conflict {
                    self.stats.forward_prunes+=1;
                    Outcome::Failed(Failure {conflict:involved,
                        detail:format!("candidate {}=={} leaves incompatible requirements for {}",
                                       name,candidate.version,dep_name)})
                } else {
                    let mut next=state.clone();
                    next.selected.insert(name.clone(),candidate.clone());
                    self.search(next,depth+1)?
                };
                match result {
                    Outcome::Solved(sol) => return Ok(Outcome::Solved(sol)),
                    Outcome::Failed(failure) => {
                        last_detail=failure.detail.clone();
                        if failure.conflict.contains(&name) {
                            self.learn_nogood(nogood,&failure.conflict,&name,&state.selected);
                        } else {
                            self.stats.backjumps+=1;
                            self.failed(key.clone());
                            return Ok(Outcome::Failed(failure));
                        }
                        combined_conflict.extend(failure.conflict.into_iter().filter(|n|n!=&name));
                    }
                }
            }
            combined_conflict.extend(branch_causes);
            self.failed(key.clone());
            if last_detail.is_empty() { last_detail=format!("all compatible candidates exhausted for {}",name); }
            return Ok(Outcome::Failed(Failure{conflict:combined_conflict,detail:last_detail}));
        }
    }
}

fn process(wire: &mut Wire) -> Result<(),String> {
    let max_frame=wire.raw_u64()?;
    let limit=usize::try_from(max_frame).map_err(err)?;
    if limit==0 || limit>u32::MAX as usize { return Err("invalid configured IPC frame limit".into()); }
    wire.max_frame=limit;
    let max_decisions=wire.raw_u64()?;
    let max_depth=usize::try_from(wire.raw_u64()?).map_err(err)?;
    let max_cache_bytes=usize::try_from(wire.raw_u64()?).map_err(err)?;
    let deadline_seconds=wire.raw_u64()?;
    let prefetch_width=usize::try_from(wire.raw_u64()?).map_err(err)?;
    let no_deps=wire.raw_u8()? != 0;
    if max_decisions==0 || max_depth==0 || max_cache_bytes==0 || prefetch_width==0 {
        return Err("invalid versioned solver resource policy".into());
    }
    let count=wire.raw_u32()? as usize;
    if count>limit { return Err("root requirement count exceeds IPC safety limit".into()); }
    let mut roots=BTreeSet::new();
    let mut entries=Vec::with_capacity(count);
    for _ in 0..count {
        let name=wire.raw_string()?;
        let requirement=wire.raw_string()?;
        let extras_count=wire.raw_u32()? as usize;
        if extras_count>limit { return Err("root extras count exceeds IPC limit".into()); }
        let mut extras=BTreeSet::new();
        for _ in 0..extras_count { extras.insert(wire.raw_string()?); }
        roots.insert(name.clone());
        entries.push(Entry{name,requirement,extras,causes:BTreeSet::new()});
    }
    let deadline=if deadline_seconds==0 { None } else {
        Some(Instant::now().checked_add(Duration::from_secs(deadline_seconds))
            .ok_or_else(||"invalid resolver deadline".to_string())?)
    };
    let mut solver=Solver {wire:Wire::new(),no_deps,roots,deadline,max_decisions,max_depth,
        max_cache_bytes,prefetch_width,stats:Stats::default(),
        candidate_domains:HashMap::new(),metadata_seen:HashSet::new(),
        expanded_cache:HashMap::new(),failed_states:HashSet::new(),failed_fifo:VecDeque::new(),
        failed_bytes:0,nogoods:HashMap::new(),nogood_bytes:0};
    solver.wire.max_frame=limit;
    let state=State{entries,selected:BTreeMap::new(),expanded:BTreeMap::new()};
    let result=solver.search(state,0);
    match result {
        Ok(Outcome::Solved(selected))=>solver.wire.finish_success(&selected,&solver.stats),
        Ok(Outcome::Failed(failure))=>solver.wire.finish_unsat(&failure.detail,&solver.stats),
        Err(detail)=>solver.wire.finish_error(&detail),
    }
}
fn main() {
    let mut wire=Wire::new();
    if let Err(error)=process(&mut wire) {
        let _=wire.finish_error(&error);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_requirements_combine_causal_provenance() {
        let a=Entry{name:"dependency".into(), requirement:"dependency<2".into(),
            extras:BTreeSet::new(),causes:BTreeSet::from(["left".into()])};
        let b=Entry{causes:BTreeSet::from(["right".into()]),..a.clone()};
        let merged=grouped(&[a,b]);
        assert_eq!(merged.rows["dependency"].len(),1);
        assert_eq!(merged.rows["dependency"][0].causes,
                   BTreeSet::from(["left".into(),"right".into()]));
    }

    #[test]
    fn state_identity_matches_python_requirement_and_assignment_semantics() {
        let a=Entry{name:"dependency".into(),requirement:"dependency<2".into(),
            extras:BTreeSet::new(),causes:BTreeSet::from(["left".into()])};
        let b=Entry{causes:BTreeSet::from(["right".into()]),..a.clone()};
        let left=State{entries:vec![a],selected:BTreeMap::new(),expanded:BTreeMap::new()};
        let right=State{entries:vec![b],selected:BTreeMap::new(),expanded:BTreeMap::new()};
        // Python's state_key intentionally excludes causal provenance.
        assert_eq!(current_state_key(&left,&grouped(&left.entries)),
                   current_state_key(&right,&grouped(&right.entries)));
    }

    #[test]
    fn ordered_grouping_is_independent_of_input_order() {
        let mut entries=Vec::new();
        for name in ["z", "a", "b"] {
            entries.push(Entry{name:name.into(),requirement:format!("{}>=1",name),
                extras:BTreeSet::new(),causes:BTreeSet::new()});
        }
        let mut reversed=entries.clone();reversed.reverse();
        assert_eq!(format!("{:?}",grouped(&entries).rows),
                   format!("{:?}",grouped(&reversed).rows));
    }
}
