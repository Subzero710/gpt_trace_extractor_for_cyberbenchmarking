//! Exact PubGrub interval propagation, conflict learning and backjumping.
//! Python remains the authoritative PEP 440/508/517 and artifact oracle.
//! The finite candidate universe of a project is discovered only when an
//! incoming requirement first reaches that project, not before.
use pubgrub::{resolve, Dependencies, DependencyConstraints, DependencyProvider,
    DefaultStringReporter, PackageResolutionStatistics, PubGrubError, Ranges,
    Reporter};
use std::cell::{Cell, RefCell};
use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::time::{Duration, Instant};

type Range = Ranges<u32>;

fn failure(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Other, message.into())
}

fn time_limit(seconds: u64) -> Result<Duration, io::Error> {
    if !(1..=180).contains(&seconds) {
        return Err(failure("native resolver time limit must be between 1 and 180 seconds"));
    }
    Ok(Duration::from_secs(seconds))
}

fn process_cpu_time() -> Result<Duration, io::Error> {
    let mut timestamp = std::mem::MaybeUninit::<libc::timespec>::uninit();
    if unsafe { libc::clock_gettime(libc::CLOCK_PROCESS_CPUTIME_ID, timestamp.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let timestamp = unsafe { timestamp.assume_init() };
    Ok(Duration::new(timestamp.tv_sec as u64, timestamp.tv_nsec as u32))
}

fn nonblocking(fd: RawFd) -> Result<(), io::Error> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn ipc_remaining(deadline: Instant) -> Result<Duration, io::Error> {
    deadline.checked_duration_since(Instant::now()).filter(|left| !left.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "native resolver IPC deadline expired"))
}

fn wait_ready(fd: RawFd, events: libc::c_short, deadline: Option<Instant>) -> Result<(), io::Error> {
    let mut descriptor = libc::pollfd { fd, events, revents: 0 };
    loop {
        let millis = match deadline {
            Some(end) => ipc_remaining(end)?.as_millis().max(1) as libc::c_int,
            None => -1,
        };
        let status = unsafe { libc::poll(&mut descriptor, 1, millis) };
        if status > 0 {
            return Ok(());
        }
        if status < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

struct Wire {
    input: BufReader<File>,
    output: File,
    message: Vec<u8>,
    max_frame: usize,
    ipc_timeout: Duration,
    input_deadline: Option<Instant>,
    input_size: usize,
}
impl Wire {
    fn new(ipc_timeout: Duration) -> Result<Self, io::Error> {
        nonblocking(libc::STDIN_FILENO)?;
        nonblocking(libc::STDOUT_FILENO)?;
        // The protocol exclusively owns both standard descriptors.
        let input = unsafe { File::from_raw_fd(libc::STDIN_FILENO) };
        let output = unsafe { File::from_raw_fd(libc::STDOUT_FILENO) };
        Ok(Self {
            input: BufReader::new(input),
            output,
            message: Vec::new(),
            max_frame: u32::MAX as usize,
            ipc_timeout,
            input_deadline: Some(Instant::now() + ipc_timeout),
            input_size: 0,
        })
    }

    fn read_exact(&mut self, mut bytes: &mut [u8]) -> Result<(), io::Error> {
        if self.input_size.saturating_add(bytes.len()) > self.max_frame {
            return Err(failure("IPC input message exceeds frame limit"));
        }
        self.input_size += bytes.len();
        while !bytes.is_empty() {
            if let Some(end) = self.input_deadline {
                ipc_remaining(end)?;
            }
            match self.input.read(bytes) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete resolver IPC response")),
                Ok(count) => bytes = &mut bytes[count..],
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    wait_ready(self.input.get_ref().as_raw_fd(), libc::POLLIN, self.input_deadline)?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn response_status(&mut self) -> Result<u8, io::Error> {
        // The bridge sends the status only after the metadata producer finishes.
        // EOF abandons this dependency if the bridge exits.
        self.input_deadline = None;
        self.input_size = 0;
        let status = self.u8()?;
        self.input_deadline = Some(Instant::now() + self.ipc_timeout);
        Ok(status)
    }

    fn u8(&mut self) -> Result<u8, io::Error> {
        let mut bytes = [0u8; 1]; self.read_exact(&mut bytes)?; Ok(bytes[0])
    }
    fn u32(&mut self) -> Result<u32, io::Error> {
        let mut bytes = [0u8; 4]; self.read_exact(&mut bytes)?;
        Ok(u32::from_be_bytes(bytes))
    }
    fn u64(&mut self) -> Result<u64, io::Error> {
        let mut bytes = [0u8; 8]; self.read_exact(&mut bytes)?;
        Ok(u64::from_be_bytes(bytes))
    }
    fn string(&mut self) -> Result<String, io::Error> {
        let size = self.u32()? as usize;
        if size > self.max_frame { return Err(failure("IPC string exceeds frame limit")); }
        let mut bytes = vec![0; size]; self.read_exact(&mut bytes)?;
        String::from_utf8(bytes).map_err(|e| failure(e.to_string()))
    }
    fn append(&mut self, bytes: &[u8]) -> Result<(), io::Error> {
        if self.message.len().saturating_add(bytes.len()) > self.max_frame {
            return Err(failure("IPC output message exceeds frame limit"));
        }
        self.message.extend_from_slice(bytes);
        Ok(())
    }
    fn put8(&mut self, value: u8) -> Result<(), io::Error> {
        self.append(&[value])
    }
    fn put32(&mut self, value: u32) -> Result<(), io::Error> {
        self.append(&value.to_be_bytes())
    }
    fn put_len(&mut self, value: usize) -> Result<(), io::Error> {
        self.put32(u32::try_from(value).map_err(|e| failure(e.to_string()))?)
    }
    fn put_string(&mut self, value: &str) -> Result<(), io::Error> {
        if value.len() > self.max_frame { return Err(failure("IPC outbound string exceeds frame limit")); }
        self.put_len(value.len())?;
        self.append(value.as_bytes())
    }
    fn flush(&mut self) -> Result<(), io::Error> {
        let deadline = Instant::now() + self.ipc_timeout;
        let mut bytes = self.message.as_slice();
        while !bytes.is_empty() {
            ipc_remaining(deadline)?;
            match self.output.write(bytes) {
                Ok(0) => return Err(failure("native resolver IPC write made no progress")),
                Ok(count) => bytes = &bytes[count..],
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    wait_ready(self.output.as_raw_fd(), libc::POLLOUT, Some(deadline))?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
                Err(error) => return Err(error),
            }
        }
        self.message.clear();
        Ok(())
    }
    fn ack(&mut self) -> Result<(), io::Error> {
        match self.response_status()? {
            1 => Ok(()),
            0 => Err(failure(self.string()?)),
            other => Err(failure(format!("invalid IPC response {other}"))),
        }
    }
    fn success(&mut self, ids: &BTreeMap<String,u32>, detail: &str) -> Result<(),io::Error> {
        self.put8(b'S')?; self.put_len(ids.len())?;
        for id in ids.values() { self.put32(*id)?; }
        self.put_string(detail)?; self.flush()
    }
    fn unsat(&mut self, detail: &str, decisions: u64) -> Result<(),io::Error> {
        let stats = format!("pubgrub decisions={decisions}; conflict derivation; no solution");
        let mut end = detail.len().min(self.max_frame.saturating_sub(9 + stats.len()));
        while !detail.is_char_boundary(end) {
            end -= 1;
        }
        self.put8(b'U')?;
        self.put_string(&detail[..end])?;
        self.put_string(&stats)?;
        self.flush()
    }
    fn error(&mut self, detail: &str) -> Result<(),io::Error> {
        self.message.clear();
        let mut end = detail.len().min(self.max_frame.saturating_sub(5));
        while !detail.is_char_boundary(end) {
            end -= 1;
        }
        self.put8(b'F')?; self.put_string(&detail[..end])?; self.flush()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord)]
enum Pkg {
    Root,
    Base(String),
    Extra(String,String),
}
impl fmt::Display for Pkg {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Root => write!(fmt, "<verified-root>"),
            Self::Base(name) => fmt.write_str(name),
            Self::Extra(name, extra) => write!(fmt, "{name}[{extra}]"),
        }
    }
}
impl Pkg {
    fn name(&self) -> Option<&str> {
        match self { Self::Root => None, Self::Base(name) | Self::Extra(name,_) => Some(name) }
    }
}

#[derive(Clone, Debug)]
struct Candidate { id: u32, kind: String, version: String, filename: String }
struct Universe {
    // Rank follows exact PEP 440 ordering supplied by Python. The preference
    // vector follows cache/release policy independently of that ordering.
    preference: Vec<u32>,
    by_rank: HashMap<u32,u32>,
}
struct Requirement { name: String, requirement: String, extras: Vec<String> }
struct Oracle<'a> {
    wire: &'a mut Wire,
    compute_started: Duration,
    compute_limit: Duration,
    no_deps: bool,
    roots: Vec<Requirement>,
    candidates: HashMap<u32,Candidate>,
    universes: HashMap<String,Universe>,
    ranges: HashMap<(String,String),Range>,
    rejected: HashMap<u32,String>,
    checked: HashSet<u32>,
    decisions: Cell<u64>,
    max_decisions: u64,
}
impl Oracle<'_> {
    fn check_time(&self) -> Result<(),io::Error> {
        if process_cpu_time()?.saturating_sub(self.compute_started) >= self.compute_limit {
            Err(failure("PubGrub solve exceeded configured active computation budget"))
        } else { Ok(()) }
    }
    fn read_candidate(&mut self) -> Result<u32,io::Error> {
        let id = self.wire.u32()?;
        match self.wire.u8()? {
            0 if self.candidates.contains_key(&id) => Ok(id),
            1 if !self.candidates.contains_key(&id) => {
                let kind = self.wire.string()?;
                let version = self.wire.string()?;
                let filename = self.wire.string()?;
                if kind != "wheel" && kind != "sdist" {
                    return Err(failure("invalid candidate artifact kind"));
                }
                self.candidates.insert(id,Candidate{id,kind,version,filename});
                Ok(id)
            },
            _ => Err(failure("invalid candidate registration")),
        }
    }
    fn read_universe(&mut self, name: &str) -> Result<(),io::Error> {
        if self.universes.contains_key(name) {
            return Err(failure("duplicate PubGrub universe registration"));
        }
        let count = self.wire.u32()? as usize;
        if count > self.wire.max_frame || count >= u32::MAX as usize {
            return Err(failure("unbounded PubGrub project universe"));
        }
        let mut pref = Vec::with_capacity(count);
        let mut ranks = HashMap::with_capacity(count);
        let mut seen = HashSet::with_capacity(count);
        for _ in 0..count {
            let id = self.read_candidate()?;
            let rank = self.wire.u32()?;
            if rank == 0 || rank > count as u32 || !seen.insert(rank)
                || ranks.insert(rank,id).is_some() {
                return Err(failure("invalid or duplicate PEP 440 version rank"));
            }
            pref.push(rank);
        }
        self.universes.insert(name.to_string(),Universe {preference:pref,by_rank:ranks});
        Ok(())
    }
    fn ensure_universe(&mut self, name: &str, first: &str) -> Result<(),io::Error> {
        if self.universes.contains_key(name) { return Ok(()); }
        self.check_time()?;
        self.wire.put8(b'V')?;
        self.wire.put_string(name)?;
        self.wire.put_string(first)?;
        self.wire.flush()?;
        self.wire.ack()?;
        self.read_universe(name)
    }
    fn prime_roots(&mut self, roots: &[Requirement]) -> Result<(),io::Error> {
        let projects: BTreeMap<&str,&str> = roots.iter()
            .map(|row| (row.name.as_str(),row.requirement.as_str())).collect();
        if projects.len() < 2 { return Ok(()); }
        self.check_time()?;
        self.wire.put8(b'Q')?;
        self.wire.put_len(projects.len())?;
        for (name, first) in &projects {
            self.wire.put_string(name)?;
            self.wire.put_string(first)?;
        }
        self.wire.flush()?;
        self.wire.ack()?;
        if self.wire.u32()? as usize != projects.len() {
            return Err(failure("PubGrub universe batch count differs"));
        }
        for (name, _) in projects {
            self.read_universe(name)?;
        }
        Ok(())
    }
    fn prefetch_candidates(&mut self, name: &str, ranks: &[u32]) -> Result<(),io::Error> {
        if ranks.len() < 2 { return Ok(()); }
        self.check_time()?;
        self.wire.put8(b'W')?;
        self.wire.flush()?;
        self.wire.ack()?;
        let width = self.wire.u32()? as usize;
        if width == 0 { return Err(failure("invalid adaptive metadata prefetch width")); }
        let ids: Vec<u32> = ranks.iter().take(width)
            .map(|rank| self.ref_for(name,*rank)).collect::<Result<_,_>>()?;
        self.wire.put8(b'A')?;
        // PubGrub's conflict-driven search has one flat candidate scope.
        self.wire.put_len(0)?;
        self.wire.put_len(ids.len())?;
        for id in ids { self.wire.put32(id)?; }
        self.wire.flush()?;
        self.wire.ack()
    }
    fn range(&mut self, name: &str, requirement: &str) -> Result<Range,io::Error> {
        let key = (name.to_string(),requirement.to_string());
        if let Some(cached) = self.ranges.get(&key) { return Ok(cached.clone()); }
        self.ensure_universe(name,requirement)?;
        self.wire.put8(b'R')?;
        self.wire.put_string(name)?;
        self.wire.put_string(requirement)?;
        self.wire.flush()?;
        self.wire.ack()?;
        let segments = self.wire.u32()? as usize;
        let max = self.universes[name].preference.len();
        if segments > max { return Err(failure("invalid PubGrub interval count")); }
        let mut range = Range::empty();
        let mut previous = 0;
        for _ in 0..segments {
            let lo = self.wire.u32()?;
            let hi = self.wire.u32()?;
            if lo == 0 || hi <= lo || hi > (max as u32 + 1) || lo <= previous {
                return Err(failure("noncanonical verified interval range"));
            }
            range = range.union(&Range::between(lo,hi));
            previous = hi-1;
        }
        self.ranges.insert(key,range.clone());
        Ok(range)
    }
    fn add_requirement(&mut self, deps: &mut BTreeMap<Pkg,Range>, row: &Requirement)
        -> Result<(),io::Error> {
        let range = self.range(&row.name,&row.requirement)?;
        let base = Pkg::Base(row.name.clone());
        let intersect = |key:Pkg, value:Range, target:&mut BTreeMap<Pkg,Range>| {
            target.entry(key).and_modify(|existing| {
                *existing = existing.intersection(&value);
            }).or_insert(value);
        };
        intersect(base,range.clone(),deps);
        if !self.no_deps {
            for extra in &row.extras {
                intersect(Pkg::Extra(row.name.clone(),extra.clone()),range.clone(),deps);
            }
        }
        Ok(())
    }
    fn ref_for(&self, name: &str, rank: u32) -> Result<u32,io::Error> {
        self.universes.get(name).and_then(|universe| universe.by_rank.get(&rank))
            .copied().ok_or_else(||failure("selected PubGrub version absent from proven universe"))
    }
    fn metadata(&mut self, id: u32) -> Result<Option<String>,io::Error> {
        if let Some(reason) = self.rejected.get(&id) { return Ok(Some(reason.clone())); }
        if self.checked.contains(&id) { return Ok(None); }
        self.check_time()?;
        self.wire.put8(b'M')?; self.wire.put_len(1)?; self.wire.put32(id)?;
        self.wire.flush()?;
        match self.wire.response_status()? {
            1 => {self.checked.insert(id);Ok(None)},
            2 => {
                let reason = self.wire.string()?;
                if reason.is_empty() { return Err(failure("missing verified source rejection reason")); }
                self.rejected.insert(id,reason.clone()); Ok(Some(reason))
            },
            0 => Err(failure(self.wire.string()?)),
            _ => Err(failure("invalid metadata verification acknowledgement")),
        }
    }
    fn dependencies(&mut self, id: u32, extras: &[String])
        -> Result<Vec<Requirement>,io::Error> {
        self.check_time()?;
        self.wire.put8(b'P')?;
        self.wire.put32(id)?;
        self.wire.put_len(extras.len())?;
        for extra in extras { self.wire.put_string(extra)?; }
        self.wire.flush()?;
        self.wire.ack()?;
        let count = self.wire.u32()? as usize;
        if count > self.wire.max_frame { return Err(failure("unbounded dependency metadata")); }
        let mut result=Vec::with_capacity(count);
        for _ in 0..count {
            let name=self.wire.string()?;
            let requirement=self.wire.string()?;
            let n=self.wire.u32()? as usize;
            if n > self.wire.max_frame { return Err(failure("invalid extras count")); }
            let mut extras=Vec::with_capacity(n);
            for _ in 0..n { extras.push(self.wire.string()?); }
            result.push(Requirement{name,requirement,extras});
        }
        Ok(result)
    }
    fn get_deps(&mut self, package: &Pkg, rank: u32)
        -> Result<Dependencies<Pkg,Range,String>,io::Error> {
        self.check_time()?;
        let mut dependencies=BTreeMap::<Pkg,Range>::new();
        match package {
            Pkg::Root => {
                if rank != 1 { return Err(failure("invalid PubGrub root version")); }
                let root = std::mem::take(&mut self.roots);
                self.prime_roots(&root)?;
                for row in &root { self.add_requirement(&mut dependencies,row)?; }
                self.roots=root;
            },
            Pkg::Base(name) | Pkg::Extra(name,_) => {
                let id=self.ref_for(name,rank)?;
                if let Some(reason)=self.metadata(id)? {
                    return Ok(Dependencies::Unavailable(reason));
                }
                if let Pkg::Extra(_,_) = package {
                    // A requested extra is a virtual package whose version is
                    // *identically* the selected distribution version.
                    dependencies.insert(Pkg::Base(name.clone()),Range::singleton(rank));
                }
                let extras=match package {
                    Pkg::Extra(_,extra)=>vec![extra.clone()], _=>Vec::new(),
                };
                if !self.no_deps {
                    for row in self.dependencies(id,&extras)? {
                        if row.name == *name {
                            // A distribution is already fixed to `rank` here. A
                            // self-requirement cannot introduce another choice of
                            // its version, so reject a contradiction directly.
                            // PubGrub must not be asked to solve a dependency
                            // edge from a package back to that same package.
                            if !self.range(name,&row.requirement)?.contains(&rank) {
                                return Ok(Dependencies::Unavailable(format!(
                                    "selected {name} version contradicts {}",row.requirement)));
                            }
                            // Self-requirements can still activate other extras.
                            // Keep those as separate virtual packages at the
                            // already-selected distribution version.
                            for extra in row.extras {
                                let virtual_package=Pkg::Extra(name.clone(),extra);
                                if &virtual_package == package { continue; }
                                let exact=Range::singleton(rank);
                                dependencies.entry(virtual_package)
                                    .and_modify(|existing| *existing=existing.intersection(&exact))
                                    .or_insert(exact);
                            }
                        } else {
                            self.add_requirement(&mut dependencies,&row)?;
                        }
                    }
                }
            }
        }
        Ok(Dependencies::Available(DependencyConstraints::from_iter(dependencies)))
    }
}

struct Provider<'a> { oracle: RefCell<Oracle<'a>> }
impl DependencyProvider for Provider<'_> {
    type P = Pkg;
    type V = u32;
    type VS = Range;
    type Priority = (Reverse<usize>,u32);
    type M = String;
    type Err = io::Error;
    fn prioritize(&self, package:&Pkg, range:&Range, stats:&PackageResolutionStatistics)
        -> Self::Priority {
        let oracle=self.oracle.borrow();
        let count=package.name().and_then(|name|oracle.universes.get(name))
            .map(|universe|universe.preference.iter().filter(|&&rank|range.contains(&rank)).count())
            .unwrap_or(1);
        (Reverse(count),stats.conflict_count())
    }
    fn choose_version(&self, package:&Pkg, range:&Range)->Result<Option<u32>,io::Error> {
        let mut oracle=self.oracle.borrow_mut();
        oracle.check_time()?;
        let decisions=oracle.decisions.get()+1;
        if decisions>oracle.max_decisions { return Err(failure("PubGrub decision budget exceeded")); }
        oracle.decisions.set(decisions);
        match package {
            Pkg::Root => Ok(range.contains(&1).then_some(1)),
            Pkg::Base(name) | Pkg::Extra(name,_) => {
                let universe=oracle.universes.get(name)
                    .ok_or_else(||failure("PubGrub selected a project before its verified range"))?;
                let allowed: Vec<u32> = universe.preference.iter().copied()
                    .filter(|rank|range.contains(rank)).collect();
                oracle.prefetch_candidates(name,&allowed)?;
                Ok(allowed.first().copied())
            }
        }
    }
    fn get_dependencies(&self, package:&Pkg, version:&u32)
        ->Result<Dependencies<Pkg,Range,String>,io::Error> {
        self.oracle.borrow_mut().get_deps(package,*version)
    }
    fn should_cancel(&self)->Result<(),io::Error> {
        self.oracle.borrow().check_time()
    }
}

fn run(wire: &mut Wire) -> Result<(),io::Error> {
    let frame=wire.u64()?;
    if frame==0 || frame>u32::MAX as u64 { return Err(failure("invalid IPC frame capacity")); }
    wire.max_frame=frame as usize;
    let max_decisions=wire.u64()?;
    let max_depth=wire.u64()?;
    let max_cache_bytes=wire.u64()?;
    let compute_limit=time_limit(wire.u64()?)?;
    let prefetch_width=wire.u64()?;
    let no_deps=wire.u8()? != 0;
    if max_decisions==0 || max_depth==0 || max_cache_bytes==0 || prefetch_width==0 {
        return Err(failure("invalid mandatory PubGrub resource policy"));
    }
    let count=wire.u32()? as usize;
    if count>wire.max_frame { return Err(failure("unbounded PubGrub roots")); }
    let mut roots=Vec::with_capacity(count);
    for _ in 0..count {
        let name=wire.string()?;
        let requirement=wire.string()?;
        let extra_count=wire.u32()? as usize;
        if extra_count>wire.max_frame { return Err(failure("unbounded root extras")); }
        let mut extras=Vec::with_capacity(extra_count);
        for _ in 0..extra_count { extras.push(wire.string()?); }
        roots.push(Requirement{name,requirement,extras});
    }
    let oracle=Oracle {wire,compute_started:process_cpu_time()?,compute_limit,no_deps,roots,
        candidates:HashMap::new(),universes:HashMap::new(),ranges:HashMap::new(),
        rejected:HashMap::new(),checked:HashSet::new(),decisions:Cell::new(0),max_decisions};
    let provider=Provider {oracle:RefCell::new(oracle)};
    let outcome=resolve(&provider,Pkg::Root,1u32);
    let oracle=provider.oracle.into_inner();
    oracle.check_time()?;
    match outcome {
        Ok(solution)=>{
            let mut refs=BTreeMap::<String,u32>::new();
            let mut selected=BTreeMap::<String,u32>::new();
            for (pkg,rank) in solution.iter() {
                if let Pkg::Base(name)=pkg {
                    selected.insert(name.clone(),*rank);
                    refs.insert(name.clone(),oracle.ref_for(name,*rank)?);
                }
            }
            for (pkg,rank) in solution.iter() {
                if let Pkg::Extra(name,_)=pkg {
                    if selected.get(name)!=Some(rank) {
                        return Err(failure("PubGrub extra version differs from its distribution"));
                    }
                }
            }
            let details=format!("pubgrub decisions={} packages={}",oracle.decisions.get(),refs.len());
            oracle.wire.success(&refs,&details)
        },
        Err(PubGrubError::NoSolution(mut tree))=>{
            tree.collapse_no_versions();
            let detail=DefaultStringReporter::report(&tree);
            oracle.wire.unsat(&detail,oracle.decisions.get())
        },
        Err(other)=>Err(failure(format!("{other:?}"))),
    }
}
fn main() {
    let ipc_timeout = std::env::args().nth(1)
        .ok_or_else(|| failure("missing native resolver IPC time limit"))
        .and_then(|arg| arg.parse::<u64>().map_err(|_| failure("invalid native resolver IPC time limit")))
        .and_then(time_limit);
    let mut wire = match ipc_timeout.and_then(Wire::new) {
        Ok(wire) => wire,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    };
    if let Err(error)=run(&mut wire) {
        if error.kind() != io::ErrorKind::TimedOut {
            let _=wire.error(&error.to_string());
        }
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn computation_budget_is_mandatory_and_bounded() {
        assert!(time_limit(0).is_err());
        assert!(time_limit(1).is_ok());
        assert!(time_limit(181).is_err());
    }

    #[test]
    fn process_computation_clock_excludes_time_spent_waiting() {
        let started = process_cpu_time().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let after_wait = process_cpu_time().unwrap();
        assert!(after_wait - started < Duration::from_millis(100));
        while process_cpu_time().unwrap() - after_wait < Duration::from_millis(10) {
            std::hint::spin_loop();
        }
        assert!(process_cpu_time().unwrap() - started >= Duration::from_millis(10));
    }
    #[test]
    fn interval_ranges_eliminate_incompatible_candidates() {
        let allowed=Range::between(10u32,20u32).intersection(&Range::between(15u32,25u32));
        assert!(allowed.contains(&15));
        assert!(!allowed.contains(&14));
        assert!(!allowed.contains(&20));
    }
    #[test]
    fn disjoint_intervals_prove_impossibility() {
        let left=Range::between(1u32,5u32);
        let right=Range::between(7u32,12u32);
        assert_eq!(left.intersection(&right),Range::empty());
    }
    #[test]
    fn real_pubgrub_backtracks_without_enumerating_combinations() {
        let mut provider=pubgrub::OfflineDependencyProvider::<&str,Range>::new();
        provider.add_dependencies("root",1u32,[
            ("a",Range::between(1u32,4u32)),("b",Range::singleton(1u32))]);
        provider.add_dependencies("a",3u32,[("b",Range::singleton(2u32))]);
        provider.add_dependencies("a",2u32,[("b",Range::singleton(1u32))]);
        provider.add_dependencies("b",1u32,[]);
        provider.add_dependencies("b",2u32,[]);
        let result=resolve(&provider,"root",1u32).unwrap();
        assert_eq!(result.get(&"a"),Some(&2));
        assert_eq!(result.get(&"b"),Some(&1));
    }
    #[test]
    fn real_pubgrub_proves_disjoint_transitive_intervals_unsat() {
        let mut provider=pubgrub::OfflineDependencyProvider::<&str,Range>::new();
        provider.add_dependencies("root",1u32,[
            ("a",Range::singleton(1u32)),("b",Range::singleton(1u32))]);
        provider.add_dependencies("a",1u32,[("c",Range::singleton(1u32))]);
        provider.add_dependencies("b",1u32,[("c",Range::singleton(2u32))]);
        provider.add_dependencies("c",1u32,[]);
        provider.add_dependencies("c",2u32,[]);
        assert!(matches!(resolve(&provider,"root",1u32),Err(PubGrubError::NoSolution(_))));
    }
}
