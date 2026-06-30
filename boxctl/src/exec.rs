use crate::Result;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

pub const SIGTERM: i32 = 15;
pub const SIGKILL: i32 = 9;

#[cfg(unix)]
unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

#[derive(Clone)]
pub struct Runner {
    dry_run: bool,
    verbose: bool,
}

pub struct Output {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
}

impl Runner {
    pub fn new(dry_run: bool, verbose: bool) -> Self {
        Self { dry_run, verbose }
    }

    pub fn dry_run(&self) -> bool {
        self.dry_run
    }

    pub fn run<S: AsRef<str>>(&self, program: &str, args: &[S]) -> Result<Output> {
        self.print_command(program, args);
        if self.dry_run {
            return Ok(Output {
                ok: false,
                stdout: String::new(),
                stderr: String::new(),
            });
        }

        let output = Command::new(program)
            .args(args.iter().map(|value| value.as_ref()))
            .output()
            .map_err(|err| format!("execute {program} failed: {err}"))?;

        Ok(Output {
            ok: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }

    pub fn run_ok<S: AsRef<str>>(&self, program: &str, args: &[S]) -> bool {
        self.run(program, args)
            .map(|output| output.ok)
            .unwrap_or(false)
    }

    pub fn run_ignore<S: AsRef<str>>(&self, program: &str, args: &[S]) {
        let _ = self.run(program, args);
    }

    pub fn signal(&self, pid: i32, sig: i32) {
        self.print_command("kill", &[format!("-{sig}"), pid.to_string()]);
        if self.dry_run {
            return;
        }
        send_signal(pid, sig);
    }

    pub fn preview<S: AsRef<str>>(&self, program: &str, args: &[S]) {
        self.print_command(program, args);
    }

    pub fn run_with_stdin_output<S: AsRef<str>>(
        &self,
        program: &str,
        args: &[S],
        input: &str,
    ) -> Result<Output> {
        self.print_command(program, args);
        if self.verbose && !input.is_empty() {
            eprintln!("{input}");
        }
        if self.dry_run {
            return Ok(Output {
                ok: true,
                stdout: String::new(),
                stderr: String::new(),
            });
        }

        let mut child = Command::new(program)
            .args(args.iter().map(|value| value.as_ref()))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| format!("execute {program} failed: {err}"))?;

        if let Some(stdin) = child.stdin.as_mut() {
            stdin
                .write_all(input.as_bytes())
                .map_err(|err| format!("write {program} stdin failed: {err}"))?;
        }

        let output = child
            .wait_with_output()
            .map_err(|err| format!("wait for {program} failed: {err}"))?;

        Ok(Output {
            ok: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }

    pub fn spawn_to_file_with_env_as<S: AsRef<str>>(
        &self,
        program: &str,
        args: &[S],
        log_path: &Path,
        envs: &[(&str, String)],
        uid: u32,
        gid: u32,
    ) -> Result<Option<u32>> {
        self.print_command(program, args);
        if self.dry_run {
            return Ok(None);
        }

        let stdout = File::create(log_path)
            .map_err(|err| format!("create log {} failed: {err}", log_path.display()))?;
        let stderr = stdout
            .try_clone()
            .map_err(|err| format!("copy log handle {} failed: {err}", log_path.display()))?;

        let mut command = Command::new(program);
        command
            .args(args.iter().map(|value| value.as_ref()))
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        for (key, value) in envs {
            command.env(*key, value.as_str());
        }
        apply_process_identity(&mut command, uid, gid);

        let child = command
            .spawn()
            .map_err(|err| format!("start {program} failed: {err}"))?;

        Ok(Some(child.id()))
    }

    fn print_command<S: AsRef<str>>(&self, program: &str, args: &[S]) {
        if self.dry_run || self.verbose {
            eprintln!("+ {}", shell_join(program, args));
        }
    }
}

#[cfg(unix)]
fn apply_process_identity(command: &mut Command, uid: u32, gid: u32) {
    command.uid(uid).gid(gid);
}

#[cfg(not(unix))]
fn apply_process_identity(_command: &mut Command, _uid: u32, _gid: u32) {}

#[cfg(unix)]
fn send_signal(pid: i32, sig: i32) {
    unsafe {
        kill(pid, sig);
    }
}

#[cfg(not(unix))]
fn send_signal(pid: i32, sig: i32) {
    let _ = Command::new("kill")
        .arg(format!("-{sig}"))
        .arg(pid.to_string())
        .status();
}

pub(crate) fn shell_join<S: AsRef<str>>(program: &str, args: &[S]) -> String {
    let mut parts = Vec::with_capacity(args.len() + 1);
    parts.push(shell_quote(program));
    parts.extend(args.iter().map(|arg| shell_quote(arg.as_ref())));
    parts.join(" ")
}

pub(crate) fn shell_quote(value: &str) -> String {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || "-_./:@%+=".contains(ch))
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}
