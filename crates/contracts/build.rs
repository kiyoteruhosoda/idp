use std::{env, process::Command};

fn main() {
    println!("cargo:rerun-if-env-changed=IDP_GIT_VERSION");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/index");

    let provider = EnvGitVersionProvider.or(GitDescribeVersionProvider);
    let git_version = provider
        .git_version()
        .unwrap_or_else(|| "unknown".to_owned());

    println!("cargo:rustc-env=IDP_GIT_VERSION={git_version}");
}

trait GitVersionProvider {
    fn git_version(&self) -> Option<String>;
}

#[derive(Debug, Clone, Copy)]
struct EnvGitVersionProvider;

impl GitVersionProvider for EnvGitVersionProvider {
    fn git_version(&self) -> Option<String> {
        env::var("IDP_GIT_VERSION").ok().and_then(non_empty_version)
    }
}

#[derive(Debug, Clone, Copy)]
struct GitDescribeVersionProvider;

impl GitVersionProvider for GitDescribeVersionProvider {
    fn git_version(&self) -> Option<String> {
        Command::new("git")
            .args(["describe", "--always", "--dirty", "--tags"])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .and_then(non_empty_version)
    }
}

#[derive(Debug, Clone, Copy)]
struct FallbackGitVersionProvider<Primary, Secondary> {
    primary: Primary,
    secondary: Secondary,
}

impl<Primary, Secondary> GitVersionProvider for FallbackGitVersionProvider<Primary, Secondary>
where
    Primary: GitVersionProvider,
    Secondary: GitVersionProvider,
{
    fn git_version(&self) -> Option<String> {
        self.primary
            .git_version()
            .or_else(|| self.secondary.git_version())
    }
}

trait GitVersionProviderExt: GitVersionProvider + Sized {
    fn or<Secondary>(self, secondary: Secondary) -> FallbackGitVersionProvider<Self, Secondary>
    where
        Secondary: GitVersionProvider,
    {
        FallbackGitVersionProvider {
            primary: self,
            secondary,
        }
    }
}

impl<T> GitVersionProviderExt for T where T: GitVersionProvider {}

fn non_empty_version(version: String) -> Option<String> {
    let version = version.trim();
    (!version.is_empty() && version != "unknown").then(|| version.to_owned())
}
