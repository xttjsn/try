extern crate libc;

use sysjack::common::{SockaddrUn};
use sysjack::ctrl::{Val, SkipControl, ScriptStarter,
				   FailControl, CallControl, Script};
use sysjack::trace::{Tracee, Tracer};
use sysjack::regs::{Register, Reg};
use sysjack::util::struct2words;

use nc::{SYS_OPENAT, SYS_SOCKET, SYS_CONNECT, AF_UNIX, SOCK_STREAM};
use getopts::Options;
use std::{env, path::PathBuf, process::exit};
use nix::unistd::{fork, ForkResult, getpid};
use is_executable::IsExecutable;
use std::convert::TryInto;


static WRITER_OUTPUT: &str = "/tmp/writer_output";
static SOCKET_PATH: &str = "/tmp/portalsock";

fn usage(prog: &str, opts: Options) {
    let brief = format!("Usage: {} <Tracee> [options]", prog);
    print!("{}", opts.usage(&brief));
}

fn main() -> std::io::Result<()> {
    let args: Vec<_> = env::args().collect();
    let mut opts = Options::new();
    opts.reqopt("t", "tracee", "program path", "Tracee");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(_) => {
            usage(&args[0], opts);
            exit(1);
        }
    };

    let tracee_prog = match matches.opt_str("tracee") {
        Some(path) => {
            if path.starts_with("/") {
                PathBuf::from(path)
            } else {
                PathBuf::from(&env::current_dir().unwrap().join(&path))
            }
        }
        None => {
            usage(&args[0], opts);
            exit(1);
        }
    };

    if !tracee_prog.as_path().is_executable() {
        eprintln!("{:?} does not exist or is not executable", tracee_prog);
        exit(1);
    }

    match fork() {
        Ok(ForkResult::Child) => {
            println!("Child PID is {}", getpid());
            println!("tracee is {:?}", &tracee_prog);
            Tracee::start(tracee_prog.as_path());
        }
        Ok(ForkResult::Parent { child: cpid, .. }) => {
            let tracee = Tracee::new(cpid);
            let mut tracer = Tracer::<&dyn Fn(Reg, Reg, Reg, Reg) -> bool>::new(&tracee);
            let openat_activation = |dirfd: Reg, pathname: Reg, _flags: Reg, _mode: Reg| {
                /* open(...) always becomes openat(AT_FDCWD, ...) in linux */
                dirfd == nc::AT_FDCWD as Reg && pathname.resolve_string(cpid) == WRITER_OUTPUT
            };
			let openat_activation = &openat_activation as &dyn Fn(Reg, Reg, Reg, Reg) -> bool;
            let openat_skip_control = SkipControl::Skip{
				regs_enter_name: "openat_regs_enter".to_owned()
			};
            let script_starter = ScriptStarter::new(openat_activation, openat_skip_control);
			let fail_ctrl = FailControl::Default;
            let socket_regs_ctrl = CallControl::new("socket_regs_enter".to_owned(),
													"socket_regs_exit".to_owned(),
													"socket_ret".to_owned());
            let connect_regs_ctrl = CallControl::new("connect_regs_enter".to_owned(),
													 "connect_exit".to_owned(),
													 "connect_ret".to_owned());
			let blob = struct2words(SockaddrUn::new(AF_UNIX.try_into().unwrap(), SOCKET_PATH));
            let bloblen = blob.len();

            let script = {
				let mut builder = Script::builder();
                builder.new(script_starter, fail_ctrl)
                    .call(socket_regs_ctrl,
                          SYS_SOCKET,
                          vec![Val::Raw(AF_UNIX as Reg),
                               Val::Raw(SOCK_STREAM as Reg),
                               Val::Raw(0)])
                    .alloc(blob, "serveraddr".to_owned())
                    .call(connect_regs_ctrl,
                          SYS_CONNECT,
                          vec![Val::Var("socket_ret".to_owned()),
                               Val::Var("serveraddr".to_owned()),
                               Val::Raw(bloblen as Reg)])
                    .ret(Val::Var("SocketRet".to_owned()));
				builder.build().unwrap()
            };

			tracer.hook(SYS_OPENAT, script).unwrap();
			tracer.sync().unwrap(); // Tracee is kicked off

        }
        Err(_) => {
            eprintln!("fork(): {}", errno::errno());
            std::process::exit(1);
        }
    }
    Ok(())
}
